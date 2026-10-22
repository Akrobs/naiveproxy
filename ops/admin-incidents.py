#!/usr/bin/env python3
"""Private, bounded SQLite incidents. Python 3.11+, Linux, effective UID 0.

CLI results are JSON (including errors, exit 2); --help is ordinary help.
ingest reads one UTF-8 JSON object, at most 256 KiB / 256 observations.
Identifiers: [A-Za-z0-9][A-Za-z0-9_.-]{0,63}. Timestamps: finite Unix
seconds in [0, 4102444800]. Thresholds: 1..100. Unknown resets BOTH streaks,
without closing an incident. Equal/older timestamps are ignored per key;
duplicate keys in one batch are rejected atomically. Missing keys do not
constitute an observation. Threshold changes affect subsequent observations.

list returns {incidents, checks}; render returns {message, parse_mode, page,
pages, total, node}. Render includes open and recovered history, open first.
ack keeps the first positive signed-64-bit numeric actor (authorization is
the caller's job), without affecting health or notifications. pending returns
{events}, with immutable open/recovery snapshots. delivered is idempotent.
Outbox insertion and state transitions share a transaction. Delivery is
at-least-once: ambiguous send errors may cause duplicates, never exactly-once.

Only incidents.sqlite3 is used, never user/config/token databases. The final
directory must be root-owned 0700; parents root-owned and not writable by
others (root-owned sticky temporary directories are allowed). No symlinks,
hard-linked files, WAL, network calls, subprocesses or stored raw summaries.
Windows fails closed; its ACL privacy cannot be inferred from chmod.
Limits: 8 MiB DB, 1024 checks, 2048 incidents, 4096 events, 240 UTF-16 units
per sanitized summary. Capacity errors roll back; history is NOT auto-pruned.
Callers must supply diagnostic descriptions, not secrets: redaction is
defense in depth, not a general-purpose secret detector. No retention/reset
or repair commands are exposed.
"""

import argparse
from contextlib import contextmanager
import datetime as dt
import html
import json
import math
import os
import re
import sqlite3
import stat
import sys
import time
import unicodedata
import uuid


DB_NAME = "incidents.sqlite3"
APPLICATION_ID = 0x59494E43
SCHEMA_VERSION = 1
MAX_DB_BYTES = 8 * 1024 * 1024
MAX_CHECKS = 1024
MAX_INCIDENTS = 2048
MAX_EVENTS = 4096
MAX_INPUT_BYTES = 256 * 1024
MAX_OBSERVATIONS = 256
MAX_RAW_SUMMARY = 2048
MAX_SUMMARY = 240
MAX_TIMESTAMP = 4102444800
MAX_THRESHOLD = 100
MAX_RENDER_UNITS = 3000
BUSY_MS = 5000
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
RECORD_ID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
ACTOR = re.compile(r"[1-9][0-9]{0,18}\Z", re.ASCII)
URI = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{0,20}://[^\s<>\"']+")
SECRET_LABEL = re.compile(
    r"(?i)\b(?:[a-z0-9_-]*(?:token|password|passwd|secret|credential|"
    r"authorization|api[_-]?key|private[_-]?key)|pwd)\b[\"']?\s*(?:[:=]|\s)\s*.*"
)
AUTH_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+\S+")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
BOT_TOKEN = re.compile(r"\b[0-9]{5,20}:[A-Za-z0-9_-]{20,}\b")
OPAQUE_SECRET = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_+=/-]{24,}(?![A-Za-z0-9_-])")
PRIVATE_PATH = re.compile(r"(?i)(?:\b[a-z]:[\\/]|\\\\|(?<![A-Za-z0-9])~?/)[^\s<>\"']+")


class IncidentError(Exception):
    """Only fixed, non-sensitive error codes may cross the CLI boundary."""


def utf16_size(value):
    return len(value.encode("utf-16-le")) // 2


def truncate(value, limit):
    if utf16_size(value) <= limit:
        return value
    result, used = [], 0
    for character in value:
        cost = 2 if ord(character) > 0xFFFF else 1
        if used + cost > limit - 3:
            break
        result.append(character)
        used += cost
    return "".join(result) + "..."


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise IncidentError("invalid_identifier")
    return value


def record_id(value):
    if not isinstance(value, str) or not RECORD_ID.fullmatch(value):
        raise IncidentError("invalid_id")
    return value


def actor_id(value):
    if (not isinstance(value, str) or not ACTOR.fullmatch(value)
            or int(value) > 9223372036854775807):
        raise IncidentError("invalid_actor")
    return value


def bounded_integer(value, maximum, error):
    if type(value) is not int or not 1 <= value <= maximum:
        raise IncidentError(error)
    return value


def sanitize_summary(value):
    if (not isinstance(value, str) or len(value) > MAX_RAW_SUMMARY
            or any(unicodedata.category(c) in ("Cc", "Cs", "Cf") for c in value)):
        raise IncidentError("invalid_summary")
    if utf16_size(value) > MAX_RAW_SUMMARY:
        raise IncidentError("invalid_summary")
    value = " ".join(value.split())
    # Redact BEFORE truncation, and drop a labeled secret's entire suffix.
    value = SECRET_LABEL.sub("[REDACTED]", value)
    for pattern in (URI, AUTH_VALUE, JWT, BOT_TOKEN, PRIVATE_PATH, OPAQUE_SECRET):
        value = pattern.sub("[REDACTED]", value)
    return truncate(value, MAX_SUMMARY)


def validate_payload(payload):
    if not isinstance(payload, dict) or set(payload) != {"observed_at", "observations"}:
        raise IncidentError("invalid_payload")
    stamp = payload["observed_at"]
    if (type(stamp) not in (int, float) or not 0 <= stamp <= MAX_TIMESTAMP
            or not math.isfinite(stamp)):
        raise IncidentError("invalid_timestamp")
    observations = payload["observations"]
    if not isinstance(observations, list) or len(observations) > MAX_OBSERVATIONS:
        raise IncidentError("invalid_observations")
    seen, clean = set(), []
    for item in observations:
        if not isinstance(item, dict) or set(item) != {"node", "check", "status", "summary"}:
            raise IncidentError("invalid_observation")
        node, check = identifier(item["node"]), identifier(item["check"])
        if (node, check) in seen:
            raise IncidentError("duplicate_key")
        seen.add((node, check))
        if not isinstance(item["status"], str) or item["status"] not in ("ok", "fail", "unknown"):
            raise IncidentError("invalid_status")
        clean.append({"node": node, "check": check, "status": item["status"],
                      "summary": sanitize_summary(item["summary"])})
    return {"observed_at": stamp, "observations": clean}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IncidentError("duplicate_json_key")
        result[key] = value
    return result


def decode_payload(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_INPUT_BYTES:
        raise IncidentError("input_too_large")
    def invalid_constant(_value):
        raise IncidentError("invalid_json")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                             parse_constant=invalid_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise IncidentError("invalid_json") from None
    return validate_payload(payload)


def _directory_permissions(info, final=False):
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise IncidentError("unsafe_state_directory")
    if final:
        if mode != 0o700:
            raise IncidentError("unsafe_state_directory")
    elif mode & 0o022 and not mode & stat.S_ISVTX:
        raise IncidentError("unsafe_parent_directory")


@contextmanager
def _private_directory(path):
    if (not sys.platform.startswith("linux") or not hasattr(os, "geteuid")
            or not hasattr(os, "O_NOFOLLOW")):
        raise IncidentError("unsupported_platform")
    if os.geteuid() != 0:
        raise IncidentError("root_required")
    if (not isinstance(path, str) or len(path) > 4096 or not path.startswith("/")
            or path.startswith("//") or "\\" in path
            or any(unicodedata.category(c).startswith("C") for c in path)):
        raise IncidentError("unsafe_state_path")
    components = [part for part in path.split("/") if part]
    if not components or any(part in (".", "..") for part in components):
        raise IncidentError("unsafe_state_path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        _directory_permissions(os.fstat(descriptor))
        for index, part in enumerate(components):
            final = index == len(components) - 1
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not final:
                    raise IncidentError("state_parent_missing") from None
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass  # Another root worker may have created it.
                child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            _directory_permissions(os.fstat(descriptor), final=final)
        yield descriptor
    finally:
        os.close(descriptor)


def _file_permissions(info, maximum=MAX_DB_BYTES):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum):
        raise IncidentError("unsafe_state_file")


def _check_sidecars(descriptor):
    for suffix in ("-journal", "-wal", "-shm"):
        try:
            info = os.stat(DB_NAME + suffix, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            continue
        _file_permissions(info, MAX_DB_BYTES + 65536)
        if suffix != "-journal":
            raise IncidentError("unsupported_journal")


@contextmanager
def open_store(state_dir):
    with _private_directory(state_dir) as directory:
        _check_sidecars(directory)
        try:
            existing = os.stat(DB_NAME, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            _file_permissions(existing)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        try:
            descriptor = os.open(DB_NAME, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
        except FileExistsError:
            descriptor = os.open(DB_NAME, flags, dir_fd=directory)
        try:
            _file_permissions(os.fstat(descriptor))
            # Anchor SQLite to the validated open directory, not an unchecked pathname.
            path = "/proc/self/fd/" + str(directory) + "/" + DB_NAME
            connection = _connect_database(path)
            try:
                yield IncidentStore(connection)
            finally:
                connection.close()
        finally:
            os.close(descriptor)


SCHEMA = (
    """CREATE TABLE checks (
        node TEXT NOT NULL, check_name TEXT NOT NULL, observed_at REAL NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('ok','fail','unknown')),
        summary TEXT NOT NULL CHECK(length(summary)<=240),
        failures INTEGER NOT NULL CHECK(failures BETWEEN 0 AND 100),
        recoveries INTEGER NOT NULL CHECK(recoveries BETWEEN 0 AND 100),
        PRIMARY KEY(node, check_name))""",
    """CREATE TABLE incidents (
        id TEXT PRIMARY KEY NOT NULL, node TEXT NOT NULL, check_name TEXT NOT NULL,
        opened_at REAL NOT NULL, updated_at REAL NOT NULL, recovered_at REAL,
        status TEXT NOT NULL CHECK(status IN ('ok','fail','unknown')),
        summary TEXT NOT NULL CHECK(length(summary)<=240), ack_actor TEXT, ack_at REAL,
        FOREIGN KEY(node,check_name) REFERENCES checks(node,check_name))""",
    "CREATE UNIQUE INDEX one_active ON incidents(node,check_name) WHERE recovered_at IS NULL",
    """CREATE TABLE outbox (
        event_id TEXT PRIMARY KEY NOT NULL,
        incident_id TEXT NOT NULL REFERENCES incidents(id),
        kind TEXT NOT NULL CHECK(kind IN ('open','recovery')),
        observed_at REAL NOT NULL, summary TEXT NOT NULL CHECK(length(summary)<=240),
        delivered_at REAL, UNIQUE(incident_id,kind))""",
    "CREATE INDEX pending_events ON outbox(delivered_at,observed_at)",
)


def _connect_database(path):
    connection = sqlite3.connect(path, timeout=BUSY_MS / 1000, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA busy_timeout=" + str(BUSY_MS))
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA secure_delete=ON")
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 65536)
        connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 32768)
        connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        connection.execute("BEGIN IMMEDIATE")
        app = connection.execute("PRAGMA application_id").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = connection.execute("SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if (app, version) == (0, 0) and not tables:
            if connection.execute("PRAGMA page_size").fetchone()[0] != 4096:
                raise IncidentError("unsupported_database")
            for statement in SCHEMA:
                connection.execute(statement)
            connection.execute("PRAGMA application_id=" + str(APPLICATION_ID))
            connection.execute("PRAGMA user_version=" + str(SCHEMA_VERSION))
        elif (app, version) != (APPLICATION_ID, SCHEMA_VERSION):
            raise IncidentError("unsupported_database")
        if (connection.execute("PRAGMA page_size").fetchone()[0] != 4096
                or connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete"):
            raise IncidentError("unsupported_database")
        if connection.execute("PRAGMA page_count").fetchone()[0] > MAX_DB_BYTES // 4096:
            raise IncidentError("capacity_exceeded")
        connection.execute("PRAGMA max_page_count=" + str(MAX_DB_BYTES // 4096))
        connection.commit()
        return connection
    except BaseException:
        connection.close()
        raise


class IncidentStore:
    def __init__(self, connection):
        self.db = connection

    @contextmanager
    def transaction(self, write=False):
        self.db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def _capacity(self):
        for table, maximum in (("checks", MAX_CHECKS), ("incidents", MAX_INCIDENTS), ("outbox", MAX_EVENTS)):
            if self.db.execute("SELECT count(*) FROM " + table).fetchone()[0] > maximum:
                raise IncidentError("capacity_exceeded")

    def _event(self, incident, kind, stamp, summary):
        event = uuid.uuid4().hex
        self.db.execute("INSERT INTO outbox VALUES(?,?,?,?,?,NULL)",
                        (event, incident, kind, stamp, summary))
        return event

    def ingest(self, payload, failures=3, recoveries=2):
        bounded_integer(failures, MAX_THRESHOLD, "invalid_threshold")
        bounded_integer(recoveries, MAX_THRESHOLD, "invalid_threshold")
        payload = validate_payload(payload)
        stamp = payload["observed_at"]
        accepted, ignored, transitions = 0, 0, []
        with self.transaction(write=True):
            for item in payload["observations"]:
                node, check = item["node"], item["check"]
                previous = self.db.execute("SELECT * FROM checks WHERE node=? AND check_name=?", (node, check)).fetchone()
                if previous is not None and stamp <= previous["observed_at"]:
                    ignored += 1
                    continue
                status, summary = item["status"], item["summary"]
                bad = min((previous["failures"] if previous else 0) + 1, MAX_THRESHOLD) if status == "fail" else 0
                good = min((previous["recoveries"] if previous else 0) + 1, MAX_THRESHOLD) if status == "ok" else 0
                self.db.execute("""INSERT INTO checks VALUES(?,?,?,?,?,?,?)
                    ON CONFLICT(node,check_name) DO UPDATE SET
                    observed_at=excluded.observed_at,status=excluded.status,summary=excluded.summary,
                    failures=excluded.failures,recoveries=excluded.recoveries""",
                    (node, check, stamp, status, summary, bad, good))
                active = self.db.execute("SELECT id FROM incidents WHERE node=? AND check_name=? AND recovered_at IS NULL",
                                         (node, check)).fetchone()
                kind, incident = None, active["id"] if active else None
                if incident:
                    recovered_at = stamp if status == "ok" and good >= recoveries else None
                    self.db.execute("UPDATE incidents SET updated_at=?,status=?,summary=?,recovered_at=? WHERE id=?",
                                    (stamp, status, summary, recovered_at, incident))
                    if recovered_at is not None:
                        kind = "recovery"
                elif status == "fail" and bad >= failures:
                    incident, kind = uuid.uuid4().hex, "open"
                    self.db.execute("""INSERT INTO incidents
                        (id,node,check_name,opened_at,updated_at,status,summary) VALUES(?,?,?,?,?,?,?)""",
                        (incident, node, check, stamp, stamp, status, summary))
                if kind:
                    event = self._event(incident, kind, stamp, summary)
                    transitions.append({"id": incident, "event_id": event, "kind": kind})
                accepted += 1
            self._capacity()
        return {"accepted": accepted, "ignored": ignored, "transitions": transitions}

    def list(self, node=None):
        if node is not None:
            identifier(node)
        where, args = (" WHERE node=?", (node,)) if node is not None else ("", ())
        with self.transaction():
            incidents = [dict(row) for row in self.db.execute(
                "SELECT id,node,check_name AS 'check',opened_at,updated_at,recovered_at,status,summary,ack_actor,ack_at "
                "FROM incidents" + where + " ORDER BY recovered_at IS NOT NULL,updated_at DESC,id", args)]
            checks = [dict(row) for row in self.db.execute(
                "SELECT node,check_name AS 'check',observed_at,status,summary,failures,recoveries "
                "FROM checks" + where + " ORDER BY node,check_name", args)]
        return {"incidents": incidents, "checks": checks}

    def ack(self, incident, actor):
        record_id(incident)
        actor_id(actor)
        with self.transaction(write=True):
            row = self.db.execute("SELECT ack_actor,ack_at FROM incidents WHERE id=?", (incident,)).fetchone()
            if row is None:
                raise IncidentError("incident_not_found")
            changed = row["ack_actor"] is None
            acknowledged_by = actor if changed else row["ack_actor"]
            acknowledged_at = time.time() if changed else row["ack_at"]
            if changed:
                self.db.execute("UPDATE incidents SET ack_actor=?,ack_at=? WHERE id=?",
                                (acknowledged_by, acknowledged_at, incident))
        return {"id": incident, "ack_actor": acknowledged_by, "ack_at": acknowledged_at, "changed": changed}

    def pending(self, limit=5):
        bounded_integer(limit, 100, "invalid_limit")
        with self.transaction():
            events = [dict(row) for row in self.db.execute("""SELECT
                o.event_id,o.incident_id,o.kind,o.observed_at,o.summary,i.node,i.check_name AS 'check',i.opened_at
                FROM outbox o JOIN incidents i ON i.id=o.incident_id WHERE o.delivered_at IS NULL
                ORDER BY o.observed_at,CASE o.kind WHEN 'open' THEN 0 ELSE 1 END,o.event_id LIMIT ?""", (limit,))]
        return {"events": events}

    def delivered(self, event):
        record_id(event)
        with self.transaction(write=True):
            row = self.db.execute("SELECT delivered_at FROM outbox WHERE event_id=?", (event,)).fetchone()
            if row is None:
                raise IncidentError("event_not_found")
            changed = row["delivered_at"] is None
            delivered_at = time.time() if changed else row["delivered_at"]
            if changed:
                self.db.execute("UPDATE outbox SET delivered_at=? WHERE event_id=?", (delivered_at, event))
        return {"event_id": event, "delivered_at": delivered_at, "changed": changed}


def _utc(stamp):
    return dt.datetime.fromtimestamp(stamp, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def render_rows(rows, page=1, node=None):
    bounded_integer(page, 1000000, "invalid_page")
    if node is not None:
        identifier(node)
    blocks = []
    for row in rows:
        state = "\u041e\u0422\u041a\u0420\u042b\u0422" if row["recovered_at"] is None else "\u0412\u041e\u0421\u0421\u0422\u0410\u041d\u041e\u0412\u041b\u0415\u041d"
        block = "<b>" + state + "</b> <code>" + html.escape(row["node"] + "/" + row["check"]) + "</code>"
        block += "\n<code>" + row["id"] + "</code> | " + row["status"]
        block += "\n" + _utc(row["opened_at"])
        if row["recovered_at"] is not None:
            block += " / " + _utc(row["recovered_at"])
        block += "\n" + html.escape(sanitize_summary(row["summary"]), quote=True)
        if row["ack_actor"] is not None:
            block += "\nAck: <code>" + actor_id(row["ack_actor"]) + "</code>"
        blocks.append(block)
    # Reserve header space, pack complete blocks: never cut an HTML entity/tag.
    pages, current, used = [], [], 0
    for block in blocks:
        cost = utf16_size(block) + 2
        if cost > MAX_RENDER_UNITS - 300:
            raise IncidentError("render_limit")
        if current and used + cost > MAX_RENDER_UNITS - 300:
            pages.append("\n\n".join(current))
            current, used = [], 0
        current.append(block)
        used += cost
    if current or not pages:
        pages.append("\n\n".join(current))
    page = min(page, len(pages))
    message = "<b>\u0418\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u044b</b>"
    if node is not None:
        message += " | <code>" + html.escape(node) + "</code>"
    message += "\n\u0412\u0441\u0435\u0433\u043e: " + str(len(rows))
    message += " | \u0421\u0442\u0440\u0430\u043d\u0438\u0446\u0430: " + str(page) + "/" + str(len(pages))
    message += "\n\n" + (pages[page - 1] or "\u0418\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u043e\u0432 \u043d\u0435\u0442.")
    if utf16_size(message) > MAX_RENDER_UNITS:
        raise IncidentError("render_limit")
    return {"message": message, "parse_mode": "HTML", "page": page, "pages": len(pages),
            "total": len(rows), "node": node}


class JsonParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, allow_abbrev=False, **kwargs)

    def error(self, _message):
        raise IncidentError("invalid_arguments")


def _number(value):
    if not re.fullmatch(r"[1-9][0-9]{0,6}", value, flags=re.ASCII):
        raise IncidentError("invalid_arguments")
    return int(value)


def parser():
    root = JsonParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("ingest", "render", "list", "ack", "pending", "delivered"):
        command = commands.add_parser(name)
        command.add_argument("--state-dir", required=True)
        if name == "ingest":
            command.add_argument("--failures", type=_number, default=3)
            command.add_argument("--recoveries", type=_number, default=2)
        elif name == "render":
            command.add_argument("--node")
            command.add_argument("--page", type=_number, default=1)
        elif name == "ack":
            command.add_argument("--id", required=True)
            command.add_argument("--actor", required=True)
        elif name == "pending":
            command.add_argument("--limit", type=_number, default=5)
        elif name == "delivered":
            command.add_argument("--event-id", required=True)
    return root


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        if args.command == "ingest":
            bounded_integer(args.failures, MAX_THRESHOLD, "invalid_threshold")
            bounded_integer(args.recoveries, MAX_THRESHOLD, "invalid_threshold")
            payload = decode_payload(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
        elif args.command == "render":
            bounded_integer(args.page, 1000000, "invalid_page")
            if args.node is not None:
                identifier(args.node)
        elif args.command == "ack":
            record_id(args.id)
            actor_id(args.actor)
        elif args.command == "pending":
            bounded_integer(args.limit, 100, "invalid_limit")
        elif args.command == "delivered":
            record_id(args.event_id)
        with open_store(args.state_dir) as store:
            if args.command == "ingest":
                result = store.ingest(payload, args.failures, args.recoveries)
            elif args.command == "list":
                result = store.list()
            elif args.command == "render":
                result = render_rows(store.list(args.node)["incidents"], args.page, args.node)
            elif args.command == "ack":
                result = store.ack(args.id, args.actor)
            elif args.command == "pending":
                result = store.pending(args.limit)
            else:
                result = store.delivered(args.event_id)
        output, status = {"ok": True, "schema": SCHEMA_VERSION, **result}, 0
    except IncidentError as error:
        output, status = {"ok": False, "error": str(error)}, 2
    except sqlite3.Error as error:
        code = getattr(error, "sqlite_errorcode", 0) or 0
        code &= 0xFF
        reason = "storage_busy" if code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) else "storage_error"
        if code == sqlite3.SQLITE_FULL:
            reason = "capacity_exceeded"
        output, status = {"ok": False, "error": reason}, 2
    except (OSError, UnicodeError):
        output, status = {"ok": False, "error": "unsafe_or_unavailable_storage"}, 2
    print(json.dumps(output, ensure_ascii=True, allow_nan=False, separators=(",", ":")))
    return status


if __name__ == "__main__":
    sys.exit(main())
