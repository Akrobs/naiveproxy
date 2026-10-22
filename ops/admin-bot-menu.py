#!/usr/bin/env python3
"""Admin-only menu rendering and one-use drafts; never execute panel actions."""
import argparse
from contextlib import contextmanager
import datetime as dt
import hashlib
import hmac
import html
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import time


PAGE_SIZE = 10
DRAFT_TTL = 300
USER = re.compile(r'[A-Za-z0-9_-]{2,32}')
CHAT = re.compile(r'[0-9]{5,15}')
CONTACT = re.compile(r'-?[0-9]{5,20}')
COMMANDS = {'users': '/users', 'expiry': '/expiring', 'qr': '/qrpick',
            'sub': '/subpick', 'delete': '/delpick', 'notifications': '/notifications'}
TITLES = {'users': 'Пользователи', 'expiry': 'Сроки подписок', 'qr': 'Выбери пользователя для QR',
          'sub': 'Выбери пользователя для подписки', 'delete': 'Выбери пользователя для удаления',
          'notifications': 'Уведомления и привязки Telegram'}


def utf16_size(text):
    return len(text.encode('utf-16-le')) // 2


def bounded(text, limit=1800):
    result, used = [], 0
    for character in text:
        cost = utf16_size(character)
        if used + cost > limit:
            return ''.join(result) + '\n[предпросмотр сокращён]'
        result.append(character)
        used += cost
    return ''.join(result)


def envelope(message, rows):
    return {'message': message, 'markup': {'keyboard': [[{'text': text} for text in row] for row in rows],
            'resize_keyboard': True, 'one_time_keyboard': False, 'is_persistent': True}}


def read_rows(data):
    values = data.split('\0')
    if values and values[-1] == '':
        values.pop()
    if len(values) % 3 or len(values) > 30000:
        raise ValueError('Некорректный список пользователей.')
    result = {}
    for offset in range(0, len(values), 3):
        name, expiry, chat = values[offset:offset + 3]
        if not USER.fullmatch(name):
            raise ValueError('Список содержит неподдерживаемый логин.')
        try:
            date = dt.date.fromisoformat(expiry)
        except ValueError:
            date = None
        result[name] = {'name': name, 'expiry': date, 'telegram': bool(CONTACT.fullmatch(chat))}
    return sorted(result.values(), key=lambda row: (row['name'].casefold(), row['name']))


def render_page(rows, view, request, today=None):
    today = today or dt.datetime.now(dt.timezone.utc).date()
    if view == 'detail':
        selected = next((row for row in rows if row['name'] == request), None)
        if selected is None:
            raise ValueError('Пользователь не найден.')
        name = selected['name']
        expiry = selected['expiry'].strftime('%d.%m.%Y') if selected['expiry'] else 'без срока'
        message = '<b>' + html.escape(name) + '</b>\nСрок: ' + expiry
        message += '\nTelegram: ' + ('привязан' if selected['telegram'] else 'не привязан')
        message += '\nДля привязки: <code>/bindtg ' + name + ' TELEGRAM_ID</code>'
        return envelope(message, [['📱 QR: ' + name, '🔗 Подписка: ' + name],
                                 ['/testnotify ' + name, '/untg ' + name],
                                 ['🗑 Удалить: ' + name], ['👥 Пользователи', '🏠 Главное меню']])
    if view not in COMMANDS or len(request) > 100:
        raise ValueError('Некорректный запрос списка.')
    parts = request.split()
    filtering = 'all'
    if view == 'expiry' and parts and parts[0] in ('all', 'soon', 'expired', 'no_tg'):
        filtering = parts.pop(0)
    page = 1
    if parts and parts[0].isdecimal():
        value = parts.pop(0)
        if not re.fullmatch(r'[1-9][0-9]{0,5}', value):
            raise ValueError('Номер страницы должен быть положительным числом.')
        page = int(value)
    search = ' '.join(parts)
    if search and not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', search):
        raise ValueError('Поиск: часть логина, латинские буквы, цифры, _ или -.')
    matches = []
    for row in rows:
        if search.casefold() not in row['name'].casefold():
            continue
        expiry = row['expiry']
        days = (expiry - today).days if expiry else None
        if filtering == 'soon' and not (days is not None and 0 <= days <= 7):
            continue
        if filtering == 'expired' and not (days is not None and days < 0):
            continue
        if filtering == 'no_tg' and row['telegram']:
            continue
        matches.append(row)
    pages = max(1, math.ceil(len(matches) / PAGE_SIZE))
    page = min(page, pages)
    selected = matches[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]
    lines = ['<b>' + TITLES[view] + '</b>', 'Найдено: ' + str(len(matches)) + ' из ' + str(len(rows)),
             'Страница ' + str(page) + ' / ' + str(pages)]
    keyboard = []
    labels = []
    for row in selected:
        name = row['name']
        line = '• <code>' + html.escape(name) + '</code>'
        if view == 'expiry':
            line += ' · ' + (row['expiry'].strftime('%d.%m.%Y') if row['expiry'] else 'без срока')
        if view in ('expiry', 'notifications'):
            line += ' · TG ' + ('есть' if row['telegram'] else 'нет')
        lines.append(line)
        prefix = {'qr': '📱 QR: ', 'sub': '🔗 Подписка: ', 'delete': '🗑 Удалить: '}.get(view, '👤 ')
        labels.append(prefix + name)
    keyboard.extend([labels[index:index + 2] for index in range(0, len(labels), 2)])
    if not selected:
        lines.append('Ничего не найдено.')
    def link(number):
        suffix = (' ' + filtering) if view == 'expiry' and filtering != 'all' else ''
        return COMMANDS[view] + suffix + ' ' + str(number) + (' ' + search if search else '')
    navigation = []
    if page > 1:
        navigation.append('⬅️ ' + link(page - 1))
    if page < pages:
        navigation.append('➡️ ' + link(page + 1))
    if navigation:
        keyboard.append(navigation)
    if view == 'expiry':
        keyboard.extend([['⏳ Скоро истекают', '⌛ Истекли'], ['🔕 Без Telegram', '📅 Все сроки']])
    if view == 'notifications':
        lines.append('Привязка: <code>/bindtg ЛОГИН TELEGRAM_ID</code>')
        keyboard.append(['📅 Сроки подписок', '🔕 Без Telegram'])
    lines.append('Поиск: <code>' + COMMANDS[view] + ' логин</code>')
    keyboard.append(['🏠 Главное меню'])
    return envelope('\n'.join(lines), keyboard)


class DraftStore:
    def __init__(self, directory, chat):
        if not CHAT.fullmatch(chat):
            raise ValueError('Некорректный чат.')
        self.chat = chat
        self.directory = Path(directory)
        if self.directory.is_symlink():
            raise ValueError('Небезопасный каталог подтверждений.')
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.stat()
        if not stat.S_ISDIR(info.st_mode) or (os.name != 'nt' and info.st_uid != os.geteuid()):
            raise ValueError('Небезопасный владелец каталога подтверждений.')
        os.chmod(self.directory, 0o700)
        self.path = self.directory / ('admin-action.' + chat + '.env')

    def open_private(self, path, flags):
        if path.is_symlink():
            raise ValueError('Небезопасный файл подтверждения.')
        fd = os.open(path, flags | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (
                os.name != 'nt' and (info.st_uid != os.geteuid() or info.st_mode & 0o077)):
            os.close(fd)
            raise ValueError('Небезопасные права файла подтверждения.')
        return fd

    @contextmanager
    def locked(self):
        lock = self.directory / ('admin-action.' + self.chat + '.lock')
        fd = self.open_private(lock, os.O_CREAT | os.O_RDWR)
        with os.fdopen(fd, 'r+b') as stream:
            if os.name == 'nt':
                import msvcrt
                if not os.fstat(stream.fileno()).st_size:
                    stream.write(b'0')
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if os.name == 'nt':
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(stream, fcntl.LOCK_UN)

    def read(self, now):
        try:
            fd = self.open_private(self.path, os.O_RDONLY)
        except FileNotFoundError:
            raise ValueError('Нет ожидающего действия. Создай новый запрос.') from None
        with os.fdopen(fd, 'r', encoding='utf-8') as stream:
            raw = stream.read(16001)
        if len(raw) > 16000:
            raise ValueError('Некорректный файл подтверждения.')
        draft = json.loads(raw)
        if (not isinstance(draft, dict) or draft.get('chat') != self.chat
                or draft.get('kind') not in ('delete', 'news')
                or type(draft.get('created')) not in (int, float)
                or not 0 <= now - draft['created'] <= DRAFT_TTL
                or not re.fullmatch(r'[a-f0-9]{32}', str(draft.get('nonce', '')))
                or not re.fullmatch(r'[a-f0-9]{64}', str(draft.get('fingerprint', '')))
                or not isinstance(draft.get('body'), str)
                or not isinstance(draft.get('subject'), str)
                or type(draft.get('count')) is not int
                or (draft['kind'] == 'delete' and (not USER.fullmatch(draft['subject']) or draft['body']))
                or (draft['kind'] == 'news' and (not draft['body'].strip() or utf16_size(draft['body']) > 3000
                                                or not 1 <= draft['count'] <= 10000))
                or not hmac.compare_digest(hashlib.sha256(draft['body'].encode()).hexdigest(), str(draft.get('body_sha256', '')))):
            raise ValueError('Подтверждение истекло или повреждено. Создай новый запрос.')
        return draft

    def stage(self, kind, subject, body, fingerprint, count=0, now=None):
        if not re.fullmatch(r'[a-f0-9]{64}', fingerprint):
            raise ValueError('Не удалось проверить состояние действия.')
        if kind == 'delete' and (not USER.fullmatch(subject) or body):
            raise ValueError('Некорректный пользователь.')
        if kind == 'news' and (not body.strip() or utf16_size(body) > 3000 or not 1 <= count <= 10000):
            raise ValueError('Новость: до 3000 UTF-16 символов и хотя бы один получатель.')
        if kind not in ('delete', 'news'):
            raise ValueError('Недопустимое действие.')
        draft = {'chat': self.chat, 'kind': kind, 'subject': subject, 'body': body,
                 'fingerprint': fingerprint, 'count': count,
                 'body_sha256': hashlib.sha256(body.encode()).hexdigest(),
                 'nonce': secrets.token_hex(16), 'created': time.time() if now is None else now}
        with self.locked():
            if self.path.is_symlink():
                raise ValueError('Небезопасный файл подтверждения.')
            fd, temporary = tempfile.mkstemp(prefix='.admin-action.', suffix='.env', dir=self.directory)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                    os.chmod(temporary, 0o600)
                    json.dump(draft, stream, ensure_ascii=False)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        if kind == 'delete':
            message = '<b>Подтвердить удаление?</b>\nПользователь: <code>' + html.escape(subject) + '</code>'
            message += '\nБудут отозваны доступ и подписка на всех нодах.'
        else:
            message = '<b>Предпросмотр рассылки</b>\nПолучателей: ' + str(count)
            message += '\n\n' + html.escape(bounded(body))
        message += '\n\nПодтверждение действует 5 минут и используется один раз.'
        return envelope(message, [['✅ /confirm ' + draft['nonce']], ['❌ Отмена']])

    def peek(self, now=None):
        with self.locked():
            draft = self.read(time.time() if now is None else now)
            return {key: draft[key] for key in ('kind', 'subject', 'nonce', 'count')}

    def take(self, nonce, fingerprint, now=None):
        with self.locked():
            draft = self.read(time.time() if now is None else now)
            if not hmac.compare_digest(str(nonce), draft['nonce']):
                raise ValueError('Не совпадает подтверждение. Создай новый запрос.')
            if not hmac.compare_digest(str(fingerprint), draft['fingerprint']):
                raise ValueError('Пользователь или список получателей изменился. Создай новый запрос.')
            self.path.unlink()
            return {key: draft[key] for key in ('kind', 'subject', 'body')}

    def cancel(self):
        with self.locked():
            if self.path.is_symlink():
                raise ValueError('Небезопасный файл подтверждения.')
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
        return envelope('Действие отменено.', [['🏠 Главное меню']])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('page', 'stage', 'peek', 'take', 'cancel'))
    parser.add_argument('--view', choices=tuple(COMMANDS) + ('detail',))
    parser.add_argument('--request', default='')
    parser.add_argument('--state-dir')
    parser.add_argument('--chat', default='')
    parser.add_argument('--kind', choices=('delete', 'news'))
    parser.add_argument('--subject', default='')
    parser.add_argument('--fingerprint', default='')
    parser.add_argument('--nonce', default='')
    parser.add_argument('--count', type=int, default=0)
    args = parser.parse_args()
    if args.action == 'page':
        result = render_page(read_rows(sys.stdin.read(1000001)), args.view, args.request)
    else:
        if not args.state_dir:
            raise ValueError('Не задан каталог подтверждений.')
        store = DraftStore(args.state_dir, args.chat)
        if args.action == 'stage':
            result = store.stage(args.kind, args.subject, sys.stdin.read(16001), args.fingerprint, args.count)
        elif args.action == 'take':
            result = store.take(args.nonce, args.fingerprint)
        elif args.action == 'peek':
            result = store.peek()
        else:
            result = store.cancel()
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        message = str(error) if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError) else 'Не удалось безопасно обработать меню.'
        print(json.dumps({'error': message}, ensure_ascii=False))
        raise SystemExit(1)
