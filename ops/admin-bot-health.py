#!/usr/bin/env python3
"""Bounded, read-only fleet checks. Never emit credentials or full configs."""
import argparse
from collections import Counter
import datetime as dt
import html
import ipaddress
import json
import math
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time

try:
    import yaml
except ImportError:
    yaml = None

SCHEMA = 1
UNITS = ('caddy', 'xray', 'haproxy', 'hysteria', 'fail2ban', 'unbound', 'naiveproxy-bot', 'yurich-sales-bot')
SETTINGS = ('DOMAIN', 'SUBSCRIPTION_DOMAIN', 'CADDY_BIN', 'CADDYFILE', 'XRAY_CONFIG',
            'HYSTERIA_CONFIG', 'XRAY_CADDY_FALLBACK_PORT', 'EDGE_ROUTING_MODE', 'HYSTERIA_PORT',
            'UNBOUND_ENABLED', 'UNBOUND_MODE')
CORE = '/usr/local/bin/yurich-panel.sh'
NAIVE_FORK_COMMIT = 'd62c80d3dd2c'
MODES = ('status', 'diagnose', 'protocols', 'cert', 'logs')


def command(args, timeout=4):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, encoding='utf-8', errors='replace')
        return result.returncode, result.stdout[:262144]
    except (OSError, subprocess.TimeoutExpired):
        return 1, ''


def configuration():
    code = 'source ' + CORE + '; load_config || exit 1; '
    code += 'for k in ' + ' '.join(SETTINGS) + '; do printf "%s\\0%s\\0" "$k" "${!k-}"; done'
    rc, output = command(['bash', '-c', code], timeout=6)
    if rc:
        raise RuntimeError('Server configuration could not be loaded')
    parts = output.split('\0')
    return dict(zip(parts[:-1:2], parts[1:-1:2]))


def service_states():
    _, output = command(['systemctl', 'show', *UNITS, '-p', 'Id', '-p', 'LoadState', '-p', 'ActiveState', '-p', 'MainPID'])
    result = {}
    for block in output.strip().split('\n\n'):
        fields = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        name = fields.get('Id', '').removesuffix('.service')
        if name in UNITS:
            result[name] = {'active': fields.get('ActiveState') == 'active',
                            'loaded': fields.get('LoadState') == 'loaded'}
    return result


def ports(protocol):
    rc, output = command(['ss', '-H', '-ln' + protocol])
    found = set()
    for line in output.splitlines():
        columns = line.split()
        if len(columns) >= 5:
            match = re.search(r':(\d+)$', columns[3])
            if match:
                found.add(int(match[1]))
    return sorted(found) if not rc else None


def resources():
    mem = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, _, value = line.partition(':')
        mem[key] = int(value.strip().split()[0]) * 1024
    disk = shutil.disk_usage('/')
    usable = disk.used + disk.free
    return {'ram_percent': round((1 - mem['MemAvailable'] / mem['MemTotal']) * 100),
            'disk_percent': math.ceil(disk.used / usable * 100) if usable else 0,
            'disk_free_gib': round(disk.free / 1024**3, 1), 'ram_total_gib': round(mem['MemTotal'] / 1024**3, 1)}


def tls_check(domain, port, address='127.0.0.1'):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{1,252}', domain):
        return {'ok': False, 'error': 'domain_not_configured'}
    connected = False
    try:
        context = ssl.create_default_context()
        context.set_alpn_protocols(['h2', 'http/1.1'])
        with socket.create_connection((address, port), timeout=3) as sock:
            connected = True
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                expires = ssl.cert_time_to_seconds(cert['notAfter'])
                return {'ok': True, 'tcp_ok': True, 'alpn': tls.selected_alpn_protocol(),
                        'days': int((expires - time.time()) // 86400),
                        'expires': dt.datetime.fromtimestamp(expires, dt.timezone.utc).strftime('%Y-%m-%d'),
                        'endpoint': address + ':' + str(port)}
    except ssl.SSLCertVerificationError:
        return {'ok': False, 'tcp_ok': connected, 'error': 'certificate_verification_failed'}
    except (OSError, ValueError, KeyError):
        return {'ok': False, 'tcp_ok': connected, 'error': 'tls_unavailable'}


def relay_check(host, port, tls_name):
    if (not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{1,252}', host)
            or type(port) is not int or not 1 <= port <= 65535
            or not isinstance(tls_name, str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{1,252}', tls_name)):
        raise ValueError('Invalid configured relay endpoint')
    result = tls_check(tls_name, port, address=host)
    return {'host': host, 'port': port, 'tls_name': tls_name, 'tls': result,
            'ok': result.get('ok', False) and result.get('alpn') == 'h2'}


def relay_lines(relays):
    if not isinstance(relays, list) or len(relays) > 8:
        raise ValueError('Invalid relay result list')
    result = []
    for relay in relays:
        if not isinstance(relay, dict):
            raise ValueError('Invalid relay result')
        host, port, name = relay.get('host', '?'), relay.get('port', '?'), relay.get('tls_name', '?')
        text = 'Relay TCP/TLS: ' + str(host) + ':' + str(port) + ', XHTTP SNI ' + str(name)
        okay = relay.get('ok') is True and relay.get('tls', {}).get('ok') is True and relay.get('tls', {}).get('alpn') == 'h2'
        result.append(('pass' if okay else 'fail', text + (', h2 подтверждён' if okay else ' не подтверждён')))
    return result


def protocol_entry_lines(data):
    domain = data.get('domain', '')
    if not isinstance(domain, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{1,252}', domain):
        return ['Входы ноды: домен не подтверждён.']
    port = data.get('hysteria_port')
    udp_port = str(port) if type(port) is int and 1 <= port <= 65535 else '?'
    lines = ['<b>Входы ноды</b>',
             'Naive: <code>' + html.escape(domain) + ':443</code> · TCP, прямой вход.',
             'Hysteria2: <code>' + html.escape(domain) + ':' + udp_port + '</code> · UDP, прямой вход.']
    # The gateway also checks downstream relays; only match this node's TLS name.
    relays = [relay for relay in data.get('relay_checks', [])
              if isinstance(relay, dict) and isinstance(relay.get('tls_name'), str)
              and relay['tls_name'].rstrip('.').lower() == domain.rstrip('.').lower()]
    if relays:
        lines.append('Reality/XHTTP этой ноды используют TCP-relay, указанный выше.')
        lines.append('Relay-маршрут выше относится к Reality/XHTTP; входы Naive и Hysteria2 остаются прямыми.')
    lines.append('Входы ноды не означают, что все эти профили опубликованы для каждого пользователя.')
    return lines


def hosts_check(domains):
    entries = {}
    for line in Path('/etc/hosts').read_text().splitlines():
        fields = line.split('#', 1)[0].split()
        if not fields:
            continue
        try:
            address = str(ipaddress.ip_address(fields[0]))
        except ValueError:
            continue
        for name in fields[1:]:
            if name.lower() in domains:
                entries.setdefault(name.lower(), set()).add(address)
    result = []
    for domain, addresses in entries.items():
        checked, matched, mismatch = set(), set(), False
        for family in ('A', 'AAAA'):
            relevant = {str(ipaddress.ip_address(address)) for address in addresses
                        if ipaddress.ip_address(address).version == (4 if family == 'A' else 6)}
            if not relevant:
                continue
            rc, output = command(['dig', '@1.1.1.1', '+time=1', '+tries=1', '+short', family, domain], timeout=2)
            public = set()
            for line in output.splitlines():
                try:
                    public.add(str(ipaddress.ip_address(line)))
                except ValueError:
                    continue
            if not rc and public:
                checked |= relevant
                matched |= relevant & public
                mismatch |= not relevant <= public
        status = 'mismatch' if mismatch else 'match' if checked == matched == addresses else 'unverified'
        result.append({'domain': domain, 'status': status})
    return result


def naive_build(config):
    binary = config.get('CADDY_BIN') or '/usr/local/bin/caddy'
    rc_modules, modules = command([binary, 'list-modules'], timeout=5)
    rc_build, build = command([binary, 'build-info'], timeout=5)
    module = not rc_modules and 'http.handlers.forward_proxy' in modules.splitlines()
    fork = not rc_build and bool(re.search(r'github\.com/klzgrad/forwardproxy\s+\S*' + NAIVE_FORK_COMMIT, build))
    return {'forward_proxy': module, 'pinned_naive_fork': fork, 'padding_build_verified': module and fork}


def xray_protocols(config, listening):
    try:
        data = json.loads(Path(config.get('XRAY_CONFIG') or '/etc/xray/config.json').read_text())
        result = []
        for inbound in data.get('inbounds', []):
            if inbound.get('protocol') not in ('vless', 'trojan', 'shadowsocks', 'socks'):
                continue
            stream = inbound.get('streamSettings', {})
            port = inbound.get('port')
            result.append({'protocol': inbound['protocol'], 'transport': stream.get('network', 'tcp'),
                           'security': stream.get('security', 'none'), 'port': port,
                           'listening': isinstance(port, int) and listening is not None and port in listening})
        return result
    except (OSError, ValueError, TypeError):
        return None


SOCKS_UDP_TIMEOUT = 1.5
HYSTERIA_CONFIG_LIMIT = 262144
PRIVATE_DESTINATIONS = tuple(ipaddress.ip_network(value) for value in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4',
    '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8',
))


def read_hysteria_config(config):
    if yaml is None:
        return None, 'yaml_unavailable'

    class UniqueLoader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            self.flatten_mapping(node)
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str) or key in result:
                    raise ValueError('Ambiguous YAML mapping')
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    try:
        path = Path(config.get('HYSTERIA_CONFIG') or '/etc/naiveproxy/hysteria.yaml')
        with path.open('r', encoding='utf-8') as source:
            text = source.read(HYSTERIA_CONFIG_LIMIT + 1)
        if len(text) > HYSTERIA_CONFIG_LIMIT:
            return None, 'config_too_large'
        data = yaml.load(text, Loader=UniqueLoader)
        if not isinstance(data, dict):
            return None, 'config_invalid'
        return data, None
    except OSError:
        return None, 'config_unavailable'
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        return None, 'config_invalid'


def configured_hysteria_port(data):
    listen = data.get('listen') if isinstance(data, dict) else None
    if not isinstance(listen, str):
        return None
    match = re.fullmatch(r'(?:\[[0-9a-fA-F:]+\]|[^:\s]*):([0-9]{1,5})', listen)
    port = int(match[1]) if match else 0
    return port if 1 <= port <= 65535 else None


def hysteria_port(config):
    data, _ = read_hysteria_config(config)
    return configured_hysteria_port(data)


def loopback_socks_endpoint(value):
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r'(?:([0-9.]+)|\[([0-9a-fA-F:]+)\]):([0-9]{1,5})', value)
    if not match:
        return None
    try:
        address = ipaddress.ip_address(match[1] or match[2])
    except ValueError:
        return None
    port = int(match[3])
    if not address.is_loopback or not 1 <= port <= 65535:
        return None
    return (socket.AF_INET if address.version == 4 else socket.AF_INET6, str(address), port)


def socks_udp_probe(outbound):
    settings = outbound.get('socks5') if isinstance(outbound, dict) else None
    endpoint = loopback_socks_endpoint(settings.get('addr')) if isinstance(settings, dict) else None
    if endpoint is None:
        return {'status': 'unknown', 'reason': 'non_loopback_or_invalid_endpoint'}

    deadline = time.monotonic() + SOCKS_UDP_TIMEOUT

    def budget(sock):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        sock.settimeout(remaining)

    def receive(sock, size):
        value = b''
        while len(value) < size:
            budget(sock)
            part = sock.recv(size - len(value))
            if not part:
                raise OSError()
            value += part
        return value

    try:
        family, address, port = endpoint
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            budget(sock)
            sock.connect((address, port))
            budget(sock)
            sock.sendall(b'\x05\x01\x00')
            greeting = receive(sock, 2)
            if greeting != b'\x05\x00':
                return {'status': 'unknown', 'reason': 'anonymous_socks_unavailable'}
            budget(sock)
            sock.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
            header = receive(sock, 3)
            if header[0] != 5 or header[2] != 0:
                return {'status': 'unknown', 'reason': 'invalid_socks_reply'}
            if header[1] == 7:
                # WARP closes after a three-byte command-not-supported reply.
                try:
                    budget(sock)
                    address_type = sock.recv(1)
                except OSError:
                    address_type = b''
                if address_type and address_type[0] not in (1, 3, 4):
                    return {'status': 'unknown', 'reason': 'invalid_socks_reply'}
                return {'status': 'unsupported', 'reply': 7}
            if header[1] != 0:
                return {'status': 'unknown', 'reason': 'socks_rejected', 'reply': header[1]}
            header += receive(sock, 1)
            if header[3] not in (1, 3, 4):
                return {'status': 'unknown', 'reason': 'invalid_socks_reply'}
            size = {1: 4, 4: 16}.get(header[3])
            if size is None:
                size = receive(sock, 1)[0]
                if not size:
                    return {'status': 'unknown', 'reason': 'invalid_socks_reply'}
            receive(sock, size + 2)
            return {'status': 'accepted'}
    except TimeoutError:
        return {'status': 'unknown', 'reason': 'probe_timeout'}
    except OSError:
        return {'status': 'unknown', 'reason': 'socket_error'}


def private_destination(value):
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return False
    return any(network.version == private.version and network.subnet_of(private)
               for private in PRIVATE_DESTINATIONS)


def hysteria_udp_path(data):
    # Only unconditional UDP rules and literal private rejects are understood.
    # An unfamiliar earlier rule can change the route, so it stops inference.
    outbounds = data.get('outbounds')
    if outbounds is None:
        outbounds = []
    if not isinstance(outbounds, list) or len(outbounds) > 64:
        return 'unknown', 'outbounds_invalid', None
    named = {}
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            return 'unknown', 'outbounds_invalid', None
        name, kind = outbound.get('name'), outbound.get('type')
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,63}', name)
                or name in named or not isinstance(kind, str)
                or name == 'default' or (name in ('direct', 'reject') and name != kind)):
            return 'unknown', 'outbounds_invalid', None
        named[name] = outbound

    def route(name):
        # Hysteria's builtin default selects the first configured outbound.
        if name == 'default' and not outbounds:
            return 'direct', 'acl', None
        outbound = outbounds[0] if name == 'default' else named.get(name)
        if outbound is None and name in ('direct', 'reject'):
            return name, 'acl', None
        kind = outbound.get('type') if outbound else None
        return (kind if kind in ('direct', 'socks5') else 'unknown',
                'acl' if kind in ('direct', 'socks5') else 'outbound_unknown', outbound)

    acl = data.get('acl')
    if acl is not None:
        if not isinstance(acl, dict):
            return 'unknown', 'acl_invalid', None
        if acl.get('file') not in (None, ''):
            return 'unknown', 'external_acl', None
        if set(acl) - {'inline', 'file'}:
            return 'unknown', 'acl_options_unknown', None
        rules = acl.get('inline')
        if rules is None:
            rules = []
        if not isinstance(rules, list) or len(rules) > 1024:
            return 'unknown', 'acl_invalid', None
        parsed = []
        for rule in rules:
            if not isinstance(rule, str):
                return 'unknown', 'acl_unknown', None
            if not rule.strip() or rule.lstrip().startswith('#'):
                continue
            match = re.fullmatch(
                r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([^(),]+?)\s*'
                r'(?:,\s*([^(),]+?)\s*)?\)\s*(?:#.*)?', rule)
            if not match:
                return 'unknown', 'acl_unknown', None
            target, destination, protocol = match.groups()
            if (protocol not in (None, 'udp', 'tcp')
                    or target not in named and target not in ('direct', 'reject', 'default')):
                return 'unknown', 'acl_unknown', None
            parsed.append((target, destination, protocol))
        for target, destination, protocol in parsed:
            if protocol == 'tcp':
                continue
            if destination == 'all':
                return route(target)
            if target == 'reject' and private_destination(destination):
                continue
            return 'unknown', 'acl_unknown', None
    if not outbounds:
        return 'direct', 'default', None
    path, _, outbound = route(outbounds[0]['name'])
    return path, 'default' if path != 'unknown' else 'outbound_unknown', outbound


def hysteria_udp_diagnostic(data, error=None):
    result = {'path': 'unknown', 'reason': error or 'config_invalid',
              'socks5_present': None, 'socks_udp': {'status': 'not_probed'}}
    if error or not isinstance(data, dict):
        return result
    outbounds = data.get('outbounds')
    socks = [item for item in outbounds
             if isinstance(item, dict) and item.get('type') == 'socks5'] if isinstance(outbounds, list) else []
    result['socks5_present'] = bool(socks) if outbounds is None or isinstance(outbounds, list) else None
    path, reason, selected = hysteria_udp_path(data)
    result.update(path=path, reason=reason)
    probe = selected if path == 'socks5' else socks[0] if socks else None
    if probe is not None:
        result['socks_udp'] = socks_udp_probe(probe)
    return result


def hysteria_udp_lines(diagnostic):
    diagnostic = diagnostic if isinstance(diagnostic, dict) else {}
    path = diagnostic.get('path')
    probe = diagnostic.get('socks_udp')
    probe = probe if isinstance(probe, dict) else {}
    unsupported = probe.get('status') == 'unsupported' and probe.get('reply') == 7
    suffix = '; SOCKS UDP unsupported (UDP_ASSOCIATE=7)' if unsupported else ''
    if path == 'direct':
        if unsupported:
            suffix += ', SOCKS для UDP не используется'
        return [('pass', 'Hysteria2: UDP через VPS (настройка; не клиентский тест)' + suffix)]
    if path == 'reject':
        return [('fail', 'Hysteria2: UDP запрещён ACL; эффективного UDP bypass нет' + suffix)]
    if path == 'socks5' and unsupported:
        return [('fail', 'Hysteria2: SOCKS UDP unsupported (UDP_ASSOCIATE=7); эффективного UDP bypass нет')]
    if path == 'socks5' and probe.get('status') == 'accepted':
        return [('warn', 'Hysteria2: SOCKS UDP_ASSOCIATE принят; передача UDP и сеть клиента не проверялись')]
    if path == 'socks5':
        return [('warn', 'Hysteria2: UDP через SOCKS; UDP_ASSOCIATE не подтверждён (не клиентский тест)')]
    return [('warn', 'Hysteria2: UDP-маршрут unknown; ACL/YAML не подтверждены' + suffix)]


def redact(text):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    sensitive = r'authorization|proxy-authorization|password|private[_-]?key|token|secret'
    text = re.sub(r'(?i)("(?:' + sensitive + r')"\s*:\s*)(?:"(?:\\.|[^"\\])*"|\[[^\]\r\n]*\]|[^,}\s]+)', r'\1"[redacted]"', text)
    text = re.sub(r'(?i)(\b(?:proxy-authorization|authorization)\s*[:=]\s*)(?:Basic|Bearer)\s+\S+', r'\1[redacted]', text)
    text = re.sub(r'(?:https?://\S+/)?s/[a-fA-F0-9]{32,64}(?:/\S*)?', '[subscription]', text)
    text = re.sub(r'\b\d{5,15}:[A-Za-z0-9_-]{20,}\b', '[bot-token]', text)
    text = re.sub(r'\b(?:naive\+https|vless|trojan|hysteria2|hy2|ss)://\S+', '[proxy-link]', text)
    text = re.sub(r'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b', '[uuid]', text)
    text = re.sub(r'(?i)(authorization|proxy-authorization|password|private[_-]?key|token|secret)([\"\s:=]+)([^\s,}\]]+)', r'\1\2[redacted]', text)
    return text


def local_resolver_route(resolv_conf, dns_output='', domains_output=''):
    local = {'127.0.0.1', '::1'}
    stub = {'127.0.0.53', '127.0.0.54'}
    servers = []
    for line in resolv_conf.splitlines():
        fields = line.split('#', 1)[0].split()
        if len(fields) >= 2 and fields[0] == 'nameserver':
            try:
                servers.append(str(ipaddress.ip_address(fields[1])))
            except ValueError:
                return None, []
    if not servers:
        return None, []
    if set(servers) <= local:
        return True, servers
    if not set(servers) <= local | stub:
        return False, servers
    dns = dict(line.split(':', 1) for line in dns_output.splitlines() if ':' in line)
    domains = dict(line.split(':', 1) for line in domains_output.splitlines() if ':' in line)
    global_dns = dns.get('Global', '').split()
    if not global_dns or not domains.get('Global'):
        return None, servers
    if not set(global_dns) <= local or '~.' not in domains['Global'].split():
        return False, global_dns
    # More-specific per-link routes can override the global root route.
    for link, routes in domains.items():
        if link.strip() != 'Global' and routes.split() and not set(dns.get(link, '').split()) <= local:
            return False, global_dns
    return True, global_dns


def dns_query(name, tcp=False, checking_disabled=False):
    args = ['dig', '@127.0.0.1', name, 'A', '+dnssec', '+noall', '+answer', '+comments', '+time=2', '+tries=1']
    if tcp:
        args.append('+tcp')
    if checking_disabled:
        args.append('+cdflag')
    rc, output = command(args, timeout=3)
    status = re.search(r'status: ([A-Z]+)', output)
    flags = re.search(r';; flags: ([^;]+);', output)
    addresses = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[-2] == 'A':
            try:
                addresses.append(str(ipaddress.IPv4Address(fields[-1])))
            except ValueError:
                pass
    return {'status': status[1] if status and not rc else None,
            'ad': bool(flags and 'ad' in flags[1].split()), 'addresses': addresses}


def own_dns_check(config, expected_ips, deep=False):
    result = {'system_local': None, 'system_servers': [], 'recursive': None, 'deep': deep}
    try:
        resolv_conf = Path('/etc/resolv.conf').read_text()
        _, dns = command(['resolvectl', 'dns'], timeout=2)
        _, domains = command(['resolvectl', 'domain'], timeout=2)
        result['system_local'], result['system_servers'] = local_resolver_route(resolv_conf, dns, domains)
    except OSError:
        pass
    rc, _ = command(['unbound-checkconf'], timeout=3)
    if not rc:
        try:
            recursive = config.get('UNBOUND_MODE') == 'recursive'
            for path in Path('/etc/unbound').rglob('*.conf'):
                with path.open() as source:
                    text = source.read(1048577)
                if len(text) > 1048576:
                    recursive = None
                    break
                if re.search(r'(?m)^\s*forward-zone\s*:', text):
                    recursive = False
                    break
            result['recursive'] = recursive
        except (OSError, ValueError):
            pass
    if deep:
        lookup_rc, lookup = command(['getent', 'ahostsv4', 'example.com'], timeout=3)
        result['system_lookup'] = True if not lookup_rc and lookup.strip() else False if lookup_rc == 2 else None
        queries = {'signed_udp': dns_query('cloudflare.com'),
                   'signed_tcp': dns_query('cloudflare.com', tcp=True),
                   'bogus': dns_query('dnssec-failed.org'),
                   'bogus_cd': dns_query('dnssec-failed.org', checking_disabled=True)}
        result['queries'] = queries
        result['dnssec'] = (all(queries[key]['status'] == 'NOERROR' and queries[key]['ad']
                               for key in ('signed_udp', 'signed_tcp'))
                           and queries['bogus']['status'] == 'SERVFAIL'
                           and queries['bogus_cd']['status'] == 'NOERROR')
        if any(value['status'] is None for value in queries.values()):
            result['dnssec'] = None
        identity = dns_query('whoami.akamai.net')
        result['recursor_ips'] = identity['addresses']
        if identity['status'] == 'NOERROR' and identity['addresses'] and expected_ips:
            result['own_exit'] = set(identity['addresses']) <= set(expected_ips)
        else:
            result['own_exit'] = None
    return result


def dns_check_lines(data):
    result = []
    service = data.get('services', {}).get('unbound', {})
    if service.get('active') is True:
        result.append(('pass', 'DNS Unbound: запущен'))
    elif service.get('loaded') is False or service.get('active') is False:
        result.append(('fail', 'DNS Unbound: не запущен / не установлен'))
    else:
        result.append(('warn', 'DNS Unbound: состояние не проверено'))
    dns = data.get('dns')
    if not isinstance(dns, dict):
        result.append(('warn', 'Собственный DNS: маршрут и рекурсия не проверены'))
        return result
    def add(key, success, failure, unknown):
        value = dns.get(key)
        result.append(('pass' if value is True else 'fail' if value is False else 'warn',
                       success if value is True else failure if value is False else unknown))
    suffix = ', '.join(str(value) for value in dns.get('system_servers', []))[:200]
    add('system_local', 'DNS системы: собственный локальный resolver',
        'DNS системы: внешний / обход локального resolver' + (' (' + suffix + ')' if suffix else ''),
        'DNS системы: эффективный маршрут не подтверждён')
    add('recursive', 'DNS: рекурсия без публичного forwarder', 'DNS: recursive mode без forwarding не подтверждён',
        'DNS: конфигурацию рекурсии не удалось проверить')
    if dns.get('deep'):
        add('system_lookup', 'DNS системы: разрешение имени работает', 'DNS системы: имя не разрешается',
            'DNS системы: реальное разрешение имени не подтверждено')
        add('dnssec', 'DNSSEC: UDP/TCP, AD и неверная подпись проверены', 'DNSSEC: контрольные проверки не прошли',
            'DNSSEC: нет полного ответа, проверка не подтверждена')
        addresses = ', '.join(str(value) for value in dns.get('recursor_ips', []))[:200]
        add('own_exit', 'DNS-рекурсор: IP своей ноды (' + addresses + ')',
            'DNS-рекурсор: выходит с чужого IP (' + addresses + ')', 'DNS-рекурсор: исходящий IP не подтверждён')
    return result


def collect(mode):
    config = configuration()
    domain = config.get('DOMAIN', '')
    snapshot = {'schema': SCHEMA, 'hostname': socket.gethostname(), 'domain': domain,
                'utc': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
                'services': service_states(), 'resources': resources()}
    rc, addresses = command(['ip', '-j', '-4', 'addr'])
    if not rc:
        snapshot['ipv4'] = sorted({address['local'] for interface in json.loads(addresses)
                                   for address in interface.get('addr_info', [])
                                   if ipaddress.ip_address(address['local']).is_global})
    if mode == 'logs':
        rc, logs = command(['journalctl', '-u', 'caddy', '-u', 'xray', '-u', 'hysteria', '-u', 'haproxy',
                            '-n', '25', '--no-pager', '-o', 'short-iso'], timeout=5)
        snapshot['logs'] = redact(logs) if not rc else 'Логи недоступны'
        return snapshot
    tcp, udp = ports('t'), ports('u')
    snapshot['tcp_ports'], snapshot['udp_ports'] = tcp, udp
    tls_port = int(config.get('XRAY_CADDY_FALLBACK_PORT') or 7443)
    snapshot['tls'] = tls_check(domain, tls_port if tcp and tls_port in tcp else 443)
    if mode in ('status', 'diagnose', 'protocols'):
        snapshot['dns'] = own_dns_check(config, snapshot.get('ipv4', []), deep=mode == 'diagnose')
    if mode in ('diagnose', 'protocols'):
        snapshot['naive'] = naive_build(config)
        rc, _ = command([config.get('CADDY_BIN') or '/usr/local/bin/caddy', 'adapt', '--config',
                         config.get('CADDYFILE') or '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'], timeout=5)
        snapshot['caddyfile_valid'] = rc == 0
        snapshot['xray'] = xray_protocols(config, tcp)
        hysteria_config, hysteria_error = read_hysteria_config(config)
        snapshot['hysteria_port'] = configured_hysteria_port(hysteria_config)
        snapshot['hysteria_udp'] = hysteria_udp_diagnostic(hysteria_config, hysteria_error)
        rc, output = command(['ufw', 'status'])
        snapshot['ufw'] = not rc and 'Status: active' in output
        snapshot['hosts'] = hosts_check({domain.lower(), config.get('SUBSCRIPTION_DOMAIN', '').lower()})
    return snapshot


def check_lines(data):
    checks = []
    def add(level, text):
        checks.append((level, text))
    services = data['services']
    for unit in ('caddy', 'xray', 'haproxy', 'hysteria'):
        active = services.get(unit, {}).get('active', False)
        add('pass' if active else 'fail', unit + (' запущен' if active else ' не запущен / не проверен'))
    checks.extend(dns_check_lines(data))
    naive = data.get('naive', {})
    add('pass' if naive.get('padding_build_verified') else 'warn',
        'Naive padding: модуль и закреплённый fork подтверждены' if naive.get('padding_build_verified') else 'Naive padding: сборка не подтверждена')
    add('pass' if data.get('caddyfile_valid') else 'fail', 'Caddyfile: адаптация ' + ('OK' if data.get('caddyfile_valid') else 'не прошла'))
    xray = data.get('xray')
    if xray is None:
        add('fail', 'VLESS: конфигурация не проверена')
    elif not xray:
        add('warn', 'VLESS: управляемые входы отсутствуют')
    else:
        for inbound in xray:
            name = 'Reality' if inbound['security'] == 'reality' else 'XHTTP' if inbound['transport'] == 'xhttp' else inbound['transport']
            okay = inbound['listening'] and services.get('xray', {}).get('active', False)
            add('pass' if okay else 'fail', 'VLESS ' + name + ': TCP/' + str(inbound['port']) + (' слушает' if okay else ' не подтверждён'))
    port = data.get('hysteria_port')
    listening = port is not None and data.get('udp_ports') is not None and port in data['udp_ports'] and services.get('hysteria', {}).get('active', False)
    add('pass' if listening else 'fail', 'Hysteria2: UDP/' + (str(port) if port is not None else '?') + (' слушает' if listening else ' не подтверждён'))
    checks.extend(hysteria_udp_lines(data.get('hysteria_udp')))
    checks.extend(relay_lines(data.get('relay_checks', [])))
    hosts = data.get('hosts', [])
    if not hosts:
        add('pass', '/etc/hosts: VPN-домены не переопределены')
    for entry in hosts:
        status = entry['status']
        add('pass' if status == 'match' else 'warn', '/etc/hosts: ' + entry['domain'] +
            (' совпадает с публичным DNS (статическая запись)' if status == 'match' else ' отличается от публичного DNS' if status == 'mismatch' else ' DNS не удалось сверить'))
    tls = data.get('tls', {})
    add('pass' if tls.get('ok') and tls.get('alpn') == 'h2' else 'fail',
        'TLS/SNI: сертификат проверен, ALPN h2' if tls.get('ok') and tls.get('alpn') == 'h2' else 'TLS/SNI/h2: локальная проверка не прошла')
    if tls.get('ok'):
        days = tls['days']
        add('fail' if days < 7 else 'warn' if days < 30 else 'pass', 'Сертификат: ' + str(days) + ' дней')
    add('pass' if data.get('ufw') else 'warn', 'UFW ' + ('активен' if data.get('ufw') else 'неактивен / не проверен'))
    add('pass' if services.get('fail2ban', {}).get('active') else 'warn', 'Fail2Ban ' + ('активен' if services.get('fail2ban', {}).get('active') else 'не запущен / не проверен'))
    for key, name in (('ram_percent', 'RAM'), ('disk_percent', 'Диск')):
        value = data['resources'][key]
        add('fail' if value >= 95 else 'warn' if value >= 85 else 'pass', name + ': ' + str(value) + '%')
    return checks


def plain_pre(text, budget=2900):
    clean = ''.join(c for c in text if c in '\n\t' or ord(c) >= 32)
    output, used = [], 0
    for character in clean:
        encoded = html.escape(character, quote=False)
        cost = len(encoded.encode('utf-16-le')) // 2
        if used + cost > budget:
            output.append('\n[вывод сокращён]')
            break
        output.append(encoded)
        used += cost
    return ''.join(output) or 'нет вывода'


def test_route_description(domain):
    if not Path('/etc/naiveproxy/subscription-test-routes.json').is_file():
        return ''
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,252}', domain):
        return ''
    rc, output = command(['python3', '-B', '/usr/local/lib/yurich-panel/subscription-test-routes.py', '--describe', domain])
    if rc:
        return 'Test ingress metadata unavailable; this is not a protocol test result.'
    return output.strip()[:500]


def render(envelope, mode):
    label = html.escape(str(envelope.get('label', 'Сервер'))[:100])
    if not envelope.get('ok'):
        return '❌ <b>' + label + '</b>\nSSH/проверка недоступны. Это не результат VPN-теста.'
    data = dict(envelope['snapshot'])
    data['relay_checks'] = envelope.get('relay_checks', [])
    if data.get('schema') != SCHEMA:
        raise ValueError('Unexpected health schema')
    for field in ('ram_percent', 'disk_percent'):
        if type(data['resources'][field]) is not int or not 0 <= data['resources'][field] <= 100:
            raise ValueError('Invalid resource percentage')
    if type(data['resources']['disk_free_gib']) not in (int, float):
        raise ValueError('Invalid resource size')
    if data.get('tls', {}).get('ok') and type(data['tls']['days']) is not int:
        raise ValueError('Invalid certificate expiry')
    title = {'status': 'Состояние', 'diagnose': 'Диагностика', 'protocols': 'Протоколы', 'cert': 'Сертификат', 'logs': 'Логи'}[mode]
    lines = ['<b>' + title + ': ' + label + '</b>', 'Домен: <code>' + html.escape(data.get('domain', '')) + '</code>']
    if data.get('ipv4'):
        lines.append('IPv4: <code>' + html.escape(', '.join(data['ipv4'])) + '</code>')
    routes = str(envelope.get('routes', ''))[:500]
    if routes:
        lines.append('<code>' + html.escape(routes) + '</code>')
    test_routes = test_route_description(data.get('domain', ''))
    if test_routes:
        lines.append('<code>' + html.escape(test_routes) + '</code>')
    if data['relay_checks'] and mode != 'diagnose':
        lines.extend(('✅ ' if level == 'pass' else '❌ ') + '<code>' + html.escape(text) + '</code>'
                     for level, text in relay_lines(data['relay_checks']))
    if mode == 'status':
        for unit in ('caddy', 'xray', 'haproxy', 'hysteria'):
            lines.append(('✅ ' if data['services'].get(unit, {}).get('active') else '❌ ') + unit)
        r = data['resources']
        for field, name in (('ram_percent', 'RAM'), ('disk_percent', 'Диск')):
            lines.append(('⚠️ ' if r[field] >= 85 else '') + name + ': ' + str(r[field]) + '%')
        lines.append('Свободно на диске: ' + str(r['disk_free_gib']) + ' GiB')
        tls = data.get('tls', {})
        lines.append(('⚠️ ' if tls.get('days', 0) < 30 else '') + 'TLS: ' + (str(tls['days']) + ' дней, ' + html.escape(str(tls.get('alpn'))) if tls.get('ok') else 'локальная проверка не прошла'))
        icons = {'pass': '✅ ', 'warn': '⚠️ ', 'fail': '❌ '}
        lines.extend(icons[level] + html.escape(text) for level, text in dns_check_lines(data))
    elif mode == 'diagnose':
        checks = check_lines(data)
        icons = {'pass': '✅ ', 'warn': '⚠️ ', 'fail': '❌ '}
        lines += [icons[level] + ('<code>' + html.escape(text) + '</code>' if text.startswith('Relay TCP/TLS: ') else html.escape(text))
                  for level, text in checks]
        counts = Counter(level for level, _ in checks)
        lines.append('Пройдено: ' + str(counts['pass']) + ' · Внимание: ' + str(counts['warn']) + ' · Проблемы: ' + str(counts['fail']))
    elif mode == 'cert':
        tls = data.get('tls', {})
        if tls.get('ok'):
            lines += ['✅ Имя и цепочка TLS проверены', 'ALPN: ' + html.escape(str(tls.get('alpn'))),
                      'Истекает: ' + html.escape(tls['expires']) + ', осталось ' + str(tls['days']) + ' дней']
        else:
            lines.append('❌ TLS не подтверждён: ' + html.escape(tls.get('error', 'unavailable')))
    elif mode == 'logs':
        lines.append('<pre>' + plain_pre(data.get('logs', '')) + '</pre>')
    elif mode == 'protocols':
        naive = data.get('naive', {})
        naive_ok = naive.get('padding_build_verified') and data['services'].get('caddy', {}).get('active') and data.get('tls', {}).get('ok') and data.get('tls', {}).get('alpn') == 'h2'
        lines.append(('✅ ' if naive_ok else '⚠️ ') + 'Naive: сборка/TLS/h2 ' + ('подтверждены (сервер)' if naive_ok else 'не подтверждены полностью'))
        for inbound in data.get('xray') or []:
            description = 'VLESS Reality' if inbound['security'] == 'reality' else 'VLESS XHTTP' if inbound['transport'] == 'xhttp' else inbound['protocol'] + ' ' + inbound['transport']
            lines.append(('✅ ' if inbound['listening'] and data['services'].get('xray', {}).get('active') else '⚠️ ') + html.escape(description) + ': порт ' + html.escape(str(inbound['port'])) + ' (сервер)')
        if data.get('xray') is None:
            lines.append('⚠️ Конфигурация Xray не проверена')
        port = data.get('hysteria_port')
        listening = port is not None and data.get('udp_ports') is not None and port in data['udp_ports'] and data['services'].get('hysteria', {}).get('active')
        lines.append(('✅ ' if listening else '⚠️ ') + 'Hysteria2: UDP/' + (str(port) if port is not None else '?') + ' (сервер)')
        icons = {'pass': '✅ ', 'warn': '⚠️ ', 'fail': '❌ '}
        lines.extend(icons[level] + html.escape(text)
                     for level, text in hysteria_udp_lines(data.get('hysteria_udp')))
        lines.extend(icons[level] + html.escape(text) for level, text in dns_check_lines(data))
    if mode in ('diagnose', 'protocols'):
        lines.extend(protocol_entry_lines(data))
        lines.append('DNS-время в приложении не подтверждает QUIC-соединение или авторизацию Hysteria2.')
    if mode != 'logs':
        if routes and 'VLESS' in routes:
            lines.append('Relay-вход не является адресом веб-страницы. Reality использует SNI из профиля; XHTTP — имя конечной ноды.')
        lines.append('Зелёные отметки TCP/TLS и служб — серверные проверки, не VPN-авторизация и прохождение трафика.')
        lines.append('Проверка на сервере; подключение из сети клиента не проверялось.')
    lines.append(html.escape(data['utc']))
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('collect', 'render', 'pre', 'relay'))
    parser.add_argument('mode', nargs='?', choices=MODES, default='status')
    parser.add_argument('--host')
    parser.add_argument('--port', type=int)
    parser.add_argument('--tls-name')
    args = parser.parse_args()
    if args.action == 'collect':
        print(json.dumps({'ok': True, 'snapshot': collect(args.mode)}, ensure_ascii=False))
    elif args.action == 'render':
        print(render(json.load(sys.stdin), args.mode))
    elif args.action == 'relay':
        print(json.dumps(relay_check(args.host, args.port, args.tls_name), ensure_ascii=False))
    else:
        print(plain_pre(sys.stdin.read()))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        if len(sys.argv) > 1 and sys.argv[1] in ('collect', 'relay'):
            print(json.dumps({'ok': False, 'error': 'read_only_health_check_failed'}))
        else:
            print('Проверка недоступна; подробности не отправлены для защиты конфигурации.')
        raise SystemExit(1)
