#!/usr/bin/env python3
"""Read-only fleet observations and incident notifications; never repair servers."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import html
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

CORE = '/usr/local/bin/yurich-panel.sh'
HEALTH = Path(__file__).with_name('admin-bot-health.py')
INCIDENTS = Path(__file__).with_name('admin-incidents.py')
DEFAULT_STATE = '/var/lib/yurich-panel/incidents'
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}')
CHECKS = ('node_access','service_caddy','service_xray','service_haproxy','service_hysteria','service_unbound',
          'tls','certificate_expiry','disk','ram','dns_system_local','dns_recursive','dns_system_lookup',
          'dns_dnssec','dns_own_exit','hysteria_udp_path','public_tls')


def process(args, *, data=None, timeout=80):
    if os.name != 'posix':raise RuntimeError('linux_monitor_required')
    child = subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    output = bytearray()
    error_bytes = 0
    pending = memoryview(data.encode('utf-8') if data is not None else b'')
    deadline = time.monotonic()+timeout
    selector = selectors.DefaultSelector()
    try:
        for stream in (child.stdout,child.stderr):
            os.set_blocking(stream.fileno(),False)
            selector.register(stream,selectors.EVENT_READ,'stdout' if stream is child.stdout else 'stderr')
        if pending:
            os.set_blocking(child.stdin.fileno(),False)
            selector.register(child.stdin,selectors.EVENT_WRITE,'stdin')
        else:child.stdin.close()
        while selector.get_map():
            remaining = deadline-time.monotonic()
            if remaining<=0:raise RuntimeError('bounded_probe_timeout')
            for key,_ in selector.select(min(remaining,0.2)):
                if key.data=='stdin':
                    try:written=os.write(key.fileobj.fileno(),pending[:65536])
                    except BlockingIOError:continue
                    except BrokenPipeError:written=len(pending)
                    pending=pending[written:]
                    if not pending:selector.unregister(key.fileobj);key.fileobj.close()
                    continue
                try:block=os.read(key.fileobj.fileno(),65536)
                except BlockingIOError:continue
                if not block:selector.unregister(key.fileobj);key.fileobj.close();continue
                if key.data=='stdout':
                    output.extend(block)
                    if len(output)>262144:raise RuntimeError('bounded_probe_output')
                else:
                    error_bytes+=len(block)
                    if error_bytes>32768:raise RuntimeError('bounded_probe_error_output')
        child.wait(timeout=max(0.1,deadline-time.monotonic()))
    except (RuntimeError,subprocess.TimeoutExpired):
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        raise RuntimeError('bounded_probe_failed') from None
    finally:
        selector.close()
        for stream in (child.stdin,child.stdout,child.stderr):
            if not stream.closed:stream.close()
        if child.poll() is None:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:child.wait(timeout=2)
            except subprocess.TimeoutExpired:pass
    if child.returncode:
        raise RuntimeError('bounded_probe_failed')
    return output.decode('utf-8',errors='replace')


def incident_api(action, state, *args, payload=None):
    output = process([sys.executable,'-B',str(INCIDENTS),action,'--state-dir',str(state),*args],
        data=json.dumps(payload,ensure_ascii=True) if payload is not None else None, timeout=12)
    result = json.loads(output)
    if result.get('ok') is not True:raise RuntimeError('incident_storage_unavailable')
    return result


def registry():
    script = '''source "$1"; load_config || exit 1
name="${TG_MONITOR_LOCAL_NODE:-}"
if [[ -z "$name" ]]; then
    [[ "${DOMAIN:-}" == poland.* ]] && name=poland || name=primary
fi
printf '%s\\t%s\\n' "$name" "${DOMAIN:-}"
nodes_list_lines
'''
    output = process(['bash','-c',script,'--',CORE],timeout=12)
    lines = output.splitlines()
    local = lines[0].split('\t') if lines else []
    if (len(local) != 2 or not IDENTIFIER.fullmatch(local[0])
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{1,252}',local[1])):
        raise RuntimeError('invalid_local_registry')
    nodes = [{'name':local[0],'local':True,'domain':local[1]}]
    for line in lines[1:]:
        fields = line.split('|')
        if len(fields) != 8 or not IDENTIFIER.fullmatch(fields[0]):raise RuntimeError('invalid_registry')
        name,host,port,user,domain,role,weight,enabled = fields
        if enabled != '1':continue
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',host) or not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise RuntimeError('invalid_registry')
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',user) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{1,252}',domain):
            raise RuntimeError('invalid_registry')
        nodes.append({'name':name,'host':host,'port':port,'user':user,'domain':domain,'local':False})
    if len(nodes)>16 or len({node['name'] for node in nodes}) != len(nodes):raise RuntimeError('invalid_registry')
    return nodes


def snapshot(node, timeout=52):
    if node['local']:
        args = [sys.executable,'-B',str(HEALTH),'collect','diagnose']
    else:
        import base64
        encoded = base64.b64encode(HEALTH.read_bytes()).decode('ascii')
        command = ('' if node['user']=='root' else 'sudo -n ') + 'python3 -B -c '
        import shlex
        command += shlex.quote('import base64;exec(compile(base64.b64decode("'+encoded+'"),"<yurich-health>","exec"))') + ' collect diagnose'
        args = ['ssh','-n','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','ConnectionAttempts=1',
            '-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2','-o','StrictHostKeyChecking=yes',
            '-o','UserKnownHostsFile=/etc/naiveproxy/nodes_known_hosts','-p',node['port'],
            node['user']+'@'+node['host'],command]
    return json.loads(process(args,timeout=timeout))


def public_tls(domain, timeout=8):
    try:
        value=json.loads(process([sys.executable,'-B',str(HEALTH),'relay','--host',domain,'--port','443','--tls-name',domain],timeout=timeout))
        return value.get('ok') is True
    except (RuntimeError,ValueError,OSError):return False


def observations(node, envelope, ingress=None):
    name = node['name']
    result = []
    def add(check,status,summary):
        result.append({'node':name,'check':check,'status':status,'summary':summary})
    def flag(check,value,summary):
        add(check,'ok' if value is True else 'fail' if value is False else 'unknown',summary)
    data = envelope.get('snapshot') if isinstance(envelope,dict) and envelope.get('ok') is True else None
    if (not isinstance(data,dict) or type(data.get('schema')) is not int or data.get('schema') != 1
            or any(not isinstance(data.get(key),dict) for key in ('services','tls','resources','dns','hysteria_udp'))):
        for check in CHECKS:
            add(check,'fail' if check=='node_access' else 'unknown',
                'SSH/серверная проверка недоступны; отказ VPN этим не доказан.' if check=='node_access' else 'Нет свежих данных с ноды.')
        return result
    add('node_access','ok','Серверный снимок получен; доступ из мобильной сети отдельно не проверен.')
    for unit in ('caddy','xray','haproxy','hysteria','unbound'):
        service=data['services'].get(unit)
        flag('service_'+unit,service.get('active') if isinstance(service,dict) else None,'Служба '+unit+': серверная проверка.')
    tls = data.get('tls',{})
    value = tls.get('ok') is True and tls.get('alpn') == 'h2'
    flag('tls',value,'Локальные TLS/SNI/ALPN h2 '+('подтверждены.' if value else 'не подтверждены.'))
    days = tls.get('days')
    flag('certificate_expiry',days >= 7 if type(days) is int else None,
         'Сертификат: '+(str(days)+' дней.' if type(days) is int else 'срок не проверен.'))
    for key,check,limit,label in (('disk_percent','disk',90,'Диск'),('ram_percent','ram',95,'RAM')):
        value = data.get('resources',{}).get(key)
        valid = type(value) is int and 0 <= value <= 100
        flag(check,value < limit if valid else None,label+': '+(str(value)+'%, порог '+str(limit)+'%.' if valid else 'не проверено.'))
    dns = data.get('dns',{})
    summaries = {'system_local':'DNS системы: требуется собственный локальный resolver.',
        'recursive':'Рекурсия Unbound без внешнего forwarder.', 'system_lookup':'Разрешение имени системным DNS.',
        'dnssec':'DNSSEC: подпись, неверная подпись и UDP/TCP.', 'own_exit':'DNS-рекурсор: выход с IP своей ноды.'}
    for key,summary in summaries.items():flag('dns_'+key,dns.get(key),summary)
    udp = data.get('hysteria_udp',{})
    path = udp.get('path')
    socks=udp.get('socks_udp')
    flag('hysteria_udp_path',True if path == 'direct' else False if path == 'reject' or
         (path == 'socks5' and isinstance(socks,dict) and socks.get('status')=='unsupported') else None,
         'Hysteria: внутренний UDP '+('идёт напрямую с VPS.' if path=='direct' else 'требует проверки маршрута; это не тест клиентской авторизации.'))
    flag('public_tls',ingress,'Публичный TCP/443 и доверенный TLS из сети Польши; не сквозная VPN-авторизация.')
    return result


def sample(node, deadline=None):
    if deadline is None:deadline=time.monotonic()+65
    remaining=deadline-time.monotonic()
    if remaining<10:
        return [{'node':node['name'],'check':check,'status':'unknown','summary':'Лимит времени цикла; проверка не выполнена.'} for check in CHECKS]
    try:envelope = snapshot(node,timeout=min(52,remaining-8))
    except Exception:envelope = {'ok':False}
    remaining=deadline-time.monotonic()
    ingress = public_tls(node['domain'],timeout=min(8,remaining)) if remaining>=1 else None
    try:return observations(node,envelope,ingress)
    except Exception:return observations(node,{'ok':False},ingress)


def notify(event):
    title = 'Авария' if event['kind']=='open' else 'Восстановление'
    message = '<b>'+title+' Yurich Connect</b>\n<code>'+html.escape(event['node']+'/'+event['check'])+'</code>'
    message += '\n'+html.escape(str(event['summary']))
    message += '\n<code>'+event['incident_id']+'</code>\nПодробности: /incidents'
    command = r'''source "$1"; load_config || exit 1
[[ -n "${TG_TOKEN:-}" && -n "${TG_CHAT_ID:-}" ]] || exit 1
message=$(cat)
response=$(tg_api sendMessage -s --max-time 10 -X POST --data-urlencode "chat_id=$TG_CHAT_ID" --data-urlencode parse_mode=HTML --data-urlencode "text=$message" 2>/dev/null) || exit 1
printf '%s\0%s\0' "$TG_CHAT_ID" "$response"
'''
    output=process(['bash','-c',command,'--',CORE],data=message,timeout=20).split('\0')
    if len(output)!=3 or not re.fullmatch(r'-?[0-9]{5,20}',output[0]):raise RuntimeError('invalid_telegram_response')
    reply=json.loads(output[1])
    value=reply.get('result')
    if (reply.get('ok') is not True or not isinstance(value,dict) or type(value.get('message_id')) is not int
            or value['message_id']<1 or not isinstance(value.get('chat'),dict)
            or type(value['chat'].get('id')) is not int or value['chat']['id']!=int(output[0])):
        raise RuntimeError('telegram_delivery_not_confirmed')


def save_state(path, data):
    if path.is_symlink():raise RuntimeError('unsafe_monitor_state')
    descriptor, temporary = tempfile.mkstemp(prefix='.monitor.',dir=path.parent)
    try:
        os.fchmod(descriptor,0o600)
        with os.fdopen(descriptor,'w') as stream:json.dump(data,stream,ensure_ascii=True)
        os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def run_monitor(state, no_notify=False):
    import fcntl
    incident_api('list',state)
    descriptor = os.open(state/'monitor.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return {'ok':True,'skipped':'already_running'}
        nodes = registry()
        observations_all = []
        probe_deadline=time.monotonic()+150
        cycle_deadline=time.monotonic()+190
        with ThreadPoolExecutor(max_workers=3) as executor:
            for rows in executor.map(lambda node:sample(node,probe_deadline),nodes):observations_all.extend(rows)
        stamp = time.time()
        transitions=0
        for offset in range(0,len(observations_all),256):
            result=incident_api('ingest',state,payload={'observed_at':stamp,'observations':observations_all[offset:offset+256]})
            transitions+=len(result['transitions'])
        delivered = 0
        if not no_notify:
            for event in incident_api('pending',state,'--limit','5')['events']:
                if cycle_deadline-time.monotonic()<25:break
                try:notify(event)
                except (RuntimeError,OSError,ValueError):break
                incident_api('delivered',state,'--event-id',event['event_id'])
                delivered += 1
        summary = {'ok':True,'observed_at':stamp,'nodes':[node['name'] for node in nodes],
            'checks':dict(Counter(row['status'] for row in observations_all)),
            'transitions':transitions,'notifications_delivered':delivered,
            'scope':'server-and-primary-network-not-client-vpn-test','auto_repairs':False}
        save_state(state/'last-run.json',summary)
        return summary
    finally:os.close(descriptor)


def status(state):
    path = state/'last-run.json'
    if not path.is_file() or path.is_symlink():
        return {'message':'<b>Мониторинг</b>\nПервый цикл ещё не завершён. Это не подтверждение исправности серверов.'}
    if path.stat().st_size>16384:raise RuntimeError('invalid_monitor_state')
    data = json.loads(path.read_text())
    stamp = data['observed_at']
    age = max(0,int(time.time()-stamp))
    lines = ['<b>Мониторинг</b>', 'Последний цикл: '+dt.datetime.fromtimestamp(stamp,dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'Данные '+('устарели' if age>600 else 'свежие')+'; возраст '+str(age)+' сек.',
        'Ноды: '+html.escape(', '.join(data['nodes'])),
        'OK: '+str(data['checks'].get('ok',0))+', проблемы: '+str(data['checks'].get('fail',0))+', не проверено: '+str(data['checks'].get('unknown',0)),
        'Серверные проверки и TLS из Польши. VPN-авторизация и сеть телефона этим не подтверждаются.',
        'Автоматические исправления выключены. Инциденты: /incidents']
    return {'message':'\n'.join(lines)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action',choices=('run','status','sample'))
    parser.add_argument('--state-dir',default=DEFAULT_STATE)
    parser.add_argument('--no-notify',action='store_true')
    options = parser.parse_args()
    state = Path(options.state_dir)
    if options.action=='status':result=status(state)
    elif options.action=='sample':
        rows=[]
        with ThreadPoolExecutor(max_workers=3) as executor:
            for value in executor.map(sample,registry()):rows.extend(value)
        result={'observed_at':time.time(),'observations':rows}
    else:result=run_monitor(state,options.no_notify)
    print(json.dumps(result,ensure_ascii=True,allow_nan=False))


if __name__=='__main__':
    try:main()
    except Exception:
        print(json.dumps({'ok':False,'error':'monitor_failed_without_server_changes'}))
        raise SystemExit(1)
