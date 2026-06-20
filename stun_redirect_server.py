#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""STUN穿透307重定向管理服务 - webhook接收+动态端口+管理后台+SQLite"""

import os, sys, json, sqlite3, hashlib, uuid, threading, re, hmac, datetime, glob, time
import http.client
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'stun_redirect.db')
ADMIN_PORT = int(os.environ.get('ADMIN_PORT', '8800'))
ROOT_DOMAIN = os.environ.get('ROOT_DOMAIN', '')
LOG_DIR = BASE_DIR
LOG_RETENTION_DAYS = 7

# ─── Logging ───────────────────────────────────────────────────────────────
def _log_file():
    return os.path.join(LOG_DIR, f'stun_redirect.{datetime.datetime.now():%Y-%m-%d}.log')

def log(level, module, msg, **data):
    entry = {'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'level': level, 'module': module, 'msg': msg}
    if data:
        for k, v in data.items():
            entry[k] = v
    line = json.dumps(entry, ensure_ascii=False)
    print(line, flush=True)
    try:
        with open(_log_file(), 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception as e:
        print(json.dumps({'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'level': 'ERROR', 'module': 'log', 'msg': f'write log failed', 'error': str(e)}, ensure_ascii=False), flush=True)

def cleanup_logs():
    now = datetime.datetime.now()
    deleted = 0
    for f in glob.glob(os.path.join(LOG_DIR, 'stun_redirect.*.log')):
        try:
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(f))
            if (now - mtime).days >= LOG_RETENTION_DAYS:
                os.remove(f)
                deleted += 1
        except Exception:
            pass
    if deleted:
        log('INFO', 'cleanup', f'cleaned {deleted} old log files')

def log_cleanup_loop():
    while True:
        time.sleep(3600)
        cleanup_logs()

# ─── Database ──────────────────────────────────────────────────────────────
import threading

_rules_cache = {}
_rules_cache_time = 0
_RULES_CACHE_DURATION = 3

def _cache_get(key, duration=1):
    t, v = _rules_cache.get(key, (0, None))
    if time.monotonic() - t < duration:
        return v
    return None

def _cache_set(key, value):
    _rules_cache[key] = (time.monotonic(), value)

def cache_invalidate():
    _rules_cache.clear()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def get_setting(key, default=''):
    cached = _cache_get(f'set_{key}')
    if cached is not None:
        return cached
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    val = row['value'] if row else default
    conn.close()
    _cache_set(f'set_{key}', val)
    return val

def set_setting(key, value):
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()
    cache_invalidate()

def get_rules_cache():
    cached = _cache_get('rules', _RULES_CACHE_DURATION)
    if cached is not None:
        return cached
    conn = get_db()
    rows = conn.execute("SELECT * FROM redirect_rules WHERE enabled=1").fetchall()
    rules = [dict(r) for r in rows]
    _cache_set('rules', rules)
    conn.close()
    return rules

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS redirect_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fuwuqiportxuhao TEXT UNIQUE NOT NULL,
            listen_port INTEGER UNIQUE NOT NULL,
            target_ip TEXT DEFAULT '',
            target_port INTEGER DEFAULT 0,
            host TEXT DEFAULT '',
            redirect_scheme TEXT DEFAULT 'http',
            redirect_method TEXT DEFAULT '308',
            cache_seconds INTEGER DEFAULT 300,
            created_by TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip TEXT NOT NULL,
            attempted_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
    ''')
    for col, dtype in (('host', "TEXT DEFAULT ''"), ('redirect_scheme', "TEXT DEFAULT 'http'"), ('redirect_method', "TEXT DEFAULT '308'"), ('cache_seconds', "INTEGER DEFAULT 300"), ('created_by', "TEXT DEFAULT ''"), ('domain_prefix', "TEXT DEFAULT ''"), ('domain_mappings', "TEXT DEFAULT ''"), ('proxy_mode', "INTEGER DEFAULT 0")):
        try:
            conn.execute("ALTER TABLE redirect_rules ADD COLUMN %s %s" % (col, dtype))
        except sqlite3.OperationalError:
            pass
    try:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    except sqlite3.OperationalError:
        pass
    cur = conn.execute("SELECT id FROM users WHERE username='admin'")
    if cur.fetchone():
        conn.execute("UPDATE users SET role='admin' WHERE username='admin'")
    else:
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                     ('admin', hash_password('admin123'), 'admin'))
        log('INFO', 'db', 'default admin user created')
    defaults = {'root_domain': 'stun.sd8.cc', 'admin_port': '8800', 'max_rules_per_user': '3'}
    for k, v in defaults.items():
        if not conn.execute("SELECT 1 FROM settings WHERE key=?", (k,)).fetchone():
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (k, v))
    conn.execute("DELETE FROM tokens WHERE created_at < datetime('now', '-7 days', 'localtime')")
    conn.commit()
    conn.close()

# ─── Auth ──────────────────────────────────────────────────────────────────
def hash_password(password):
    salt = os.urandom(16).hex()
    return salt + ':' + hashlib.sha256((salt + password).encode()).hexdigest()

def check_password(password, hash_str):
    salt, h = hash_str.split(':', 1)
    return hmac.compare_digest(hashlib.sha256((salt + password).encode()).hexdigest(), h)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

def check_login_allowed(username, ip):
    conn = get_db()
    cutoff = (datetime.datetime.now() - datetime.timedelta(minutes=LOCKOUT_MINUTES)).strftime('%Y-%m-%d %H:%M:%S')
    conn.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,))
    count = conn.execute("SELECT COUNT(*) FROM login_attempts WHERE username=? AND ip=? AND attempted_at>=?",
                         (username, ip, cutoff)).fetchone()[0]
    conn.close()
    return count < MAX_LOGIN_ATTEMPTS

def record_login_attempt(username, ip):
    conn = get_db()
    conn.execute("INSERT INTO login_attempts (username, ip) VALUES (?, ?)", (username, ip))
    conn.commit()
    conn.close()

def clear_login_attempts(username, ip):
    conn = get_db()
    conn.execute("DELETE FROM login_attempts WHERE username=? AND ip=?", (username, ip))
    conn.commit()
    conn.close()

_tokens = {}
def generate_token(username, role):
    token = uuid.uuid4().hex
    _tokens[token] = {'username': username, 'role': role}
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO tokens (token, username, role) VALUES (?, ?, ?)", (token, username, role))
    conn.commit()
    conn.close()
    return token

def get_current_user(headers):
    auth = headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        info = _tokens.get(auth[7:])
        if info:
            return info
        conn = get_db()
        row = conn.execute("SELECT username, role FROM tokens WHERE token=?", (auth[7:],)).fetchone()
        conn.close()
        if row:
            _tokens[auth[7:]] = {'username': row['username'], 'role': row['role']}
            return _tokens[auth[7:]]
    return None

def get_current_user(headers):
    auth = headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return _tokens.get(auth[7:])
    return None

# ─── Redirect Server Manager ──────────────────────────────────────────────
class RedirectTarget:
    __slots__ = ('ip', 'port', 'host', 'scheme', 'method', 'cache_seconds', 'domain_prefix')
    def __init__(self, ip='', port=0, host='', scheme='http', method='307', cache_seconds=300, domain_prefix=''):
        self.ip = ip
        self.port = port
        self.host = host
        self.scheme = scheme
        self.method = method
        self.cache_seconds = cache_seconds
        self.domain_prefix = domain_prefix

def parse_domain(hostname, root_domain):
    """解析域名前缀和端口: sp.50001.stun.sd8.cc -> (sp, 50001)"""
    suffix = '.' + root_domain if root_domain else ''
    if not suffix or not hostname.endswith(suffix):
        return None, None
    body = hostname[:-len(suffix)]
    parts = body.split('.')
    if len(parts) < 2:
        return None, None
    port_s = parts[-1]
    prefix = '.'.join(parts[:-1])
    try:
        port = int(port_s)
    except ValueError:
        return None, None
    return prefix, port

def _normalize_domain(entry):
    entry = entry.strip()
    for p in ('https://', 'http://'):
        if entry.startswith(p):
            entry = entry[len(p):]
    ci = entry.find(':')
    if ci > 0:
        entry = entry[:ci]
    if entry.endswith('/'):
        entry = entry[:-1]
    return entry

def _parse_domain_mapping(line):
    """解析域名映射行，返回 (prefix, target_host)
    支持格式:
      "prefix domain"         → (prefix, domain)
      "http://domain:port/"   → (first_subdomain, domain)  # 端口忽略，用规则的target_port
      "domain"                → (first_subdomain, domain)
      "prefix http://domain:port/" → (prefix, domain)
    """
    line = line.strip()
    if not line:
        return None
    for p in ('https://', 'http://'):
        if line.startswith(p):
            line = line[len(p):]
            break
    if line.endswith('/'):
        line = line[:-1]
    ci = line.find(':')
    if ci > 0:
        line = line[:ci]
    parts = line.split(None, 1)
    if len(parts) == 2:
        return (parts[0], parts[1])
    elif len(parts) == 1:
        domain = parts[0]
        dot = domain.find('.')
        if dot > 0:
            return (domain[:dot], domain)
        return (domain, None)
    return None

_redirect_servers = {}

class RedirectHandler(BaseHTTPRequestHandler):
    target = None
    def _r(self):
        t = self.target
        client_ip = self.client_address[0]
        if t and ((t.host and t.port) or (t.ip and t.port)):
            if t.host:
                h = t.host
                if '*' in h:
                    host_raw = self.headers.get('Host', '')
                    hostname = host_raw.split(':')[0].lower() if ':' in host_raw else host_raw.lower()
                    root_domain = get_setting('root_domain', '')
                    prefix, _ = parse_domain(hostname, root_domain)
                    if not prefix:
                        prefix = t.domain_prefix or ''
                    if prefix:
                        h = h.replace('*', prefix)
                dest = f'{t.scheme}://{h}:{t.port}{self.path}'
            else:
                dest = f'http://{t.ip}:{t.port}{self.path}'
            code = 308 if t.method == '308' else 307
            self.send_response(code)
            self.send_header('Location', dest)
            if code == 308:
                self.send_header('Cache-Control', 'no-store, max-age=0')
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()
            log('INFO', 'redirect', f'307 {self.command} {self.path} -> {dest}',
                client=client_ip, method=self.command, path=self.path,
                target_ip=t.ip, target_port=t.port, dest=dest, status=307)
        else:
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write('\u76ee\u6807\u672a\u914d\u7f6e'.encode())
            log('WARN', 'redirect', f'502 {self.command} {self.path} target not configured',
                client=client_ip, method=self.command, path=self.path, status=502)
    def log_message(self, fmt, *args):
        pass
    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _r

def start_redirect_server(port, ip='', port_num=0, host='', scheme='http', method='307', cache_seconds=300, proxy_mode=0, domain_prefix=''):
    if proxy_mode:
        return True
    if port in _redirect_servers:
        return True
    try:
        target = RedirectTarget(ip, port_num, host, scheme, method, cache_seconds, domain_prefix)
        handler = type('_RedirectHandler', (RedirectHandler,), {'target': target})
        srv = HTTPServer(('0.0.0.0', port), handler)
        srv.daemon = True
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        _redirect_servers[port] = {'server': srv, 'target': target, 'thread': t}
        log('INFO', 'redirect_mgr', f'started on :{port}', listen_port=port, target_ip=ip or '-', target_port=port_num or '-')
        return True
    except OSError as e:
        log('ERROR', 'redirect_mgr', f'failed to start on :{port}', listen_port=port, error=str(e))
        return False

def stop_redirect_server(port):
    info = _redirect_servers.pop(port, None)
    if info:
        info['server'].shutdown()
        log('INFO', 'redirect_mgr', f'stopped on :{port}', listen_port=port)
        return True
    return False

def update_redirect_target(port, ip, port_num, host='', scheme='http', method='307', cache_seconds=300):
    info = _redirect_servers.get(port)
    if info:
        old_ip, old_port = info['target'].ip, info['target'].port
        info['target'].ip = ip
        info['target'].port = port_num
        info['target'].host = host
        info['target'].scheme = scheme
        info['target'].method = method
        info['target'].cache_seconds = cache_seconds
        log('INFO', 'redirect_mgr', f'updated :{port} target {old_ip}:{old_port} -> {ip}:{port_num}',
            listen_port=port, old_target=f'{old_ip}:{old_port}', new_target=f'{ip}:{port_num}')
        return True
    return False

def load_all_rules():
    conn = get_db()
    rows = conn.execute("SELECT * FROM redirect_rules WHERE enabled=1").fetchall()
    conn.close()
    loaded = 0
    for r in rows:
        if start_redirect_server(r['listen_port'], r['target_ip'], r['target_port'], r['host'] or '', r['redirect_scheme'] or 'http', r['redirect_method'] or '308', r['cache_seconds'] or 300, proxy_mode=r['proxy_mode'], domain_prefix=r['domain_prefix'] or ''):
            loaded += 1
    log('INFO', 'redirect_mgr', f'loaded {loaded} redirect rules from db')
    sync_nginx_routes()

def sync_nginx_routes():
    cache_invalidate()
    conn = get_db()
    rows = conn.execute("SELECT * FROM redirect_rules WHERE enabled=1 AND proxy_mode=1").fetchall()
    conn.close()
    root_domain = get_setting('root_domain', '')
    entries = []
    for r in rows:
        prefix = r['domain_prefix'] or ''
        if not prefix:
            continue
        hostname = f'{prefix}.{r["listen_port"]}.{root_domain}' if root_domain else ''
        if not hostname:
            continue
        scheme = r['redirect_scheme'] or 'http'
        is_https = scheme == 'https'
        # Build backend URL: use target_ip if available (avoids DNS issues)
        target_ip = r['target_ip'] or ''
        target_port = r['target_port'] or 0
        backend = ''
        if target_ip:
            backend = f'{scheme}://{target_ip}:{target_port}'
        else:
            # Fallback: use domain mapping hostname
            mappings = (r['domain_mappings'] or '').strip()
            if mappings:
                for line in mappings.split('\n'):
                    parsed = _parse_domain_mapping(line)
                    if not parsed:
                        continue
                    mp, mh = parsed
                    if mp == prefix and mh:
                        backend = f'{scheme}://{mh}:{target_port}'
                        break
            if not backend and r['host']:
                backend = f'{scheme}://{r["host"].replace("*", prefix)}:{target_port}'
        if not backend:
            continue
        ssl_opts = ''
        if is_https:
            ssl_opts = '''        proxy_ssl_verify off;
        proxy_ssl_server_name off;'''
        entries.append(f'''server {{
    listen 80;
    server_name {hostname};
    location / {{
        proxy_pass {backend};
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
{ssl_opts}
    }}
}}''')
    conf_path = '/www/server/panel/vhost/nginx/stun.direct.conf'
    content = '# Auto-generated by stun_redirect_server.py\n\n'
    if entries:
        content += '\n\n'.join(entries) + '\n'
    try:
        with open(conf_path, 'w') as f:
            f.write(content)
        os.system('nginx -s reload')
        log('INFO', 'nginx_sync', f'routes synced ({len(entries)} entries)')
    except Exception as e:
        log('ERROR', 'nginx_sync', f'failed: {e}')

def find_free_port(preferred=0):
    conn = get_db()
    used = set(r[0] for r in conn.execute("SELECT listen_port FROM redirect_rules").fetchall())
    conn.close()
    if preferred and preferred not in used:
        return preferred
    for p in range(40000, 60001):
        if p not in used:
            return p
    return 0

# ─── Main Server ───────────────────────────────────────────────────────────
ADMIN_HTML = None

class MainHandler(BaseHTTPRequestHandler):
    def _json_body(self):
        try:
            length = int(self.headers.get('Content-Length', 0) or 0)
        except (ValueError, TypeError):
            length = 0
        if length:
            try: return json.loads(self.rfile.read(length).decode())
            except Exception:
                pass
        return {}

    def _send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        user = get_auth_user(self.headers)
        if not user:
            self._send_json(401, {'error': '\u767b\u5f55\u72b6\u6001\u5df2\u8fc7\u671f'})
            log('WARN', 'api', 'unauthorized access',
                client=self.client_address[0], path=self.path, method=self.command)
        return user

    def _log_api(self, action, username=None, **extra):
        data = {'client': self.client_address[0], 'method': self.command, 'path': self.path, 'action': action}
        if username:
            data['user'] = username
        if extra:
            data.update(extra)
        log('INFO', 'api', f'{action} by {username or "anonymous"}', **data)

    def _domain_proxy(self, dest_host, dest_port, scheme):
        method = self.command
        path = self.path
        body = None
        length = self.headers.get('Content-Length')
        if length:
            try:
                body = self.rfile.read(int(length))
            except Exception:
                pass
        try:
            if scheme == 'https':
                conn = http.client.HTTPSConnection(dest_host, dest_port, timeout=30)
            else:
                conn = http.client.HTTPConnection(dest_host, dest_port, timeout=30)
            conn.connect()
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for k, v in self.headers.items():
                if k.lower() not in ('connection', 'transfer-encoding', 'content-length'):
                    conn.putheader(k, v)
            if body is not None:
                conn.putheader('Content-Length', str(len(body)))
            conn.endheaders(body)
            resp = conn.getresponse()
            self.send_response(resp.status)
            skip = {'transfer-encoding', 'connection'}
            for k, v in resp.getheaders():
                if k.lower() not in skip:
                    self.send_header(k, v)
            self.end_headers()
            chunk = resp.read(65536)
            while chunk:
                self.wfile.write(chunk)
                chunk = resp.read(65536)
            conn.close()
        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f'Proxy error: {e}'.encode())
        return True

    def _domain_redirect(self):
        root_domain = get_setting('root_domain', '')
        host_raw = self.headers.get('Host', '')
        hostname = host_raw.split(':')[0].lower() if ':' in host_raw else host_raw.lower()
        prefix, port = parse_domain(hostname, root_domain)
        log('DEBUG', 'domain_redirect', 'check', root_domain=root_domain, host_raw=host_raw, hostname=hostname, prefix=prefix, port=port)
        if not root_domain:
            return False
        if prefix is None or port is None:
            return False
        rules = get_rules_cache()
        row = None
        for r in rules:
            if r['listen_port'] == port:
                row = r
                break
        if not row:
            return False
        host_tpl = row['host'] or ''
        target_port = row['target_port']
        scheme = row['redirect_scheme'] or 'http'
        dest_host = ''
        mapping_matched = False
        mappings = row['domain_mappings'] or ''
        if mappings:
            for line in mappings.split('\n'):
                parsed = _parse_domain_mapping(line)
                if not parsed:
                    continue
                mp, mh = parsed
                if mp == prefix and mh:
                    dest_host = mh
                    mapping_matched = True
                    break
        if not dest_host and host_tpl:
            dest_host = host_tpl.replace('*', prefix)
        if dest_host:
            dest = f'{scheme}://{dest_host}:{target_port}{self.path}'
        elif row['target_ip']:
            dest = f'http://{row["target_ip"]}:{target_port}{self.path}'
        else:
            return False
        if row['proxy_mode']:
            return self._domain_proxy(dest_host or row['target_ip'], target_port, scheme)
        log('INFO', 'domain_redirect', f'domain redirect', src_host=hostname, dest=dest)
        method = row['redirect_method'] or '308'
        cache_seconds = row['cache_seconds'] or 300
        code = 308 if method == '308' else 307
        self.send_response(code)
        self.send_header('Location', dest)
        if code == 308:
            self.send_header('Cache-Control', 'no-store, max-age=0')
        self.send_header('Content-Length', '0')
        self.end_headers()
        return True

    def _api_login(self, data):
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''
        ip = self.client_address[0]
        if not username or not password:
            self._log_api('login_failed', error='empty_fields')
            return self._send_json(400, {'error': '\u7528\u6237\u540d\u548c\u5bc6\u7801\u4e0d\u80fd\u4e3a\u7a7a'})
        if not check_login_allowed(username, ip):
            self._log_api('login_blocked', username=username, error='rate_limited')
            return self._send_json(429, {'error': f'\u767b\u5f55\u5931\u8d25\u6b21\u6570\u8fc7\u591a\uff0c\u8bf7 {LOCKOUT_MINUTES} \u5206\u949f\u540e\u91cd\u8bd5'})
        conn = get_db()
        cur = conn.execute("SELECT password_hash, role FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        conn.close()
        if row and check_password(password, row['password_hash']):
            clear_login_attempts(username, ip)
            role = row['role'] or 'user'
            token = generate_token(username, role)
            self._log_api('login', username=username)
            return self._send_json(200, {'token': token, 'username': username, 'role': role})
        record_login_attempt(username, ip)
        self._log_api('login_failed', username=username, error='wrong_password')
        self._send_json(403, {'error': '\u7528\u6237\u540d\u6216\u5bc6\u7801\u9519\u8bef'})

    def _api_register(self, data):
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''
        if not username or not password:
            self._log_api('register_failed', error='empty_fields')
            return self._send_json(400, {'error': '\u7528\u6237\u540d\u548c\u5bc6\u7801\u4e0d\u80fd\u4e3a\u7a7a'})
        if len(username) < 3 or len(password) < 6:
            self._log_api('register_failed', username=username, error='too_short')
            return self._send_json(400, {'error': '\u7528\u6237\u540d\u81f3\u5c113\u4f4d\uff0c\u5bc6\u7801\u81f3\u5c116\u4f4d'})
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                         (username, hash_password(password)))
            conn.commit()
            self._log_api('register', username=username)
            self._send_json(200, {'message': '\u6ce8\u518c\u6210\u529f'})
        except sqlite3.IntegrityError:
            self._log_api('register_failed', username=username, error='duplicate')
            self._send_json(409, {'error': '\u7528\u6237\u540d\u5df2\u5b58\u5728'})
        finally:
            conn.close()

    def _api_change_password(self, data):
        user_info = get_current_user(self.headers)
        if not user_info:
            return self._send_json(401, {'error': '\u767b\u5f55\u72b6\u6001\u5df2\u8fc7\u671f'})
        username = user_info['username']
        old = data.get('old_password', '')
        new = data.get('new_password', '')
        if not old or not new:
            return self._send_json(400, {'error': '\u8bf7\u586b\u5199\u5f53\u524d\u5bc6\u7801\u548c\u65b0\u5bc6\u7801'})
        if len(new) < 6:
            return self._send_json(400, {'error': '\u65b0\u5bc6\u7801\u81f3\u5c116\u4f4d'})
        conn = get_db()
        cur = conn.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return self._send_json(404, {'error': '\u7528\u6237\u4e0d\u5b58\u5728'})
        if not check_password(old, row['password_hash']):
            conn.close()
            self._log_api('change_password_failed', username=username, error='wrong_password')
            return self._send_json(403, {'error': '\u5f53\u524d\u5bc6\u7801\u9519\u8bef'})
        conn.execute("UPDATE users SET password_hash=? WHERE username=?", (hash_password(new), username))
        conn.commit()
        conn.close()
        self._log_api('change_password', username=username)
        self._send_json(200, {'message': '\u5bc6\u7801\u4fee\u6539\u6210\u529f'})

    def _api_list_rules(self):
        user_info = get_current_user(self.headers)
        if not user_info:
            return self._send_json(401, {'error': '\u767b\u5f55\u72b6\u6001\u5df2\u8fc7\u671f'})
        conn = get_db()
        if user_info['role'] == 'admin':
            rows = conn.execute("SELECT * FROM redirect_rules ORDER BY id").fetchall()
        else:
            rows = conn.execute("SELECT * FROM redirect_rules WHERE created_by=? ORDER BY id", (user_info['username'],)).fetchall()
        conn.close()
        rules = [dict(r) for r in rows]
        self._log_api('list_rules', username=user_info['username'], count=len(rules))
        self._send_json(200, rules)

    def _api_create_rule(self, data):
        user_info = get_current_user(self.headers)
        if not user_info:
            return self._send_json(401, {'error': '\u767b\u5f55\u72b6\u6001\u5df2\u8fc7\u671f'})
        user = user_info['username']
        role = user_info['role']
        fuwuqiportxuhao = (data.get('fuwuqiportxuhao') or '').strip()
        listen_port = data.get('listen_port')
        if not fuwuqiportxuhao or not listen_port:
            self._log_api('create_rule_failed', username=user, error='missing_fields')
            return self._send_json(400, {'error': '\u7f3a\u5c11\u5fc5\u586b\u5b57\u6bb5'})
        listen_port = int(listen_port)
        if listen_port < 40000 or listen_port > 60000:
            self._log_api('create_rule_failed', username=user, error='invalid_port_range')
            return self._send_json(400, {'error': '\u7aef\u53e3\u8303\u56f4\u9650\u523640000-60000'})
        if role != 'admin':
            max_rules = int(get_setting('max_rules_per_user', '3'))
            conn = get_db()
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM redirect_rules WHERE created_by=?", (user,))
            row = cur.fetchone()
            conn.close()
            if row['cnt'] >= max_rules:
                self._log_api('create_rule_failed', username=user, error='rule_limit_exceeded', count=row['cnt'])
                return self._send_json(403, {'error': f'非管理员用户最多只能新增 {max_rules} 条规则'})
        conn = get_db()
        cur = conn.execute("SELECT id, created_by, listen_port, target_ip, target_port, host, redirect_scheme, redirect_method, cache_seconds FROM redirect_rules WHERE listen_port=?", (listen_port,))
        existing = cur.fetchone()
        if existing:
            if existing['created_by'] == user or role == 'admin':
                conn.execute("UPDATE redirect_rules SET target_ip=?, target_port=?, host=?, redirect_scheme=?, redirect_method=?, cache_seconds=?, updated_at=datetime('now','localtime') WHERE id=?",
                             (data.get('target_ip', ''), data.get('target_port', 0), data.get('host', ''), data.get('redirect_scheme', 'http'), data.get('redirect_method', '308'), int(data.get('cache_seconds', 300)), existing['id']))
                conn.commit()
                conn.close()
                start_redirect_server(existing['listen_port'],
                    host=data.get('host', existing['host'] or ''),
                    scheme=data.get('redirect_scheme', existing['redirect_scheme'] or 'http'),
                    method=data.get('redirect_method', existing['redirect_method'] or '308'),
                    cache_seconds=int(data.get('cache_seconds', existing['cache_seconds'] or 300)),
                    proxy_mode=data.get('proxy_mode', existing['proxy_mode'] or 0),
                    domain_prefix=existing['domain_prefix'] or '')
                self._log_api('create_rule_same_user_update', username=user, rule_id=existing['id'], listen_port=listen_port)
                sync_nginx_routes()
                self._send_json(200, {'message': '\u540c\u7528\u6237\u7aef\u53e3\u5df2\u66f4\u65b0\u539f\u89c4\u5219', 'id': existing['id']})
                return
            conn.close()
            free_p = find_free_port()
            hint = f'\uff0c\u63a8\u8350\u4f7f\u7528 {free_p}' if free_p else ''
            self._log_api('create_rule_failed', username=user, error='port_conflict', listen_port=listen_port)
            return self._send_json(409, {'error': f'\u76d1\u542c\u7aef\u53e3 {listen_port} \u5df2\u88ab\u5360\u7528{hint}'})
        try:
            conn.execute("INSERT INTO redirect_rules (fuwuqiportxuhao, listen_port, created_by) VALUES (?,?,?)",
                         (fuwuqiportxuhao, listen_port, user))
            conn.commit()
            rule_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            extra_fields = []
            extra_vals = []
            if data.get('target_ip'):
                extra_fields.append("target_ip=?")
                extra_vals.append(data['target_ip'])
            if data.get('target_port'):
                extra_fields.append("target_port=?")
                extra_vals.append(int(data['target_port']))
            if data.get('host'):
                extra_fields.append("host=?")
                extra_vals.append(data['host'])
            if data.get('domain_prefix'):
                extra_fields.append("domain_prefix=?")
                extra_vals.append(data['domain_prefix'])
            if 'domain_mappings' in data:
                extra_fields.append("domain_mappings=?")
                extra_vals.append(data['domain_mappings'])
            if data.get('redirect_scheme') in ('http', 'https'):
                extra_fields.append("redirect_scheme=?")
                extra_vals.append(data['redirect_scheme'])
            if data.get('redirect_method') in ('307', '308'):
                extra_fields.append("redirect_method=?")
                extra_vals.append(data['redirect_method'])
            if data.get('cache_seconds'):
                try:
                    cv = int(data['cache_seconds'])
                    if 60 <= cv <= 360000:
                        extra_fields.append("cache_seconds=?")
                        extra_vals.append(cv)
                except (ValueError, TypeError):
                    pass
            if 'proxy_mode' in data:
                if user['role'] != 'admin':
                    self._send_json(403, {'error': '仅管理员可设置反向代理模式'})
                    return
                extra_fields.append("proxy_mode=?")
                extra_vals.append(1 if data['proxy_mode'] else 0)
            if extra_fields:
                extra_vals.append(rule_id)
                conn.execute(f"UPDATE redirect_rules SET {','.join(extra_fields)} WHERE id=?", extra_vals)
                conn.commit()
            if data.get('enabled', 1):
                start_redirect_server(listen_port, host=data.get('host', ''), scheme=data.get('redirect_scheme', 'http'), method=data.get('redirect_method', '308'), cache_seconds=int(data.get('cache_seconds', 300)), proxy_mode=data.get('proxy_mode', 0), domain_prefix=data.get('domain_prefix', ''))
            self._log_api('create_rule', username=user, rule_id=rule_id, fuwuqiportxuhao=fuwuqiportxuhao, listen_port=listen_port)
            sync_nginx_routes()
            self._send_json(200, {'message': '\u521b\u5efa\u6210\u529f', 'id': rule_id})
        except sqlite3.IntegrityError:
            self._log_api('create_rule_failed', username=user, error='duplicate', fuwuqiportxuhao=fuwuqiportxuhao, listen_port=listen_port)
            self._send_json(409, {'error': '\u670d\u52a1\u7aef\u53e3\u5e8f\u53f7\u5df2\u5b58\u5728'})
        finally:
            conn.close()

    def _api_update_rule(self, rid, data):
        user_info = get_current_user(self.headers)
        if not user_info:
            return self._send_json(401, {'error': '\u767b\u5f55\u72b6\u6001\u5df2\u8fc7\u671f'})
        user, role = user_info['username'], user_info['role']
        conn = get_db()
        cur = conn.execute("SELECT * FROM redirect_rules WHERE id=?", (rid,))
        row = cur.fetchone()
        if not row:
            conn.close()
            self._log_api('update_rule_failed', username=user, rule_id=rid, error='not_found')
            return self._send_json(404, {'error': '\u89c4\u5219\u4e0d\u5b58\u5728'})
        if role != 'admin' and row['created_by'] != user:
            conn.close()
            self._log_api('update_rule_failed', username=user, rule_id=rid, error='forbidden')
            return self._send_json(403, {'error': '\u65e0\u6743\u9650\u64cd\u4f5c\u6b64\u89c4\u5219'})
        fields = []
        vals = []
        if 'fuwuqiportxuhao' in data:
            fields.append('fuwuqiportxuhao=?')
            vals.append(str(data['fuwuqiportxuhao']))
        if 'listen_port' in data:
            fields.append('listen_port=?')
            vals.append(int(data['listen_port']))
        if 'host' in data:
            fields.append('host=?')
            vals.append(str(data['host']))
        if 'domain_prefix' in data:
            fields.append('domain_prefix=?')
            vals.append(str(data['domain_prefix']))
        if 'domain_mappings' in data:
            fields.append('domain_mappings=?')
            vals.append(data['domain_mappings'])
        if 'redirect_scheme' in data:
            fields.append('redirect_scheme=?')
            vals.append(str(data['redirect_scheme']))
        if 'redirect_method' in data:
            fields.append('redirect_method=?')
            vals.append(str(data['redirect_method']))
        if 'cache_seconds' in data:
            fields.append('cache_seconds=?')
            vals.append(int(data['cache_seconds']))
        if 'enabled' in data:
            fields.append('enabled=?')
            vals.append(1 if data['enabled'] else 0)
        if 'proxy_mode' in data:
            if role != 'admin':
                self._send_json(403, {'error': '仅管理员可设置反向代理模式'})
                return
            fields.append('proxy_mode=?')
            vals.append(1 if data['proxy_mode'] else 0)
        if fields:
            fields.append("updated_at=datetime('now','localtime')")
            vals.append(rid)
            conn.execute(f"UPDATE redirect_rules SET {','.join(fields)} WHERE id=?", vals)
            conn.commit()
        conn.close()
        if 'enabled' in data:
            if data['enabled']:
                start_redirect_server(row['listen_port'], row['target_ip'], row['target_port'], row['host'] or '', row['redirect_scheme'] or 'http', row['redirect_method'] or '308', row['cache_seconds'] or 300, proxy_mode=row['proxy_mode'], domain_prefix=row['domain_prefix'] or '')
            else:
                stop_redirect_server(row['listen_port'])
        self._log_api('update_rule', username=user, rule_id=rid, changes={k: data[k] for k in ('fuwuqiportxuhao', 'listen_port', 'host', 'redirect_scheme', 'redirect_method', 'cache_seconds', 'enabled', 'proxy_mode') if k in data})
        sync_nginx_routes()
        self._send_json(200, {'message': '\u66f4\u65b0\u6210\u529f'})

    def _api_delete_rule(self, rid):
        user_info = get_current_user(self.headers)
        if not user_info:
            return self._send_json(401, {'error': '\u767b\u5f55\u72b6\u6001\u5df2\u8fc7\u671f'})
        user, role = user_info['username'], user_info['role']
        conn = get_db()
        cur = conn.execute("SELECT listen_port, fuwuqiportxuhao, created_by FROM redirect_rules WHERE id=?", (rid,))
        row = cur.fetchone()
        if not row:
            conn.close()
            self._log_api('delete_rule_failed', username=user, rule_id=rid, error='not_found')
            return self._send_json(404, {'error': '\u89c4\u5219\u4e0d\u5b58\u5728'})
        if role != 'admin' and row['created_by'] != user:
            conn.close()
            self._log_api('delete_rule_failed', username=user, rule_id=rid, error='forbidden')
            return self._send_json(403, {'error': '\u65e0\u6743\u9650\u64cd\u4f5c\u6b64\u89c4\u5219'})
        stop_redirect_server(row['listen_port'])
        conn.execute("DELETE FROM redirect_rules WHERE id=?", (rid,))
        conn.commit()
        conn.close()
        self._log_api('delete_rule', username=user, rule_id=rid, fuwuqiportxuhao=row['fuwuqiportxuhao'], listen_port=row['listen_port'])
        sync_nginx_routes()
        self._send_json(200, {'message': '\u5220\u9664\u6210\u529f'})

    def _api_toggle_rule(self, rid):
        user_info = get_current_user(self.headers)
        if not user_info:
            return self._send_json(401, {'error': '\u767b\u5f55\u72b6\u6001\u5df2\u8fc7\u671f'})
        user, role = user_info['username'], user_info['role']
        conn = get_db()
        cur = conn.execute("SELECT * FROM redirect_rules WHERE id=?", (rid,))
        row = cur.fetchone()
        if not row:
            conn.close()
            self._log_api('toggle_rule_failed', username=user, rule_id=rid, error='not_found')
            return self._send_json(404, {'error': '\u89c4\u5219\u4e0d\u5b58\u5728'})
        if role != 'admin' and row['created_by'] != user:
            conn.close()
            self._log_api('toggle_rule_failed', username=user, rule_id=rid, error='forbidden')
            return self._send_json(403, {'error': '\u65e0\u6743\u9650\u64cd\u4f5c\u6b64\u89c4\u5219'})
        new_enabled = 0 if row['enabled'] else 1
        conn.execute("UPDATE redirect_rules SET enabled=?, updated_at=datetime('now','localtime') WHERE id=?", (new_enabled, rid))
        conn.commit()
        conn.close()
        if new_enabled:
            start_redirect_server(row['listen_port'], row['target_ip'], row['target_port'], row['host'] or '', row['redirect_scheme'] or 'http', row['redirect_method'] or '308', row['cache_seconds'] or 300, proxy_mode=row['proxy_mode'], domain_prefix=row['domain_prefix'] or '')
        else:
            stop_redirect_server(row['listen_port'])
        self._log_api('toggle_rule', username=user, rule_id=rid, enabled=bool(new_enabled), fuwuqiportxuhao=row['fuwuqiportxuhao'])
        sync_nginx_routes()
        self._send_json(200, {'enabled': new_enabled, 'message': '\u5f00\u542f' if new_enabled else '\u5173\u95ed'})

    def _api_webhook(self, data):
        def s(v):
            return str(v).strip() if v is not None else ''
        ip = s(data.get('ip'))
        port_str = s(data.get('port'))
        fuwuqiportxuhao = s(data.get('fuwuqiportxuhao'))
        fuwuqiport = s(data.get('fuwuqiport') or data.get('listen_port') or '')
        webhook_user = s(data.get('user'))
        webhook_pass = s(data.get('userpassword'))
        host = s(data.get('host'))
        redirect_scheme = s(data.get('redirect_scheme'))
        redirect_method = s(data.get('redirect_method'))
        cache_seconds_s = s(data.get('cache_seconds'))
        client = self.client_address[0]

        if not all([ip, port_str]):
            log('WARN', 'webhook', 'missing parameters',
                client=client, ip=ip, port=port_str, fuwuqiportxuhao=fuwuqiportxuhao)
            return self._send_json(400, {'error': '缺少必要参数 ip/port'})
        if not fuwuqiportxuhao:
            fuwuqiportxuhao = str(listen_port) if listen_port else str(port)

        port = int(port_str)
        listen_port = int(fuwuqiport) if fuwuqiport else 0
        if not webhook_user:
            webhook_user = 'admin1'

        conn = get_db()
        if webhook_pass:
            cur = conn.execute("SELECT password_hash FROM users WHERE username=?", (webhook_user,))
            rp = cur.fetchone()
            if not rp or not check_password(webhook_pass, rp['password_hash']):
                conn.close()
                log('WARN', 'webhook', 'auth failed', client=client, user=webhook_user)
                return self._send_json(403, {'error': '\u7528\u6237\u540d\u6216\u5bc6\u7801\u9519\u8bef'})
        else:
            cur = conn.execute("SELECT id FROM users WHERE username=?", (webhook_user,))
            if not cur.fetchone():
                try:
                    conn.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                                 (webhook_user, hash_password('123456')))
                    conn.commit()
                    log('INFO', 'webhook', f'auto-registered user {webhook_user}',
                        client=client, user=webhook_user)
                except sqlite3.IntegrityError:
                    pass

        cur = conn.execute("SELECT * FROM redirect_rules WHERE fuwuqiportxuhao=?", (fuwuqiportxuhao,))
        row = cur.fetchone()

        if row:
            update_fields = []
            update_vals = []
            update_fields.append("target_ip=?")
            update_vals.append(ip)
            update_fields.append("target_port=?")
            update_vals.append(port)
            if host:
                update_fields.append("host=?")
                update_vals.append(host)
            if redirect_scheme in ('http', 'https'):
                update_fields.append("redirect_scheme=?")
                update_vals.append(redirect_scheme)
            if redirect_method in ('307', '308'):
                update_fields.append("redirect_method=?")
                update_vals.append(redirect_method)
            if cache_seconds_s:
                try:
                    cv = int(cache_seconds_s)
                    if 60 <= cv <= 360000:
                        update_fields.append("cache_seconds=?")
                        update_vals.append(cv)
                except ValueError:
                    pass
            if listen_port and listen_port != row['listen_port']:
                cur2 = conn.execute("SELECT id FROM redirect_rules WHERE listen_port=? AND id!=?", (listen_port, row['id']))
                if cur2.fetchone():
                    if listen_port != row['listen_port']:
                        log('INFO', 'webhook', f'port {listen_port} taken by another rule, keeping current port {row["listen_port"]}',
                            client=client, user=webhook_user, requested=listen_port, kept=row['listen_port'])
                else:
                    update_fields.append("listen_port=?")
                    update_vals.append(listen_port)
            update_fields.append("updated_at=datetime('now','localtime')")
            update_vals.append(fuwuqiportxuhao)
            conn.execute("UPDATE redirect_rules SET %s WHERE fuwuqiportxuhao=?" % ','.join(update_fields), update_vals)
            conn.commit()
            lp = listen_port or row['listen_port']
            conn.close()
            update_redirect_target(lp, ip, port,
                host=host or row['host'] or '',
                scheme=redirect_scheme or row['redirect_scheme'] or 'http',
                method=redirect_method or row['redirect_method'] or '308',
                cache_seconds=int(cache_seconds_s or row['cache_seconds'] or 300))
            log('INFO', 'webhook', f'updated rule {fuwuqiportxuhao} -> {ip}:{port}',
                client=client, fuwuqiportxuhao=fuwuqiportxuhao, listen_port=lp, target_ip=ip, target_port=port, user=webhook_user)
            sync_nginx_routes()
            self._send_json(200, {'message': '\u66f4\u65b0\u6210\u529f', 'target': f'{ip}:{port}', 'listen_port': lp, 'user': webhook_user})

        else:
            assigned_port = find_free_port(listen_port) if listen_port else 0
            if not assigned_port:
                conn.close()
                log('WARN', 'webhook', f'auto-create failed: no free port available',
                    client=client, fuwuqiportxuhao=fuwuqiportxuhao)
                return self._send_json(503, {'error': '\u65e0\u53ef\u7528\u7aef\u53e3\uff0c\u7aef\u53e3\u6c60\u5df2\u6ee1'})
            if assigned_port != listen_port and listen_port:
                cur2 = conn.execute("SELECT id, created_by FROM redirect_rules WHERE listen_port=?", (listen_port,))
                existing = cur2.fetchone()
                if existing and existing['created_by'] == webhook_user:
                    log('INFO', 'webhook', f'same user port conflict, updating existing rule {existing["id"]}',
                        client=client, user=webhook_user, port=listen_port, existing_rule=existing['id'])
                    conn.execute("UPDATE redirect_rules SET target_ip=?, target_port=?, host=?, redirect_scheme=?, redirect_method=?, cache_seconds=?, updated_at=datetime('now','localtime') WHERE id=?",
                                 (ip, port, host, redirect_scheme if redirect_scheme in ('http','https') else 'http',
                                  redirect_method if redirect_method in ('307','308') else '307',
                                  int(cache_seconds_s) if cache_seconds_s and cache_seconds_s.isdigit() else 300,
                                  existing['id']))
                    conn.commit()
                    rule_id = existing['id']
                    start_redirect_server(listen_port, ip, port,
                        host=host or '',
                        scheme=redirect_scheme or 'http',
                        method=redirect_method or '308',
                        cache_seconds=int(cache_seconds_s or 300),
                        proxy_mode=existing['proxy_mode'] if 'proxy_mode' in existing else 0,
                        domain_prefix=existing.get('domain_prefix', '') or '')
                    log('INFO', 'webhook', f'same-user updated rule {existing["id"]} on port {listen_port} -> {ip}:{port}',
                        client=client, fuwuqiportxuhao=fuwuqiportxuhao, listen_port=listen_port, rule_id=existing['id'])
                    conn.close()
                    sync_nginx_routes()
                    self._send_json(200, {'message': '\u66f4\u65b0\u6210\u529f', 'target': f'{ip}:{port}', 'listen_port': listen_port, 'user': webhook_user, 'note': '\u540c\u7528\u6237\u7aef\u53e3\u51b2\u7a81\uff0c\u5df2\u66f4\u65b0\u539f\u89c4\u5219\u76ee\u6807'})
                    return
                log('INFO', 'webhook', f'port {listen_port} taken by different user, auto-assigned {assigned_port}',
                    client=client, requested=listen_port, assigned=assigned_port)
            listen_port = assigned_port
            try:
                conn.execute("INSERT INTO redirect_rules (fuwuqiportxuhao, listen_port, created_by) VALUES (?,?,?)",
                             (fuwuqiportxuhao, listen_port, webhook_user))
                extra_fields = []
                extra_vals = []
                extra_fields.append("target_ip=?")
                extra_vals.append(ip)
                extra_fields.append("target_port=?")
                extra_vals.append(port)
                if host:
                    extra_fields.append("host=?")
                    extra_vals.append(host)
                if redirect_scheme in ('http', 'https'):
                    extra_fields.append("redirect_scheme=?")
                    extra_vals.append(redirect_scheme)
                if redirect_method in ('307', '308'):
                    extra_fields.append("redirect_method=?")
                    extra_vals.append(redirect_method)
                if cache_seconds_s:
                    try:
                        cv = int(cache_seconds_s)
                        if 60 <= cv <= 360000:
                            extra_fields.append("cache_seconds=?")
                            extra_vals.append(cv)
                    except ValueError:
                        pass
                if extra_fields:
                    conn.execute("UPDATE redirect_rules SET %s WHERE fuwuqiportxuhao=?" % ','.join(extra_fields), extra_vals + [fuwuqiportxuhao])
                conn.commit()
                rule_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                start_redirect_server(listen_port, ip, port,
                    host=host or '',
                    scheme=redirect_scheme or 'http',
                    method=redirect_method or '308',
                    cache_seconds=int(cache_seconds_s or 300),
                    proxy_mode=0,
                    domain_prefix='')
                log('INFO', 'webhook', f'auto-created rule {fuwuqiportxuhao} on :{listen_port} -> {ip}:{port}',
                    client=client, fuwuqiportxuhao=fuwuqiportxuhao, listen_port=listen_port, rule_id=rule_id, target_ip=ip, target_port=port)
                conn.close()
                sync_nginx_routes()
                self._send_json(200, {'message': '\u521b\u5efa\u6210\u529f', 'target': f'{ip}:{port}', 'listen_port': listen_port, 'user': webhook_user})
                return
            except sqlite3.IntegrityError:
                conn.close()
                log('WARN', 'webhook', f'auto-create failed: fuwuqiportxuhao exists',
                    client=client, fuwuqiportxuhao=fuwuqiportxuhao)
                return self._send_json(409, {'error': '\u670d\u52a1\u7aef\u53e3\u5e8f\u53f7\u5df2\u5b58\u5728'})

    def _api_list_users(self):
        user_info = get_current_user(self.headers)
        if not user_info or user_info['role'] != 'admin':
            return self._send_json(403, {'error': '\u4ec5\u7ba1\u7406\u5458\u53ef\u67e5\u770b\u7528\u6237\u5217\u8868'})
        conn = get_db()
        rows = conn.execute("""
            SELECT u.id, u.username, u.role, u.created_at,
                   (SELECT COUNT(*) FROM redirect_rules WHERE created_by=u.username) AS rule_count
            FROM users u ORDER BY u.id
        """).fetchall()
        conn.close()
        self._send_json(200, [dict(r) for r in rows])

    def _api_delete_user(self, uid):
        user_info = get_current_user(self.headers)
        if not user_info or user_info['role'] != 'admin':
            return self._send_json(403, {'error': '\u4ec5\u7ba1\u7406\u5458\u53ef\u5220\u9664\u7528\u6237'})
        conn = get_db()
        cur = conn.execute("SELECT id, username FROM users WHERE id=?", (uid,))
        target = cur.fetchone()
        if not target:
            conn.close()
            return self._send_json(404, {'error': '\u7528\u6237\u4e0d\u5b58\u5728'})
        if target['username'] == user_info['username']:
            conn.close()
            return self._send_json(400, {'error': '\u4e0d\u80fd\u5220\u9664\u5f53\u524d\u767b\u5f55\u8d26\u53f7'})
        ports = conn.execute("SELECT listen_port FROM redirect_rules WHERE created_by=?", (target['username'],)).fetchall()
        for r in ports:
            stop_redirect_server(r['listen_port'])
        conn.execute("DELETE FROM redirect_rules WHERE created_by=?", (target['username'],))
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.commit()
        conn.close()
        log('INFO', 'api', f'admin deleted user {target["username"]}', admin=user_info['username'], deleted_user=target['username'])
        self._send_json(200, {'message': '\u7528\u6237\u53ca\u5176\u89c4\u5219\u5df2\u5220\u9664'})

    def _api_logout(self):
        auth = self.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            _tokens.pop(token, None)
            conn = get_db()
            conn.execute("DELETE FROM tokens WHERE token=?", (token,))
            conn.commit()
            conn.close()
        self._send_json(200, {'message': '\u5df2\u9000\u51fa\u767b\u5f55'})

    def _api_get_settings(self):
        user_info = get_current_user(self.headers)
        if not user_info or user_info['role'] != 'admin':
            return self._send_json(403, {'error': '\u4ec5\u7ba1\u7406\u5458\u53ef\u67e5\u770b\u8bbe\u7f6e'})
        conn = get_db()
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        conn.close()
        self._send_json(200, {r['key']: r['value'] for r in rows})

    def _api_update_settings(self, data):
        user_info = get_current_user(self.headers)
        if not user_info or user_info['role'] != 'admin':
            return self._send_json(403, {'error': '\u4ec5\u7ba1\u7406\u5458\u53ef\u4fee\u6539\u8bbe\u7f6e'})
        for key, value in data.items():
            set_setting(key, str(value).strip())
        log('INFO', 'api', 'settings updated', admin=user_info['username'], keys=list(data.keys()))
        self._send_json(200, {'message': '\u8bbe\u7f6e\u5df2\u4fdd\u5b58'})

    def do_GET(self):
        if self._domain_redirect():
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        qs = parse_qs(parsed.query)
        if path in ('', '/'):
            return self._send_html(ADMIN_HTML)
        elif path == '/api/rules':
            self._api_list_rules()
        elif path == '/api/users':
            self._api_list_users()
        elif path == '/api/settings':
            self._api_get_settings()
        elif path == '/api/logout':
            self._api_logout()
        elif path == '/stun':
            self._api_webhook({k: (v[0] if v else '') for k, v in qs.items()})
        else:
            self._send_json(404, {'error': 'Not Found'})
            log('WARN', 'http', '404 not found', client=self.client_address[0], path=self.path)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        data = self._json_body()
        if path == '/api/login':
            self._api_login(data)
        elif path == '/api/register':
            self._api_register(data)
        elif path == '/api/rules':
            self._api_create_rule(data)
        elif path == '/api/settings':
            self._api_update_settings(data)
        elif path == '/api/change-password':
            self._api_change_password(data)
        elif path == '/stun':
            self._api_webhook(data)
        elif re.match(r'^/api/rules/\d+/toggle$', path):
            self._api_toggle_rule(int(path.split('/')[-2]))
        else:
            self._send_json(404, {'error': 'Not Found'})
            log('WARN', 'http', '404 not found', client=self.client_address[0], path=self.path)

    def do_PUT(self):
        if self._domain_redirect():
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        m = re.match(r'^/api/rules/(\d+)$', path)
        if m:
            self._api_update_rule(int(m.group(1)), self._json_body())
        else:
            self._send_json(404, {'error': 'Not Found'})
            log('WARN', 'http', '404 not found', client=self.client_address[0], path=self.path)

    def do_DELETE(self):
        if self._domain_redirect():
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        m = re.match(r'^/api/rules/(\d+)$', path)
        if m:
            self._api_delete_rule(int(m.group(1)))
        else:
            m2 = re.match(r'^/api/users/(\d+)$', path)
            if m2:
                self._api_delete_user(int(m2.group(1)))
            else:
                self._send_json(404, {'error': 'Not Found'})
                log('WARN', 'http', '404 not found', client=self.client_address[0], path=self.path)

    do_HEAD = do_GET
    do_PATCH = do_GET
    do_OPTIONS = do_GET

    def log_message(self, fmt, *args):
        pass

# ─── Admin HTML (Embedded) ─────────────────────────────────────────────────
ADMIN_HTML = r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<title>STUN 307 重定向管理</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,'Microsoft YaHei',sans-serif;background:#0f1117;color:#e1e4e8;min-height:100vh;line-height:1.5}
.container{max-width:1200px;margin:0 auto;padding:20px}
.card{background:#1c1f2b;border-radius:10px;border:1px solid #2d3041;padding:16px;margin-bottom:14px}
.btn{display:inline-flex;align-items:center;justify-content:center;padding:7px 14px;border-radius:6px;border:none;cursor:pointer;font-size:12px;font-weight:500;transition:all .15s ease;white-space:nowrap}
.btn-primary{background:#3b82f6;color:#fff}.btn-primary:hover{background:#2563eb}
.btn-danger{background:#ef4444;color:#fff}.btn-danger:hover{background:#dc2626}
.btn-success{background:#22c55e;color:#fff}.btn-success:hover{background:#16a34a}
.btn-sm{padding:4px 10px;font-size:11px}
.btn-outline{background:0 0;border:1px solid #3b82f6;color:#3b82f6}.btn-outline:hover{background:#3b82f6;color:#fff}
.btn-ghost{background:0 0;border:none;color:#6b7280;cursor:pointer;padding:4px 6px;border-radius:4px;font-size:12px;transition:all .15s}.btn-ghost:hover{color:#e1e4e8;background:#2d3041}
input,select,textarea{width:100%;padding:9px 12px;border:1px solid #2d3041;border-radius:6px;background:#0f1117;color:#e1e4e8;font-size:13px;outline:0;transition:border-color .15s}
textarea{resize:vertical;font-family:inherit;line-height:1.5}
input:focus,select:focus{border-color:#3b82f6}
input::placeholder{color:#6b7280}
label{display:block;margin-bottom:5px;font-size:12px;color:#9ca3af;font-weight:500}
.form-group{margin-bottom:14px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
h1{font-size:20px;font-weight:600;letter-spacing:-0.01em}
h2{font-size:14px;font-weight:600;margin-bottom:12px;color:#e1e4e8}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.header h1{color:#fff}
.user-info{font-size:12px;color:#9ca3af;display:flex;align-items:center;gap:12px}
.user-info a{color:#3b82f6;cursor:pointer;text-decoration:none}.user-info a:hover{color:#60a5fa}
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:8px;border:1px solid #2d3041}
table{width:100%;border-collapse:collapse;font-size:12px;min-width:900px}
th{position:sticky;top:0;z-index:1;background:#1c1f2b;padding:10px 10px;text-align:left;border-bottom:2px solid #2d3041;color:#6b7280;font-weight:600;font-size:11px;white-space:nowrap}
td{padding:9px 10px;text-align:left;border-bottom:1px solid #2d3041;color:#e1e4e8;vertical-align:middle}
tr:last-child td{border-bottom:0}
tr:hover td{background:#252836}
.table-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600}
.badge-on{background:#22c55e18;color:#22c55e;border:1px solid #22c55e30}
.badge-off{background:#ef444418;color:#ef4444;border:1px solid #ef444430}
.badge-info{background:#3b82f618;color:#3b82f6;border:1px solid #3b82f630}
.badge-secondary{background:#6b728018;color:#9ca3af;border:1px solid #6b728030}
.badge-pending{background:#f59e0b18;color:#f59e0b;border:1px solid #f59e0b30}
.actions{display:flex;gap:4px;flex-wrap:nowrap}
.modal-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.65);z-index:1000;align-items:center;justify-content:center;backdrop-filter:blur(2px)}
.modal-overlay.active{display:flex}
.modal{background:#1c1f2b;border-radius:12px;border:1px solid #2d3041;padding:24px;width:480px;max-width:90vw;max-height:85vh;overflow-y:auto}
.modal h2{margin-bottom:16px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:18px}
#loginPage,#registerPage{max-width:380px;margin:100px auto 0}
#loginPage h1,#registerPage h1{text-align:center;margin-bottom:24px;font-size:22px}
#loginPage .card,#registerPage .card{padding:28px}
.tab-link{color:#3b82f6;cursor:pointer;text-align:center;display:block;margin-top:12px;font-size:13px}.tab-link:hover{color:#60a5fa}
.toast{position:fixed;top:20px;right:20px;padding:14px 20px;border-radius:10px;color:#fff;font-size:14px;z-index:2000;opacity:0;transform:translateY(-16px);transition:.25s ease;max-width:95vw;word-break:break-all;line-height:1.6;box-shadow:0 8px 24px rgba(0,0,0,.4)}
.toast.show{opacity:1;transform:translateY(0)}
.toast-success{background:#22c55e}.toast-error{background:#ef4444}
.empty-state{text-align:center;padding:36px 0;color:#6b7280;font-size:13px}.empty-state p{margin-bottom:10px}

.stat-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.stat-item{background:#1c1f2b;border:1px solid #2d3041;border-radius:8px;padding:5px 12px;font-size:11px;display:flex;align-items:center;gap:5px}
.stat-label{color:#6b7280}.stat-value{font-weight:600;color:#e1e4e8}.stat-warn{color:#f59e0b}

.tab-nav{display:flex;gap:0;margin-bottom:12px;background:#1c1f2b;border:1px solid #2d3041;border-radius:8px;padding:3px;width:fit-content}
.tab-btn{padding:5px 14px;border-radius:6px;border:none;background:0 0;color:#6b7280;font-size:12px;font-weight:500;cursor:pointer;transition:all .15s}
.tab-btn.active{background:#3b82f6;color:#fff}
.tab-btn:hover:not(.active){color:#e1e4e8}
.hidden-owner{display:none}

.doc-toggle{background:#1c1f2b;border:1px solid #2d3041;border-radius:10px;margin-bottom:16px;overflow:hidden}
.doc-toggle-header{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;cursor:pointer;font-size:12px;color:#9ca3af;font-weight:500;transition:background .15s}
.doc-toggle-header:hover{background:#252836}
.doc-toggle-icon{font-size:10px;transition:transform .2s}
.doc-toggle.open .doc-toggle-icon{transform:rotate(180deg)}
.doc-toggle-body{display:none;padding:0 14px 12px;font-size:12px;color:#9ca3af;line-height:1.7}
.doc-toggle.open .doc-toggle-body{display:block}
.doc-section{margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid #2d3041}
.doc-section:last-child{border-bottom:0;margin-bottom:0;padding-bottom:0}
.doc-title{font-weight:600;color:#e1e4e8;margin-bottom:5px;font-size:12px}
.doc-row{display:flex;gap:8px;margin-bottom:3px;flex-wrap:wrap}
.doc-label{color:#6b7280;min-width:70px;flex-shrink:0}
.doc-method-get{color:#3b82f6;font-weight:600}
.doc-method-post{color:#22c55e;font-weight:600}
code{background:#0f1117;padding:2px 6px;border-radius:3px;font-size:11px;color:#3b82f6}
.doc-code-warn{color:#f59e0b}
.doc-code-block{display:block;background:#0f1117;padding:10px 12px;border-radius:6px;font-size:11px;color:#22c55e;white-space:pre;line-height:1.6;margin-top:4px}
.doc-code-full{display:block;background:#0f1117;padding:8px 12px;border-radius:6px;font-size:11px;color:#3b82f6;word-break:break-all;line-height:1.6;margin-top:4px}
.doc-params{margin-top:8px}
.doc-params b{color:#e1e4e8}
.doc-conflict{margin-top:8px;padding:8px 12px;background:#f59e0b10;border:1px solid #f59e0b30;border-radius:6px;color:#f59e0b;font-size:11px}
.doc-tip{margin-top:8px;color:#6b7280;font-size:11px}

.domain-links{display:flex;flex-wrap:wrap;gap:2px 6px;align-items:center}
.domain-links a{color:#22c55e;text-decoration:none;font-size:12px;white-space:nowrap}
.domain-links a:hover{text-decoration:underline}
.domain-links .sep{color:#2d3041;font-size:10px}
.domain-links .gray{color:#6b7280}
.domain-links .blue{color:#3b82f6}

@media(max-width:768px){.form-row{grid-template-columns:1fr}.header{flex-direction:column;align-items:flex-start;gap:8px}.table-header{flex-direction:column;align-items:flex-start;gap:8px}.container{padding:12px}.card{padding:12px}}
@media(max-width:640px){.doc-row{flex-direction:column;gap:2px}.doc-label{min-width:0}}
</style>
</head>
<body>
<script>try{
var tkn=localStorage.getItem('token'),un=localStorage.getItem('uname')
var ss=document.createElement('style')
ss.textContent=tkn&&un?'#loginPage{display:none}#dashboard{display:block}':'#loginPage{display:block}#dashboard{display:none}'
document.head.appendChild(ss)
}catch(e){}</script>
<div class="container" id="app">
<div id="loginPage" style="display:none">
<div class="card">
<h1>STUN 重定向管理</h1>
<div id="loginForm">
<div class="form-group"><label>用户名</label><input id="loginUser" placeholder="请输入用户名"></div>
<div class="form-group"><label>密码</label><input id="loginPass" type="password" placeholder="请输入密码"></div>
<button class="btn btn-primary" style="width:100%" onclick="login()">登 录</button>
<div class="tab-link" onclick="showRegister()">没有账号？点此注册</div>
</div>
<div id="registerForm" style="display:none">
<div class="form-group"><label>用户名</label><input id="regUser" placeholder="至少3位"></div>
<div class="form-group"><label>密码</label><input id="regPass" type="password" placeholder="至少6位"></div>
<div class="form-group"><label>确认密码</label><input id="regPass2" type="password" placeholder="再次输入密码"></div>
<button class="btn btn-success" style="width:100%" onclick="register()">注 册</button>
<div class="tab-link" onclick="showLogin()">已有账号？点此登录</div>
</div>
</div>
</div>

<div id="dashboard" style="display:none">
<div class="header">
<h1>STUN 307 重定向</h1>
<div class="user-info">
<span id="userDisplay"></span>
<a onclick="logout()">退出登录</a>
</div>
</div>

<div class="doc-toggle" onclick="this.classList.toggle('open')">
<div class="doc-toggle-header">
<span>Webhook 接口文档</span>
<span class="doc-toggle-icon">&#9662;</span>
</div>
<div class="doc-toggle-body">
<div class="doc-section">
<div class="doc-title">GET Webhook（Lucky 推送兼容）</div>
<div class="doc-row"><span class="doc-label">完整地址</span><code class="doc-code-full" id="hookFullUrl">http://服务器IP:8800/stun?ip=#{ip}&amp;port=#{port}&amp;fuwuqiportxuhao=#{fuwuqiportxuhao}&amp;listen_port=#{listen_port}&amp;user=#{user}</code></div>
<div class="doc-row"><span class="doc-label">请求方法</span><span class="doc-method-get">GET</span></div>
<div class="doc-row"><span class="doc-label">请求头</span>无（无需鉴权）</div>
<div class="doc-row"><span class="doc-label">请求体</span>无（参数通过 URL Query 传递）</div>
</div>
<div class="doc-section">
<div class="doc-title">POST Webhook（完整参数 + 鉴权）</div>
<div class="doc-row"><span class="doc-label">接口地址</span><code>http://<span class="hookHost2">服务器IP</span>:<span class="hookPort2">8800</span>/stun</code></div>
<div class="doc-row"><span class="doc-label">请求方法</span><span class="doc-method-post">POST</span></div>
<div class="doc-row"><span class="doc-label">请求头</span><code>Content-Type: application/json</code></div>
<div class="doc-row"><span class="doc-label">请求体</span><code class="doc-code-block">{\n  "ip": "1.2.3.4",\n  "port": 80,\n  "fuwuqiportxuhao": "proxy1",\n  "listen_port": 50001,\n  "user": "admin1",\n  "userpassword": "123456",\n  "host": "*.a.b.c.com",\n  "redirect_scheme": "https",\n  "redirect_method": "308",\n  "cache_seconds": 600\n}</code></div>
</div>
<div class="doc-params">
<div class="doc-title">参数说明（#{...} 为 Lucky 自动替换占位符）</div>
<div><b>ip</b> / <b>port</b> — 必填，目标 IP、端口</div>
<div><b>listen_port</b>（或 fuwuqiport）— 代理监听端口（40000-60000），创建时必须</div>
<div><b>fuwuqiportxuhao</b> — 可选，服务端口序号，不传则自动用 listen_port 作为序号</div>
<div><b>user</b> — 可选，不传默认 admin1</div>
<div><b>userpassword</b> — 可选，传则校验密码；不传则自动注册（默认密码 123456）</div>
<div><b>host</b> — 可选，主机模板如 *.a.b.c.com，* 会被域名前缀替换</div>
<div><b>redirect_scheme</b> — 可选，http 或 https，默认 http</div>
<div><b>redirect_method</b> — 可选，307（临时）或 308（永久可缓存），默认 308</div>
<div><b>cache_seconds</b> — 可选，仅 308 时有效，60-360000，默认 300</div>
</div>
<div class="doc-conflict">
<strong>端口冲突处理</strong>：同用户端口占用 → 自动更新原规则；不同用户 → 自动分配 40000-60000 空闲端口
</div>
<div class="doc-tip">Lucky 推荐用 GET Webhook，#{ip} #{port} #{fuwuqiportxuhao} #{listen_port} #{user} 会自动替换</div>
</div>
</div>

<div class="stat-bar">
<div class="stat-item"><span class="stat-label">端口范围</span><span class="stat-value stat-warn">40000 - 60000</span></div>
<div id="ruleLimitBadge" class="stat-item"><span class="stat-label">规则上限</span><span id="ruleLimitText" class="stat-value">∞</span></div>
</div>

<div id="adminNav" style="display:none">
<div class="tab-nav">
<button class="tab-btn active" id="tabRulesBtn" onclick="switchTab('rules')">规则管理</button>
<button class="tab-btn" id="tabUsersBtn" onclick="switchTab('users')">用户管理</button>
<button class="tab-btn" id="tabSettingsBtn" onclick="switchTab('settings')">系统设置</button>
</div>
</div>

<div id="tabUsers" style="display:none">
<div class="card">
<h2>用户管理</h2>
<table>
<thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>规则数</th><th>创建时间</th><th>操作</th></tr></thead>
<tbody id="usersBody"></tbody>
</table>
<div id="userEmptyState" class="empty-state" style="display:none"><p>暂无用户</p></div>
</div>
</div>

<div id="tabSettings" style="display:none">
<div class="card">
<h2>系统设置</h2>
<div class="form-group"><label>服务域名</label><input id="settingRootDomain" placeholder="如 stun.sd8.cc"></div>
<div class="form-group"><label>普通用户规则上限</label><input id="settingMaxRules" type="number" min="1" max="100" placeholder="默认 3"></div>
<div style="margin-top:14px"><button class="btn btn-primary" onclick="saveSettings()">保存设置</button></div>
</div>
<div class="card" style="margin-top:16px">
<h2>修改密码</h2>
<div class="form-group"><label>当前密码</label><input id="changePwdOld" type="password" placeholder="输入当前密码"></div>
<div class="form-group"><label>新密码</label><input id="changePwdNew" type="password" placeholder="输入新密码（至少6位）"></div>
<div class="form-group"><label>确认新密码</label><input id="changePwdConfirm" type="password" placeholder="再次输入新密码"></div>
<div style="margin-top:14px"><button class="btn btn-primary" onclick="changePassword()">修改密码</button></div>
</div>
</div>

<div id="tabRules">
<div class="card">
<div class="table-header">
<h2>重定向规则</h2>
<button class="btn btn-primary btn-sm" onclick="showAddModal()">+ 新增规则</button>
</div>
<div class="table-wrap">
<table>
<thead><tr><th>ID</th><th>序号</th><th>端口</th><th>访问域名</th><th>Webhook</th><th>目标</th><th id="thOwner">用户</th><th>配置</th><th>状态</th><th>更新时间</th><th>操作</th></tr></thead>
<tbody id="rulesBody"></tbody>
</table>
</div>
<div id="emptyState" class="empty-state" style="display:none">
<p>暂无重定向规则</p>
<button class="btn btn-primary btn-sm" onclick="showAddModal()">+ 新增第一条规则</button>
</div>
</div>
</div>
</div>

<div class="modal-overlay" id="ruleModal">
<div class="modal">
<h2 id="modalTitle">新增规则</h2>
<div class="form-row">
<div class="form-group"><label>服务端口序号 (fuwuqiportxuhao)</label><input id="ruleXH" placeholder="如：proxy1"></div>
<div class="form-group"><label>监听端口 (listen_port)</label><input id="rulePort" type="number" placeholder="如：50001"><div style="margin-top:4px;font-size:11px;color:#f59e0b">&#9432; 仅限 40000-60000</div></div>
</div>
<div class="form-group"><label>访问域名前缀 (如 mynas，生成 mynas.端口.stun.sd8.cc)</label><input id="ruleDomainPrefix" placeholder="留空默认 * 匹配所有，如 *.50001.stun.sd8.cc"></div>
<div class="form-group"><label>主机模板 (host, 如 *.a.b.c.com，* 会被替换为域名前缀)</label><input id="ruleHost" placeholder="留空则使用目标IP方式"></div>
<div class="form-row">
<div class="form-group"><label>重定向协议</label><select id="ruleScheme" style="width:100%;padding:10px 14px;border:1px solid #2d3041;border-radius:6px;background:#0f1117;color:#e1e4e8;font-size:14px;outline:0"><option value="http">HTTP</option><option value="https">HTTPS</option></select></div>
<div class="form-group"><label>重定向方式</label><select id="ruleMethod" style="width:100%;padding:10px 14px;border:1px solid #2d3041;border-radius:6px;background:#0f1117;color:#e1e4e8;font-size:14px;outline:0" onchange="toggleCacheInput()"><option value="307">307（临时）</option><option value="308" selected>308（永久，可缓存）</option></select></div>
</div>
<div id="cacheGroup" class="form-group" style="display:none"><label>缓存时间（秒，60-360000，默认300）</label><input id="ruleCache" type="number" value="300" min="60" max="360000" placeholder="300"></div>
<div class="form-group" id="modeGroup"><label>模式</label><select id="ruleMode" style="width:100%;padding:10px 14px;border:1px solid #2d3041;border-radius:6px;background:#0f1117;color:#e1e4e8;font-size:14px;outline:0" onchange="toggleModeInput()"><option value="0">重定向（307/308）</option><option value="1">反向代理（透传）</option></select></div>
<div class="form-group"><label>域名映射（每行：前缀 后端域名，如 sp sp.speedtest.cn.sd8.cc）</label><textarea id="ruleDomainMappings" rows="3" placeholder="sp sp.speedtest.cn.sd8.cc&#10;fn fn.sd8.cc&#10;留空则使用 host 中的 * 通配符替换前缀"></textarea></div>
<div id="modalLimitHint" style="font-size:11px;color:#9ca3af;margin-bottom:12px"></div>
<div class="modal-actions">
<button class="btn btn-outline" onclick="closeModal()">取消</button>
<button class="btn btn-primary" id="saveBtn" onclick="saveRule()">保存</button>
</div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
let token=localStorage.getItem('token')||'';
let uname=localStorage.getItem('uname')||'';
let urole=localStorage.getItem('urole')||'';
let editId=null

async function api(m,p,d){
const opt={method:m,headers:{'Content-Type':'application/json'}}
if(token)opt.headers['Authorization']='Bearer '+token
if(d)opt.body=JSON.stringify(d)
try{
const r=await fetch(p,opt)
return await r.json()
}catch(e){return{error:'网络错误'}}
}

function toast(msg,type='success'){
const t=document.getElementById('toast')
t.innerHTML=msg.replace(/\n/g,'<br>')
t.className='toast toast-'+type
setTimeout(()=>t.classList.add('show'),10)
setTimeout(()=>t.classList.remove('show'),8000)
}

function copyText(t){
if(navigator.clipboard&&window.isSecureContext){
navigator.clipboard.writeText(t).then(()=>toast('已复制到剪贴板')).catch(()=>fallbackCopy(t))
}else{fallbackCopy(t)}
}
function fallbackCopy(t){
var ta=document.createElement('textarea')
ta.value=t
ta.style.cssText='position:fixed;left:-9999px;top:-9999px'
document.body.appendChild(ta)
ta.focus()
ta.select()
try{document.execCommand('copy');toast('已复制到剪贴板')}catch(e){toast('复制失败，请手动复制','error')}
document.body.removeChild(ta)
}
function showLogin(){document.getElementById('loginForm').style.display='block';document.getElementById('registerForm').style.display='none'}
function showRegister(){document.getElementById('loginForm').style.display='none';document.getElementById('registerForm').style.display='block'}

async function login(){
try{
const u=document.getElementById('loginUser').value.trim()
const p=document.getElementById('loginPass').value
if(!u||!p){toast('请输入用户名和密码','error');return}
const r=await api('POST','/api/login',{username:u,password:p})
if(r.token){localStorage.setItem('token',r.token);localStorage.setItem('uname',r.username);localStorage.setItem('urole',r.role);token=r.token;uname=r.username;urole=r.role;loadDashboard();toast('登录成功')}
else{toast(r.error||'登录失败','error')}
}catch(e){console.error(e);toast('登录异常:'+e.message,'error')}
}

async function register(){
const u=document.getElementById('regUser').value.trim()
const p=document.getElementById('regPass').value
const p2=document.getElementById('regPass2').value
if(!u||!p){toast('请填写完整','error');return}
if(p!==p2){toast('两次密码不一致','error');return}
const r=await api('POST','/api/register',{username:u,password:p})
if(r.message){toast('注册成功，请登录');showLogin()}
else{toast(r.error||'注册失败','error')}
}

function logout(){fetch('/api/logout',{headers:{'Authorization':'Bearer '+localStorage.getItem('token')}});localStorage.removeItem('token');localStorage.removeItem('uname');localStorage.removeItem('urole');token='';uname='';urole='';document.getElementById('dashboard').style.display='none';document.getElementById('loginPage').style.display='block'}

async function loadDashboard(){
const r=await api('GET','/api/rules')
if(r.error){logout();return}
const settings=await api('GET','/api/settings')
var rootDomain=(settings&&settings.root_domain)||'stun.sd8.cc'
document.getElementById('loginPage').style.display='none'
document.getElementById('dashboard').style.display='block'
const tbody=document.getElementById('rulesBody')
tbody.innerHTML=''
document.getElementById('emptyState').style.display=r.length?'none':'block'
var host=window.location.hostname||'服务器IP';var port=window.location.port||'8800'
whBase=rootDomain?`http://${rootDomain}`:`http://${host}:${port}`
var isAdmin=urole==='admin'
document.getElementById('userDisplay').textContent=uname+(isAdmin?' (管理员)':' (普通用户)')
document.getElementById('adminNav').style.display=isAdmin?'block':'none'
document.getElementById('thOwner').style.display=isAdmin?'':'none'
document.getElementById('modeGroup').style.display=isAdmin?'':'none'
if(isAdmin){
document.getElementById('ruleLimitText').textContent='∞ (管理员无限制)'
document.getElementById('ruleLimitText').style.color='#3b82f6'
document.getElementById('modalLimitHint').textContent='管理员无规则数量限制'
switchTab('rules')
loadUsers()
}else{
var maxR=parseInt(settings.max_rules_per_user)||3
document.getElementById('ruleLimitText').textContent=r.length+'/'+maxR+' 剩余'
document.getElementById('ruleLimitText').style.color=r.length<maxR?'#22c55e':'#ef4444'
document.getElementById('modalLimitHint').textContent='普通用户最多 '+maxR+' 条规则，已用 '+r.length+' 条'+(r.length<maxR?'，还可创建 '+(maxR-r.length)+' 条':'，已达上限')
}
document.getElementById('hookFullUrl').textContent=`http://${host}:${port}/stun?ip=#{ip}&port=#{port}&fuwuqiportxuhao=#{fuwuqiportxuhao}&listen_port=#{listen_port}&user=#{user}`
document.querySelectorAll('.hookHost2').forEach(function(e){e.textContent=host})
document.querySelectorAll('.hookPort2').forEach(function(e){e.textContent=port})
document.querySelectorAll('.xhSuffix2').forEach(function(e){e.textContent='#{fuwuqiportxuhao}'})
r.forEach(item=>{
const en=item.enabled
const status=en?'开启':'关闭'
const badgeCls=en?'badge-on':'badge-off'
const hasTarget=item.target_ip&&item.target_port
const tipHtml=hasTarget?'':` <span class="badge badge-pending">等待</span>`
var whUrl=`${whBase}/stun?ip=#{ip}&port=#{port}&fuwuqiportxuhao=${item.fuwuqiportxuhao}&listen_port=${item.listen_port}&user=${item.created_by||'admin1'}`
const tr=document.createElement('tr')
var owner=(item.created_by||'')!==''?item.created_by:'-'
var ownRule=!isAdmin||item.created_by===uname
var scheme=item.redirect_scheme||'http';var method=item.redirect_method||'307';var cacheInfo=method==='308'&&item.cache_seconds?item.cache_seconds+'s':''
var target=item.target_ip?`${item.target_ip}:${item.target_port}`:'-'
var links=''
if(item.domain_prefix){
  links+='<a href="http://'+item.domain_prefix+'.'+item.listen_port+'.'+rootDomain+'/" target="_blank">'+item.domain_prefix+'.'+item.listen_port+'.'+rootDomain+'</a><span class="sep">|</span><a href="http://'+rootDomain+':'+item.listen_port+'/" target="_blank" class="gray">'+rootDomain+':'+item.listen_port+'</a>'
}
if(item.target_ip&&item.target_port&&!item.domain_prefix){
  var s=item.redirect_scheme||'http'
  if(links)links+='<span class="sep">|</span>'
  links+='<a href="'+s+'://'+item.target_ip+':'+item.target_port+'/" target="_blank" class="gray">'+item.target_ip+':'+item.target_port+'</a>'
}
if(item.domain_mappings){
  var lines=item.domain_mappings.split('\n')
  for(var i=0;i<lines.length;i++){
    var dm=lines[i].trim()
    if(!dm)continue
    for(var p of['https://','http://'])if(dm.startsWith(p))dm=dm.slice(p.length)
    if(dm.endsWith('/'))dm=dm.slice(0,-1)
    var ci=dm.indexOf(':')
    if(ci>0)dm=dm.slice(0,ci)
    var parts=dm.split(/\s+/)
    var prefix=parts.length>=2?parts[0]:parts[0].split('.')[0]
    if(links)links+='<span class="sep">|</span>'
    links+='<a href="http://'+prefix+'.'+item.listen_port+'.'+rootDomain+'/" target="_blank" class="blue">'+prefix+'.'+item.listen_port+'.'+rootDomain+'</a>'
  }
}
var domainHtml=links?'<span class="domain-links">'+links+'</span>':'<span style="color:#6b7280;font-size:11px">-</span>'
var updatedAt=item.updated_at?item.updated_at.replace('T',' ').substring(0,19):'-'
var whSafe=whUrl.replace(/'/g,"\\'")
tr.innerHTML=`<td>${item.id}</td><td><code style="color:#3b82f6;font-size:12px">${item.fuwuqiportxuhao}</code></td><td><strong>${item.listen_port}</strong></td><td>${domainHtml}</td><td><span style="display:inline-flex;align-items:center;gap:4px;max-width:280px"><code style="background:#0f1117;padding:3px 6px;border-radius:3px;font-size:11px;color:#3b82f6;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">${whUrl.replace(/&/g,'&amp;')}</code><button class="btn-ghost" style="flex-shrink:0;font-size:11px" onclick="copyText('${whSafe}')" title="复制 Webhook">复制</button></span></td><td><span style="color:#6b7280;font-size:11px">${target}</span>${tipHtml}</td><td style="font-size:11px;color:#9ca3af" class="${isAdmin?'':'hidden-owner'}">${owner}</td><td style="white-space:nowrap"><span class="badge ${scheme==='https'?'badge-on':'badge-off'}">${scheme}</span> <span class="badge ${method==='308'?"badge-on":"badge-off"}">${method}${cacheInfo?' '+cacheInfo:''}</span>${isAdmin?` <span class="badge ${item.proxy_mode?'badge-info':'badge-secondary'}">${item.proxy_mode?'代理':'重定向'}</span>`:''}</td><td><span class="badge ${badgeCls}">${status}</span></td><td style="color:#6b7280;font-size:11px;white-space:nowrap">${updatedAt}</td><td class="actions">${ownRule?`<button class="btn btn-sm ${en?'btn-outline':'btn-success'}" onclick="toggleRule(${item.id})" title="${en?'关闭':'开启'}">${en?'关':'开'}</button><button class="btn btn-sm btn-ghost" onclick="editRule(${item.id})" title="编辑">&#9998;</button><button class="btn btn-sm btn-ghost" style="color:#ef4444" onclick="deleteRule(${item.id})" title="删除">&#10005;</button>`:'<span style="color:#6b7280;font-size:11px">-</span>'}</td>`
tbody.appendChild(tr)
})
}

async function toggleRule(id){
const r=await api('POST','/api/rules/'+id+'/toggle',{})
if(r.message)toast(r.message)
loadDashboard()
}

async function deleteRule(id){
if(!confirm('确定删除此规则？'))return
const r=await api('DELETE','/api/rules/'+id)
if(r.message)toast(r.message)
loadDashboard()
}

function toggleCacheInput(){var m=document.getElementById('ruleMode').value;document.getElementById('cacheGroup').style.display=(document.getElementById('ruleMethod').value==='308'&&m==='0')?'block':'none'}
function toggleModeInput(){var m=document.getElementById('ruleMode').value;document.getElementById('ruleMethod').parentElement.style.display=m==='0'?'block':'none';toggleCacheInput()}
function showAddModal(){editId=null;document.getElementById('modalTitle').textContent='新增规则';document.getElementById('ruleXH').value='';document.getElementById('rulePort').value='';document.getElementById('ruleHost').value='';document.getElementById('ruleDomainPrefix').value='';document.getElementById('ruleDomainMappings').value='';document.getElementById('ruleScheme').value='http';document.getElementById('ruleMethod').value='308';document.getElementById('ruleCache').value=300;document.getElementById('ruleMode').value='0';toggleModeInput();document.getElementById('saveBtn').textContent='保存';document.getElementById('ruleModal').classList.add('active');if(!isAdmin)document.getElementById('modeGroup').style.display='none'}

function closeModal(){document.getElementById('ruleModal').classList.remove('active')}

async function editRule(id){
editId=id;document.getElementById('modalTitle').textContent='编辑规则'
const r=await api('GET','/api/rules')
if(r.error)return
const item=r.find(i=>i.id===id)
if(!item)return
document.getElementById('ruleXH').value=item.fuwuqiportxuhao
document.getElementById('rulePort').value=item.listen_port
document.getElementById('ruleHost').value=item.host||''
document.getElementById('ruleDomainPrefix').value=item.domain_prefix||''
document.getElementById('ruleDomainMappings').value=item.domain_mappings||''
document.getElementById('ruleScheme').value=item.redirect_scheme||'http'
document.getElementById('ruleMethod').value=item.redirect_method||'308'
document.getElementById('ruleMode').value=String(item.proxy_mode||'0');toggleModeInput()
document.getElementById('ruleCache').value=item.cache_seconds||300
document.getElementById('cacheGroup').style.display=(item.redirect_method||'308')==='308'?'block':'none'
document.getElementById('saveBtn').textContent='更新'
document.getElementById('ruleModal').classList.add('active')
if(!isAdmin)document.getElementById('modeGroup').style.display='none'
}

async function saveRule(){
const xh=document.getElementById('ruleXH').value.trim()
const port=parseInt(document.getElementById('rulePort').value)
const host=document.getElementById('ruleHost').value.trim()
const domainPrefix=document.getElementById('ruleDomainPrefix').value.trim()
const scheme=document.getElementById('ruleScheme').value
const method=document.getElementById('ruleMethod').value
var cache=parseInt(document.getElementById('ruleCache').value)||300
if(method==='308'){if(cache<60)cache=60;if(cache>360000)cache=360000}
if(!xh||!port){toast('请填写完整','error');return}
if(port<40000||port>60000){toast('端口范围 40000-60000','error');return}
const btn=document.getElementById('saveBtn')
btn.textContent=editId?'更新中...':'创建中...';btn.disabled=true
const payload={fuwuqiportxuhao:xh,listen_port:port,host:host,domain_prefix:domainPrefix,domain_mappings:document.getElementById('ruleDomainMappings').value,redirect_scheme:scheme,redirect_method:method,cache_seconds:cache,proxy_mode:document.getElementById('ruleMode').value==='1'?1:0}
let r
if(editId)r=await api('PUT','/api/rules/'+editId,payload)
else r=await api('POST','/api/rules',payload)
btn.disabled=false;btn.textContent=editId?'更新':'保存'
if(r.message){
if(!editId){var wh=`${whBase}/stun?ip=#{ip}&port=#{port}&listen_port=${port}&user=${uname||'admin1'}`;toast('✅ 创建成功！<br><b style="font-size:15px">GET ${wh}</b><br><span style="font-size:12px;opacity:.8">复制以上地址配置 Lucky webhook</span>','success')}
else toast(r.message)
closeModal();loadDashboard()
}else{toast(r.error||'操作失败','error')}
}

function switchTab(tab){
document.getElementById('tabRules').style.display=tab==='rules'?'block':'none'
document.getElementById('tabUsers').style.display=tab==='users'?'block':'none'
document.getElementById('tabSettings').style.display=tab==='settings'?'block':'none'
document.getElementById('tabRulesBtn').className=tab==='rules'?'tab-btn active':'tab-btn'
document.getElementById('tabUsersBtn').className=tab==='users'?'tab-btn active':'tab-btn'
document.getElementById('tabSettingsBtn').className=tab==='settings'?'tab-btn active':'tab-btn'
if(tab==='users')loadUsers()
if(tab==='settings')loadSettings()
}

async function loadUsers(){
const r=await api('GET','/api/users')
if(r.error)return
const tbody=document.getElementById('usersBody')
tbody.innerHTML=''
document.getElementById('userEmptyState').style.display=r.length?'none':'block'
r.forEach(u=>{
var isSelf=u.username===uname
const tr=document.createElement('tr')
tr.innerHTML=`<td>${u.id}</td><td>${u.username}${isSelf?' (当前)':''}</td><td><span class="badge ${u.role==='admin'?'badge-on':'badge-off'}">${u.role}</span></td><td>${u.rule_count}</td><td style="font-size:12px;color:#9ca3af">${u.created_at||'-'}</td><td>${isSelf?'<span style="color:#6b7280;font-size:11px">当前账号</span>':`<button class="btn btn-sm btn-danger" onclick="deleteUser(${u.id},'${u.username}')">删除</button>`}</td>`
tbody.appendChild(tr)
})
}

async function loadSettings(){
const r=await api('GET','/api/settings')
if(r.error)return
document.getElementById('settingRootDomain').value=r.root_domain||''
document.getElementById('settingMaxRules').value=r.max_rules_per_user||'3'
}

async function saveSettings(){
const rootDomain=document.getElementById('settingRootDomain').value.trim()
const maxRules=document.getElementById('settingMaxRules').value.trim()
if(!rootDomain){toast('请填写服务域名','error');return}
if(!maxRules||maxRules<1){toast('规则上限至少为 1','error');return}
const r=await api('POST','/api/settings',{root_domain:rootDomain,max_rules_per_user:maxRules})
if(r.message)toast(r.message)
else toast(r.error||'保存失败','error')
}

async function changePassword(){
const old=document.getElementById('changePwdOld').value
const pwd=document.getElementById('changePwdNew').value
const confirm=document.getElementById('changePwdConfirm').value
if(!old||!pwd||!confirm){toast('请填写所有字段','error');return}
if(pwd.length<6){toast('新密码至少 6 位','error');return}
if(pwd!==confirm){toast('两次输入的密码不一致','error');return}
const r=await api('POST','/api/change-password',{old_password:old,new_password:pwd})
if(r.message){toast(r.message);document.getElementById('changePwdOld').value='';document.getElementById('changePwdNew').value='';document.getElementById('changePwdConfirm').value=''}
else toast(r.error||'修改失败','error')
}

async function deleteUser(id,username){
if(!confirm('确定删除用户「'+username+'」及其所有规则？此操作不可撤销！'))return
const r=await api('DELETE','/api/users/'+id)
if(r.message){toast(r.message);loadUsers();loadDashboard()}
else toast(r.error||'删除失败','error')
}

document.getElementById('loginPass').addEventListener('keydown',e=>{if(e.key==='Enter')login()})
document.getElementById('regPass2').addEventListener('keydown',e=>{if(e.key==='Enter')register()})
document.getElementById('changePwdConfirm').addEventListener('keydown',e=>{if(e.key==='Enter')changePassword()})

;(async()=>{
if(token){
const r=await api('GET','/api/rules')
if(r.error)logout()
else loadDashboard()
}else{document.getElementById('loginPage').style.display='block'}
})()
</script>
</body>
</html>'''

# ─── Entry ─────────────────────────────────────────────────────────────────
def main():
    init_db()
    cleanup_logs()
    threading.Thread(target=log_cleanup_loop, daemon=True).start()
    load_all_rules()
    srv = ThreadedHTTPServer(('0.0.0.0', ADMIN_PORT), MainHandler)
    log('INFO', 'server', f'started on port {ADMIN_PORT}', port=ADMIN_PORT)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log('INFO', 'server', 'shutting down')
        srv.shutdown()

if __name__ == '__main__':
    main()
