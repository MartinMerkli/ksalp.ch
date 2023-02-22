#!/usr/bin/env python3

########################################################################################################################
# IMPORTS
########################################################################################################################


from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Flask, g, make_response, redirect, render_template, request, send_from_directory, session
from hashlib import pbkdf2_hmac, sha256
from httpanalyzer import FlaskRequest as AnalyzerRequest
from logging import FileHandler as LogFileHandler, StreamHandler as LogStreamHandler, log as logging_log
from logging import basicConfig as log_basicConfig, getLogger as GetLogger, Formatter as LogFormatter
from logging import ERROR as LOG_ERROR, INFO as LOG_INFO
from os import environ, urandom
from os.path import exists, join
from random import randint, uniform
from resources.themes import THEMES as _THEMES
from resources.search_engines import SEARCH_ENGINES as _SEARCH_ENGINES
from smtplib import SMTP
from ssl import create_default_context
from sqlite3 import connect as sqlite_connect
from time import sleep
from urllib.parse import quote


########################################################################################################################
# GENERAL SETUP
########################################################################################################################


app = Flask(__name__)

if not exists(join(app.root_path, 'resources', 'key.bin')):
    with open(join(app.root_path, 'resources', 'key.bin'), 'wb') as _f:
        _f.write(urandom(64))
with open(join(app.root_path, 'resources', 'key.bin'), 'rb') as _f:
    _secret_key = _f.read()
app.secret_key = _secret_key


########################################################################################################################
# LOGGING
########################################################################################################################


def setup_logger(name, file):
    logger = GetLogger(name)
    formatter = LogFormatter('%(asctime)s\t%(message)s', datefmt='%Y-%m-%d_%H-%M-%S')
    file_handler = LogFileHandler(file, mode='a')
    file_handler.setFormatter(formatter)
    stream_handler = LogStreamHandler()
    stream_handler.setFormatter(formatter)
    logger.setLevel(LOG_INFO)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)


log_basicConfig(filename='main.log', format='%(asctime)s\t%(message)s', datefmt='%Y-%m-%d_%H-%M-%S', level=LOG_INFO)

setup_logger('access', join(app.root_path, 'logs', 'access.log'))
access_log = GetLogger('access')

setup_logger('abuse_report', join(app.root_path, 'logs', 'abuse_report.log'))
abuse_report_log = GetLogger('abuse_report')

setup_logger('request_errors', join(app.root_path, 'logs', 'request_errors.log'))
request_errors_log = GetLogger('request_errors')


########################################################################################################################
# DATABASE SETUP
########################################################################################################################


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite_connect('database.db')
    return db


@app.teardown_appcontext
def close_connection(exception):  # noqa
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    conn = get_db()
    cur = conn.execute(query, args)
    result = cur.fetchall()
    conn.commit()
    cur.close()
    return (result[0] if result else None) if one else result


db_tables = {
    'account': [
        'id TEXT PRIMARY KEY',  # account id; 8-digit base64
        'name TEXT',  # name
        'mail TEXT',  # @sluz.ch e-mail
        'salt TEXT',  # password salt; base64-encoded
        'hash TEXT',  # password hash; base64-encoded
        'newsletter INTEGER',  # has agreed to receive newsletter; binary
        'created TEXT',  # date of creation; %Y-%m-%d_%H-%M-%S
        'theme TEXT',  # selected theme
        'iframe INTEGER',  # wants to get iframes; binary
        'payment TEXT',  # payment expiry date; %Y-%m-%d_%H-%M-%S
        'banned TEXT',  # banned status; indices [_ or X]: 0: platform, 1: calendar, 2: comments, 3: uploading
        'search_engine TEXT',  # name of the selected search engine
    ],
    'ipv4': [
        'address TEXT PRIMARY KEY',  # IPv4 address
        'owner TEXT',  # organisation or physical location
        'score TEXT',  # rating: 0: banned, 1: always require captcha, 2: normal, 3: cannot be banned
    ],
    'login': [
        'id TEXT PRIMARY KEY',  # the id which is stored as a cookie on the browser; 43-digit base64
        'account TEXT',  # matching account id; 8-digit base64
        'valid TEXT',  # expiry date; %Y-%m-%d_%H-%M-%S
        'browser TEXT',  # information about user agent
    ],
    'mail': [
        'id TEXT PRIMARY KEY',  # id; 9-digit base64
        'name TEXT',  # same as account
        'mail TEXT',  # same as account
        'salt TEXT',  # same as account
        'hash TEXT',  # same as account
        'newsletter INTEGER',  # same as account
        'valid TEXT',  # expiry date; %Y-%m-%d_%H-%M-%S
        'code TEXT',  # code; 7-digit number as text
    ],
    'used_ids': [
        'id TEXT PRIMARY KEY',  # the id; usually base64
        'created TEXT',  # when this id came into use; %Y-%m-%d_%H-%M-%S
    ],
}

for _, (k, v) in enumerate(db_tables.items()):
    query_db(f"CREATE TABLE IF NOT EXISTS {k} ({', '.join(v)})")


########################################################################################################################
# DATES
########################################################################################################################


def get_current_time():
    return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


########################################################################################################################
# RANDOM
########################################################################################################################


def rand_base64(digits):
    while True:
        n = urlsafe_b64encode(urandom(digits)).decode()[:digits]
        result = query_db('SELECT * FROM used_ids WHERE id=?', (n,), True)
        if result is None:
            query_db('INSERT INTO used_ids VALUES (?, ?)', (n, get_current_time()))
            return n


def rand_base16(digits):
    while True:
        n = urandom(digits).hex()[:digits]
        result = query_db('SELECT * FROM used_ids WHERE id=?', (n,), True)
        if result is None:
            query_db('INSERT INTO used_ids VALUES (?, ?)', (n, get_current_time()))
            return n


def rand_salt():
    return urlsafe_b64encode(urandom(32)).decode()


########################################################################################################################
# ACCOUNT
########################################################################################################################


def is_signed_in(cookies):
    if 'qILs7nxM' in cookies:
        result = query_db('SELECT valid, browser FROM login WHERE id = ?', (cookies['qILs7nxM'],), True)
        if result is None:
            return False
        if result[0] >= get_current_time() and extract_browser(request.user_agent) == result[2]:
            return True
    return False


def account(cookies):
    unavailable = (False, None, '', 'Hell [Standard]', False, '____')
    if 'qILs7nxM' in cookies:
        result1 = query_db('select valid, account from login where id = ?', (cookies['qILs7nxM'],), True)
        if result1 is None:
            return unavailable
        if result1[0] < get_current_time():
            return unavailable
        result2 = query_db('select id, name, theme, payment, banned from accounts where id = ?', (result1[1],), True)
        if result2 is None:
            return unavailable
        return True, result2[0], result2[1], result2[2], result2[3] >= get_current_time(), result2[4]
    return unavailable


def is_banned(index, banned):
    return banned[index] == 'X' or banned[0] == 'X'


########################################################################################################################
# PROTECTION
########################################################################################################################


def random_sleep():
    sleep(0.1 + uniform(0.0, 0.1))


def hash_password(password, salt):
    return urlsafe_b64encode(pbkdf2_hmac('sha3_512', urlsafe_b64decode(environ['HASH_PEPPER_1']) + password.encode() +
                                         urlsafe_b64decode(environ['HASH_PEPPER_2']), urlsafe_b64decode(salt),
                                         int(environ['HASH_ITERATIONS']))).decode()


def hash_ip(ip):
    return urlsafe_b64encode(sha256(bytes(map(int, ip.split('.')))).digest()).decode()


def scan_request(r):
    ip = r.access_route[-1]
    user_agent = r.user_agent.string
    path = r.full_path
    if r.remote_addr not in ['127.0.0.1', '0.0.0.0', None]:
        access_log.info(f'{hash_ip(ip)}\t{0}\t{int(is_signed_in(r.cookies))}\t{r.method}\t{path}\t{user_agent}')
        return 0
    score = query_db('SELECT score FROM ipv4 WHERE address = ?', (ip,)).fetchone()
    if score is None:
        score = 2
        query_db('INSERT INTO ipv4 VALUES (?, ?, ?)', (ip, 'unknown', 2))
    else:
        score = score[0]
    before = score

    if 0 < score < 3:
        instance = AnalyzerRequest(r, ['controlpanel'])
        bot_rating = instance.bot()
        search_rating = instance.search_engine()
        malicious_rating = instance.malicious()
        if (bot_rating > 0.8) and (search_rating < 0.5):
            score = min(score, 1)
        if malicious_rating > 0.4:
            score = min(score, 1)
        if malicious_rating > 0.8:
            score = min(score, 0)

    if before != score:
        query_db('UPDATE ipv4 SET score = ? WHERE address = ?', (score, ip))

    access_log.info(f'{hash_ip(ip)}\t{score}\t{int(is_signed_in(r.cookies))}\t{r.method}\t{path}\t{user_agent}')
    return score


def extract_browser(agent):
    return f"{agent.platform}-{agent.browser}"


########################################################################################################################
# E-MAIL
########################################################################################################################


def send_mail(address, subject, message_plain, message):
    smtp_server = environ['SMTP_SERVER']
    smtp_port = int(environ['SMTP_PORT'])
    sender_email = environ['SMTP_ADDRESS']
    context = create_default_context()
    server = None
    m = MIMEMultipart('alternative')
    m['Subject'] = subject
    m['From'] = sender_email
    m['To'] = address
    part1 = MIMEText(message_plain, 'plain')
    part2 = MIMEText(message, 'html')
    m.attach(part1)
    m.attach(part2)
    try:
        server = SMTP(smtp_server, smtp_port)
        server.starttls(context=context)
        server.login(sender_email, environ['SMTP_PASSWORD'])
        server.sendmail(sender_email, address, m.as_string())
    except Exception as error_:
        logging_log(LOG_ERROR, e)
        return error_
    finally:
        server.quit()
    return None


########################################################################################################################
# CHECK FORM INFO
########################################################################################################################


def form_require(keys, form):
    return all([key in form for key in keys])


########################################################################################################################
# RETURN ERROR
########################################################################################################################


def error(code, event, args=None):
    if args is None:
        args = []
    codes = {
        400: 'Bad Request: Cannot process due to client error.',
        401: 'Unauthorized: No permission',
        402: 'Payment Required: No payment',
        403: 'Forbidden: Request forbidden',
        404: 'Not Found: Nothing matches the given URI',
        405: 'Method Not Allowed: Specified method is invalid for this server.',
        406: 'Not Acceptable: URI not available in preferred format.',
        407: 'Proxy Authentication Required: You must authenticate with this proxy before proceeding.',
        408: 'Request Timeout: Request timed out; try again later.',
        409: 'Conflict: A conflict between the request and the current state of the server exists.',
        410: 'Gone: URI no longer exists and has been permanently removed.',
        411: 'Length Required: Client must specify Content-Length.',
        412: 'Precondition Failed: Precondition in headers is false.',
        413: 'Request Entity Too Large: Entity is too large.',
        414: 'Request-URI Too Long: URI is too long.',
        415: 'Unsupported Media Type: Entity body in unsupported format.',
        416: 'Requested Range Not Satisfiable: Cannot satisfy request range.',
        417: 'Expectation Failed: Expect condition could not be satisfied.',
        422: 'Unprocessable Entity: Request was well-formed but was unable to be processed.',
        500: 'Internal Server Error: The server has encountered a situation it does not know how to handle.',
        501: 'Not Implemented: Server does not support this operation',
        502: 'Bad Gateway: Invalid responses from another server/proxy.',
        503: 'Service Unavailable: The server cannot process the request due to a high load',
        504: 'Gateway Timeout: The gateway server did not receive a timely response',
        505: 'HTTP Version Not Supported: Cannot fulfill request.',
    }
    if code in codes:
        status = f"{code} - {codes[code]}"
    else:
        status = str(code)
    title, message = '', ''
    match event:
        case 'banned':
            messages = [
                'Ihr Konto wurde vom*von der Betreiber*in gesperrt.',
                'Der*die Betreiber*in hat festgelegt, dass Sie keine Änderungen an den Kalendern vornehmen dürfen.',
                'Der*die Betreiber*in hat festgelegt, dass Sie keine Kommentare schreiben dürfen.',
                'Der*die Betreiber*in hat festgelegt, dass Sie keine Dateien hochladen und keine Karteikarten '
                'erstellen dürfen.'
            ]
            titles = [
                'Konto gesperrt',
                'Aktion verboten',
                'Aktion verboten',
                'Aktion verboten'
            ]
            if len(args) >= 1:
                message = messages[args[0]]
                title = titles[args[0]]
            else:
                message = messages[0]
                title = titles[args[0]]
            message += ' Für mehr Informationen können Sie den*die Betreiber*in kontaktieren.'
        case 'form-missing':
            title, message = 'Fehlendes Eingabefeld', 'Mindestens ein erforderliches Eingabefeld wurde nicht an den ' \
                                                      'Server übermittelt.'
        case 'custom':
            title, message = args[0], args[1]
        case '_':
            title, message = 'Fehler', 'Ein Fehler ist aufgetreten.'
    request_errors_log.log(LOG_ERROR, '|'.join(['', status, title, message, '']))
    return render_template('_error.html', status=status, title=title, message=message), code


########################################################################################################################
# BEFORE REQUEST
########################################################################################################################


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=64)
    score = scan_request(request)
    if score == 0:
        return render_template('_banned.html', ip=request.access_route[-1]), 403


########################################################################################################################
# RESOURCE FILES
########################################################################################################################


@app.route('/src/<path:file>', methods=['GET'])
def route_src(file):
    return send_from_directory(join(app.root_path, 'static'), file)


@app.route('/src/<theme>', methods=['GET'])
def route_stylesheets(theme):
    theme = theme.replace('.css', '')
    if theme not in _THEMES:
        theme = 'Hell [Standard]'
    with open(join(app.root_path, 'resources', 'stylesheet.css'), 'r', encoding='utf-8') as f:
        template = f.read()
    for i in _THEMES[theme]:
        template = template.replace(f"§{i}§", _THEMES[theme][i])
    set_cookie = False
    try:
        scale = int(request.cookies.get('scale-factor', '1.0'))
    except ValueError:
        scale = 1.0
        set_cookie = True
    template = template.replace('§scale§', str(scale))
    resp = make_response(template, 200)
    resp.mimetype = 'text/css'
    if set_cookie:
        resp.set_cookie('scale-factor', str(scale))
    return resp


########################################################################################################################
# MAIN PAGES
########################################################################################################################


@app.route('/', methods=['GET'])
def root():
    signed_in, acc, name, theme, paid, banned = account(request.cookies)
    if is_banned(0, banned):
        return error(403, 'banned', [0])
    search_engine = 'DuckDuckGo'
    if signed_in:
        result = query_db('SELECT search_engine FROM account WHERE id=?', (acc,), True)

        if result is not None:
            search_engine = result[0]
    return render_template('_root.html', account=name, signed_in=signed_in, search_engine=search_engine)


@app.route('/search', methods=['POST'])
def route_search():
    signed_in, acc, name, theme, paid, banned = account(request.cookies)
    if is_banned(0, banned):
        return error(403, 'banned', [0])
    if not form_require(['q'], request.form):
        return error(400, 'form-missing')
    search_engine = 'DuckDuckGo'
    if signed_in:
        result = query_db('SELECT search_engine FROM account WHERE id=?', (acc,), True)
        if result is not None:
            search_engine = result[0]
    return redirect(_SEARCH_ENGINES.get(search_engine, 'DuckDuckGo')['url']
                    .replace('%s', quote(request.form.get('q', '').replace(' ', '+'), '+')).replace('%%', '%'))


@app.route('/neuigkeiten', methods=['GET'])
def route_neuigkeiten():
    signed_in, acc, name, theme, paid, banned = account(request.cookies)
    if is_banned(0, banned):
        return error(403, 'banned', [0])
    return render_template('neuigkeiten.html', account=name, signed_in=signed_in)


########################################################################################################################
# ACCOUNT
########################################################################################################################


@app.route('/konto/registrieren', methods=['GET'])
def route_konto_registrieren():
    signed_in, acc, name, theme, paid, banned = account(request.cookies)
    if is_banned(0, banned):
        return error(403, 'banned', [0])
    if signed_in:
        return redirect('/')
    return render_template('konto_registrieren.html', account=name, signed_in=signed_in)


@app.route('/konto/registrieren2', methods=['POST'])
def route_konto_registrieren2():
    signed_in, acc, name, theme, paid, banned = account(request.cookies)
    if is_banned(0, banned):
        return error(403, 'banned', [0])
    if signed_in:
        return redirect('/')
    random_sleep()
    form = dict(request.form)
    required = {
        'name': ['Name', 2, 64],
        'mail': ['E-Mail', 8, 64],
        'password': ['Passwort', 8, 128],
        'password-repeat': ['Passwort wiederholen', 8, 128]
    }
    for _, (key, val) in enumerate(required.items()):
        if key not in form:
            return error(400, 'custom', ['Fehlendes Eingabefeld', f"Das Eingabefeld '{val[0]}' wurde nicht an den "
                                                                  f"Server übermittelt."])
        length = form[key]
        if length < val[1]:
            return error(422, 'custom', ['Ungültiges Eingabefeld', f"Der Inhalt des Eingabefeldes '{val[0]}' ist zu "
                                                                   f"kurz."])
        if length > val[1]:
            return error(422, 'custom', ['Ungültiges Eingabefeld', f"Der Inhalt des Eingabefeldes '{val[0]}' ist zu "
                                                                   f"lang."])
    if 'agreement' not in form:
        return error(400, 'custom', ['Fehlendes Eingabefeld', f"Sie müssen die Allgemeinen Geschäftsbedingungen sowie "
                                                              f"die Datenschutzrichtlinien lesen und akzeptieren."])
    for i in ['name', 'mail']:
        for j in ['<', '>', '"', '&', "'", ';']:
            if j in i:
                return error(422, 'custom', ['Ungültiges Eingabefeld', f"Das Eingabefeld {required[i]} enthält "
                                                                       f"Zeichen, welche auf einen Hacker*innenangriff "
                                                                       f"hindeuten. Ihre Anfrage wird deshalb nicht "
                                                                       f"bearbeitet."])
    if not form['mail'].endswith('@sluz.ch'):
        return error(422, 'custom', ['Ungültige E-Mail Adresse', 'Die von Ihnen angegebene E-Mail Adresse endet nicht'
                                                                 ' auf @sluz.ch'])
    result = query_db('SELECT * FROM account WHERE mail=?', (form['mail'],), True)
    if result is not None:
        return error(409, 'custom', ['Konto existiert', f"Ein Konto mit der E-Mail Adresse '{form['mail']}' existiert "
                                                        f"schon. Klicken Sie in der Navigationsleiste auf 'Anmelden', "
                                                        f"um sich anzumelden."])
    mail_id = rand_base64(9)
    code = str(randint(1000000, 9999999))
    salt = rand_salt()
    query_db('INSERT INTO mail VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
             (mail_id, form['name'], form['mail'], salt, hash_password(form['password'], salt),
              int('newsletter' in form), (datetime.now() + timedelta(minutes=16)).strftime('%Y-%m-%d_%H-%M-%S'), code))
    if send_mail(form['mail'], 'E-Mail Verifikation [ksalp.ch]', f"Ihr Code lautet: {code}",
                 f"<html><head><meta charset=\"UTF-8\"></head><body><h1>Ihr Code lautet: {code}</h1>"
                 f"<p>Dieser Code ist 15 Minuten gültig</p></body></html>") is None:
        resp = make_response(render_template('konto_registrieren2.html', account=name, signed_in=signed_in))
        resp.set_cookie('mail_id', mail_id, timedelta(minutes=16))
        return resp
    return error(500, 'custom', ['Beim Versenden der Verifikations-E-Mail ist ein Fehler aufgetreten. Bitte '
                                 'kontaktieren Sie den*die Betreiber*in, damit dieser Fehler behoben werden kann.'])


@app.route('/konto/registrieren3', methods=['POST'])
def route_konto_registrieren3():
    signed_in, acc, name, theme, paid, banned = account(request.cookies)
    if is_banned(0, banned):
        return error(403, 'banned', [0])
    if signed_in:
        return redirect('/')
    random_sleep()
    form = dict(request.form)
    if 'code' not in form:
        return error(400, 'custom', 'Das Eingabefeld \'Code\' wurde nicht an den Server übermittelt.')
    if 'mail_id' not in request.cookies:
        return error(400, 'custom', 'Das Cookie \'mail_id\' konnte nicht gefunden werden. Bitte kontrollieren Sie, '
                                    'dass Cookies aktiviert sind und versuchen Sie den Registrationsprozess erneut.')
    result = query_db('SELECT id, name, mail, salt, hash, newsletter, valid, code FROM mail WHERE id=?',
                      (request.cookies['mail_id'],), True)
    if result is None:
        return error(404, 'custom', ['ID nicht gefunden', 'Einen Datenbank-Eintrag mit der ID, welche in Ihren '
                                                          'Cookies spezifiziert ist, konnte nicht gefunden werden.'])
    if result[6] < get_current_time():
        return error(400, 'custom', ['Code abgelaufen', 'Der Verifikations-Code ist abgelaufen. Bitte versuchen Sie '
                                                        'den Registrationsprozess erneut.'])
    if result[7] != form['code']:
        return error(400, 'custom', ['Falscher Code', 'Der Verifikations-Code stimmt nicht überein. Bitte versuchen'
                                                      ' Sie es erneut.'])
    query_db('UPDATE mail SET valid=? WHERE id=?', ('0000-00-00_00-00-00', request.cookies['mail_id']))
    acc_id = rand_base64(8)
    query_db('INSERT INTO account VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
             (acc_id, result[1], result[2], result[3], result[4], result[5], get_current_time(), 'Hell [Standard]', 0,
              '0000-00-00_00-00-00', '____', 'DuckDuckGo'))
    login = rand_base64(43)
    query_db('INSERT INTO login VALUES (?, ?, ?, ?)',
             (login, acc_id, (datetime.now() + timedelta(days=64)).strftime('%Y-%m-%d_%H-%M-%S'),
              extract_browser(request.user_agent)))
    resp = make_response(redirect('/'))
    resp.set_cookie('qILs7nxM', login, timedelta(days=64))
    return resp


@app.route('/konto/anmelden', methods=['GET'])
def route_konto_anmelden():
    signed_in, acc, name, theme, paid, banned = account(request.cookies)
    if is_banned(0, banned):
        return error(403, 'banned', [0])
    if signed_in:
        return redirect('/')
    return render_template('konto_anmelden.html', account=name, signed_in=signed_in)


@app.route('/konto/anmelden2', methods=['POST'])
def route_konto_anmelden2():
    signed_in, acc, name, theme, paid, banned = account(request.cookies)
    if is_banned(0, banned):
        return error(403, 'banned', [0])
    if signed_in:
        return redirect('/')
    random_sleep()
    form = dict(request.form)
    required = {
        'mail': 'E-Mail',
        'password': 'Passwort',
    }
    for _, (key, val) in enumerate(required.items()):
        if key not in form:
            return error(400, 'custom', ['Fehlendes Eingabefeld', f"Das Eingabefeld '{val}' wurde nicht an den "
                                                                  f"Server übermittelt."])
    result = query_db('SELECT id, mail, salt, hash FROM account WHERE mail=?', (form['mail']), True)
    fail = False
    if result is None:
        fail = True
    if hash_password(form['password'], result[2]) != result[3]:
        fail = True
    if fail:
        return error(422, 'custom', ['Falsches Passwort oder E-Mail',
                                     'Entweder wurde das falsche Passwort eingegeben oder ein Konto mit dieser E-Mail '
                                     'existiert nicht. Damit Hacker*innen nicht herausfinden können, ob eine '
                                     'spezifische E-Mail-Adresse registriert ist, wird keine genauere Auskunft '
                                     'gegeben.'])
    login = rand_base64(43)
    query_db('INSERT INTO login VALUES (?, ?, ?, ?)',
             (login, result[0], (datetime.now() + timedelta(days=64)).strftime('%Y-%m-%d_%H-%M-%S'),
              extract_browser(request.user_agent)))
    resp = make_response(redirect('/'))
    resp.set_cookie('qILs7nxM', login, timedelta(days=64))
    return resp


########################################################################################################################
# MAIN
########################################################################################################################


if __name__ == '__main__':
    try:
        app.run('0.0.0.0', 8000)
    except Exception as e:
        print(e)
        logging_log(LOG_ERROR, e)
