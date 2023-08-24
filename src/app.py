#!/usr/bin/env python3

########################################################################################################################
# IMPORTS
########################################################################################################################


from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Flask, g, jsonify, make_response, redirect, render_template, request, send_from_directory, session
from hashlib import pbkdf2_hmac, sha3_256
from httpanalyzer import FlaskRequest as AnalyzerRequest
from json import loads as json_loads
from logging import FileHandler as LogFileHandler, StreamHandler as LogStreamHandler, log as logging_log
from logging import basicConfig as log_basicConfig, getLogger as GetLogger, Formatter as LogFormatter
from logging import ERROR as LOG_ERROR, INFO as LOG_INFO
from magic import from_file as type_from_file
from os import environ, urandom
from os.path import exists, getsize, join
from random import randint, uniform
from resources.src import EXTENSIONS as _EXTENSIONS, FILE_TYPES as _FILE_TYPES, GRADES as _GRADES
from resources.src import LANGUAGES as _LANGUAGES, THEMES as _THEMES, SEARCH_ENGINES as _SEARCH_ENGINES
from resources.src import SIZE_UNITS as _SIZE_UNITS, SUBJECTS as _SUBJECTS
from smtplib import SMTP
from ssl import create_default_context
from sqlite3 import connect as sqlite_connect
from time import sleep
from urllib.parse import quote
from werkzeug.utils import secure_filename


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

app.config.update(
    SESSION_COOKIE_NAME='__Host-session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(days=96),
)


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
        'class TEXT',  # class the person belongs to
        'grade TEXT',  # grade the person is in
    ],
    'comment': [
        'id TEXT PRIMARY KEY',  # comment id; 11-digit base64
        'content TEXT',  # the comment
        'author TEXT',  # account id
        'document TEXT',  # document id
        'posted TEXT',  # date; %Y-%m-%d_%H-%M-%S
    ],
    'document': [
        'id TEXT PRIMARY KEY',  # document id; 10-digit base64
        'title TEXT',  # short description
        'subject TEXT',  # subject code, 1 to 3 digits
        'description TEXT',  # additional information
        'class TEXT',  # class name
        'grade TEXT',  # '1' to '6' or '-'
        'language TEXT',  # 2-digit language code
        'owner TEXT',  # account id
        'edited TEXT',  # date; %Y-%m-%d_%H-%M-%S
        'created TEXT',  # date; %Y-%m-%d_%H-%M-%S
        'extension TEXT',  # file extension
        'mimetype TEXT',  # mimetype
        'size TEXT',  # human-readable size
    ],
    'ipv4': [
        'address TEXT PRIMARY KEY',  # IPv4 address
        'owner TEXT',  # organisation or physical location
        'score INTEGER',  # rating: 0: banned, 1: always require captcha, 2: normal, 3: cannot be banned
    ],
    'learn_exercise': [
        'id TEXT PRIMARY KEY',  # exercise id; {7-digit base64}.{12-digit base64}
        'set_id TEXT',  # id of the corresponding set; 7-digit base64
        'question TEXT',  # the question
        'answer TEXT',  # exemplary answer (may include steps)
        'answers TEXT',  # correct short answers for autocorrection; $-seperated list
        'frequency REAL',  # frequency of this exercise appearing; float
        'auto_check INTEGER',  # reserved for future use
    ],
    'learn_set': [
        'id TEXT PRIMARY KEY',  # set id; 7-digit base64
        'title TEXT',  # short description
        'subject TEXT',  # subject code, 1 to 3 digits
        'description TEXT',  # additional information
        'class TEXT',  # class name
        'grade TEXT',  # '1' to '6' or '-'
        'language TEXT',  # 2-digit language code
        'owner TEXT',  # account id
        'edited TEXT',  # date; %Y-%m-%d_%H-%M-%S
        'created TEXT',  # date; %Y-%m-%d_%H-%M-%S
    ],
    'learn_stat': [
        'id TEXT PRIMARY KEY',  # set id; 13-digit base64
        'exercise_id TEXT',  # exercise id
        'owner TEXT',  # account id
        'correct INTEGER',  # number of correct entries
        'wrong INTEGER',  # number of wrong entries
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
        'class TEXT',  # same as account
        'grade TEXT',  # same as account
        'valid TEXT',  # expiry date; %Y-%m-%d_%H-%M-%S
        'code TEXT',  # code; 7-digit number as text
    ],
    'used_ids': [
        'id TEXT PRIMARY KEY',  # the id; usually base64
        'created TEXT',  # when this id came into use; %Y-%m-%d_%H-%M-%S
    ],
}

with app.app_context():
    for _, (_k, _v) in enumerate(db_tables.items()):
        query_db(f"CREATE TABLE IF NOT EXISTS {_k} ({', '.join(_v)})")


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
        if not result:
            query_db('INSERT INTO used_ids VALUES (?, ?)', (n, get_current_time()))
            return n


def rand_base16(digits):
    while True:
        n = urandom(digits).hex()[:digits]
        result = query_db('SELECT * FROM used_ids WHERE id=?', (n,), True)
        if not result:
            query_db('INSERT INTO used_ids VALUES (?, ?)', (n, get_current_time()))
            return n


def rand_salt():
    return urlsafe_b64encode(urandom(32)).decode()


########################################################################################################################
# ACCOUNT
########################################################################################################################


def is_signed_in(session_cookie):
    if 'account' in session_cookie:
        result = query_db('SELECT valid, browser FROM login WHERE id = ?', (session_cookie['account'],), True)
        if not result:
            return False
        if result[0] >= get_current_time() and extract_browser(request.user_agent) == result[1]:
            return True
    return False


def is_banned(index, banned):
    return banned[index] == 'X' or banned[0] == 'X'


def account_name(acc):
    result = query_db('SELECT name FROM account WHERE id=?', (acc,), True)
    if not result:
        return ''
    return result[0]


def create_context(session_cookie):
    context = {
        'signed_in': False,
        'id': '',
        'theme': 'hell',
        'name': 'Nicht angemeldet',
        'payment': '2000-00-00',
        'paid': False,
        'banned': '____',
        'mail': '',
        'salt': '',
        'hash': '',
        'newsletter': False,
        'iframe': False,
        'search_engine': 'DuckDuckGo',
        'class_': '',
        'grade': ''
    }
    if 'account' in session_cookie:
        result1 = query_db('select valid, account from login where id = ?', (session_cookie['account'],), True)
        if not result1:
            return context
        if result1[0] < get_current_time():
            return context
        result2 = query_db('select id, name, mail, theme, payment, banned, newsletter, iframe, search_engine, class,'
                           ' grade, hash, salt from account where id = ?', (result1[1],), True)
        if not result2:
            return context
        result_order = ['id', 'name', 'mail', 'theme', 'payment', 'banned', 'newsletter', 'iframe', 'search_engine',
                        'class_', 'grade', 'hash', 'salt']
        for i, v in enumerate(result_order):
            context[v] = result2[i]
        context['signed_in'] = True
        context['paid'] = context['payment'] >= get_current_time()
    return context


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
    return urlsafe_b64encode(sha3_256(bytes(map(int, ip.split('.')))).digest()).decode()


def scan_request(r, session_cookie):
    ip = r.access_route[-1]
    user_agent = r.user_agent.string
    path = r.full_path
    if r.remote_addr not in ['127.0.0.1', '0.0.0.0', None]:
        access_log.info(f'{hash_ip(ip)}\t{0}\t{int(is_signed_in(session_cookie))}\t{r.method}\t{path}\t{user_agent}')
        return 0
    score = query_db('SELECT score, address FROM ipv4 WHERE address = ?', (ip,), True)
    if not score:
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

    access_log.info(f'{hash_ip(ip)}\t{score}\t{int(is_signed_in(session_cookie))}\t{r.method}\t{path}\t{user_agent}')
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
# LEARNING SETS
########################################################################################################################


def learning_set_upload(data, set_id):
    trigger_error = None
    if data[0] == '{':
        json_file = json_loads(data)
        content = {}
        for i in json_file:
            accept = True
            for j in ['question', 'answer', 'answers', 'frequency']:
                if j not in json_file[i]:
                    accept = False
            if accept:
                if (not isinstance(json_file[i]['question'], str)) \
                        or (not isinstance(json_file[i]['answer'], str)) \
                        or (not isinstance(json_file[i]['answers'], list)) \
                        or (not isinstance(json_file[i]['frequency'], float)):
                    accept = False
            if accept:
                content[set_id + '.' + rand_base64(12)] = json_file[i]
        if not content:
            trigger_error = 'Die Datei enthält keine zulässigen Aufgaben. Bitte überprüfen Sie den Inhalt der Datei.'
    else:
        content = {}
        lines = data.split('\n')
        for line in lines:
            if '; ' in line:
                parts = line.split('; ')
                content[set_id + '.' + rand_base64(12)] = {'question': parts[0], 'answer': parts[1].split('$')[0],
                                                           'answers': parts[1], 'frequency': 1.0}
        if not content:
            trigger_error = 'Die Datei enthält keine zulässigen Aufgaben. Bitte überprüfen Sie den Inhalt der Datei.'
    return content, trigger_error


########################################################################################################################
# RETURN ERROR
########################################################################################################################


def error(code, event='_', args=None):
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
        case 'premium':
            title, message = 'Kein Premium-Abo', 'Sie müssen ein Premium-Abonnement besitzen, um diese Funktion ' \
                                                 'nutzen zu können.'
        case 'account':
            title, message = 'Nicht angemeldet', 'Sie müssen angemeldet sein, um diese Funktion nutzen zu können.'
        case 'custom':
            title, message = args[0], args[1]
        case '_':
            title, message = 'Fehler', 'Ein Fehler ist aufgetreten.'
    request_errors_log.log(LOG_ERROR, '|'.join(['', status, title, message, '']))
    try:
        context = create_context(session)
    except Exception:
        context = create_context({})
    return render_template('_error.html', status=status, title=title, message=message, **context), code


########################################################################################################################
# BEFORE / AFTER REQUEST
########################################################################################################################


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=92)
    score = scan_request(request, session)
    if score == 0:
        return render_template('_banned.html', ip=request.access_route[-1]), 403


@app.after_request
def after_request(response):
    response.headers['server'] = 'nginx flask (GNU/Linux; ksalp.ch)'
    return response


########################################################################################################################
# RESOURCE FILES
########################################################################################################################


@app.route('/src/<path:file>', methods=['GET'])
def route_src(file):
    resp = send_from_directory(join(app.root_path, 'src'), file)
    if file in _FILE_TYPES:
        resp.mimetype = _FILE_TYPES[file]
    else:
        resp.mimetype = type_from_file(join(app.root_path, 'src', file), mime=True)
    return resp


@app.route('/stylesheets/<theme>', methods=['GET'])
def route_stylesheets(theme):
    theme = theme.replace('.css', '')
    if theme not in _THEMES:
        theme = 'hell'
    with open(join(app.root_path, 'resources', 'stylesheet.css'), 'r', encoding='utf-8') as f:
        template = f.read()
    for i in _THEMES[theme]:
        template = template.replace(f"§{i}§", _THEMES[theme][i])
    try:
        scale = float(session.get('scale-factor', '1.0'))
    except ValueError:
        scale = 1.0
        session['scale-factor'] = str(scale)
    template = template.replace('§scale§', str(scale))
    resp = make_response(template, 200)
    resp.mimetype = 'text/css'
    return resp


########################################################################################################################
# MAIN PAGES
########################################################################################################################


@app.route('/', methods=['GET'])
def root():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    return render_template('_root.html', **context)


@app.route('/search', methods=['POST'])
def route_search():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if not form_require(['q'], request.form):
        return error(400, 'form-missing')
    return redirect(_SEARCH_ENGINES.get(context['search_engine'], 'DuckDuckGo')['url']
                    .replace('%s', quote(request.form.get('q', '').replace(' ', '+'), '+')).replace('%%', '%'))


@app.route('/neuigkeiten', methods=['GET'])
def route_neuigkeiten():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    return render_template('neuigkeiten.html', **context)


@app.route('/melden/post', methods=['POST'])
def route_melden():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    form = dict(request.form)
    if not form_require(['type', 'id'], form):
        return error(400, 'form-missing')
    if context['signed_in']:
        author = context['id']
    else:
        author = request.access_route[-1]
    message = f"{int(context['signed_in'])}\t{author}\t{form['type']}\t{form['id']}"
    abuse_report_log.critical(message)
    send_mail(environ['SMTP_ADDRESS'], 'Abuse Report ' + get_current_time(), f"<p>{message}</p>", message)
    return render_template('melden.html', **context)


@app.route('/kommentar/neu', methods=['POST'])
def route_kommentar_neu():
    context = create_context(session)
    if is_banned(2, context['banned']):
        return error(403, 'banned', [0])
    if not context['signed_in']:
        return error(401, 'account')
    type_ = request.args.get('typ', '', type=str)
    id_ = request.args.get('id', '', type=str)
    content = request.form.get('comment', '')
    if (not id_) or (not content):
        return error(400, 'form-missing')
    if len(content) > 2048:
        return error(422, 'custom', ['Ungültiges Eingabefeld', 'Der Kommentar ist zu lang.'])
    query_db('INSERT INTO comment VALUES (?, ?, ?, ?, ?)', (rand_base64(11), content, context['id'], id_,
                                                            get_current_time()))
    match type_:
        case 'dokument':
            return redirect(f"/dokumente/vorschau/{id_}")
        case 'lernset':
            return redirect(f"/lernsets/vorschau/{id_}")
        case _:
            pass
    return redirect('/')


########################################################################################################################
# ACCOUNT
########################################################################################################################


@app.route('/konto/registrieren', methods=['GET'])
def route_konto_registrieren():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if context['signed_in']:
        return redirect('/')
    return render_template('konto_registrieren.html', **context, grades=_GRADES)


@app.route('/konto/registrieren2', methods=['POST'])
def route_konto_registrieren2():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if context['signed_in']:
        return redirect('/')
    random_sleep()
    form = dict(request.form)
    required = {
        'name': ['Name', 2, 64],
        'mail': ['E-Mail', 8, 64],
        'password': ['Passwort', 8, 128],
        'password-repeat': ['Passwort wiederholen', 8, 128],
        'class': ['Klasse', 1, 4],
        'grade': ['Klassenstufe', 0, 65536]
    }
    for _, (key, val) in enumerate(required.items()):
        if key not in form:
            return error(400, 'custom', ['Fehlendes Eingabefeld', f"Das Eingabefeld '{val[0]}' wurde nicht an den "
                                                                  f"Server übermittelt."])
        length = len(form[key])
        if length < val[1]:
            return error(422, 'custom', ['Ungültiges Eingabefeld', f"Der Inhalt des Eingabefeldes '{val[0]}' ist zu "
                                                                   f"kurz."])
        if length > val[2]:
            return error(422, 'custom', ['Ungültiges Eingabefeld', f"Der Inhalt des Eingabefeldes '{val[0]}' ist zu "
                                                                   f"lang."])
    if form['grade'] not in _GRADES:
        return error(422, 'form-missing')
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
    if result:
        return error(409, 'custom', ['Konto existiert', f"Ein Konto mit der E-Mail Adresse '{form['mail']}' existiert "
                                                        f"schon. Klicken Sie in der Navigationsleiste auf 'Anmelden', "
                                                        f"um sich anzumelden."])
    mail_id = rand_base64(9)
    code = str(randint(1000000, 9999999))
    salt = rand_salt()
    query_db('INSERT INTO mail VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
             (mail_id, form['name'], form['mail'], salt, hash_password(form['password'], salt),
              int('newsletter' in form), form['class'], form['grade'],
              (datetime.now() + timedelta(minutes=16)).strftime('%Y-%m-%d_%H-%M-%S'), code))
    if send_mail(form['mail'], 'E-Mail Verifikation [ksalp.ch]', f"Ihr Code lautet: {code}",
                 f"<html><head><meta charset=\"UTF-8\"></head><body><h1>Ihr Code lautet: {code}</h1>"
                 f"<p>Dieser Code ist 15 Minuten gültig</p></body></html>") is None:
        session['mail_id'] = mail_id
        return render_template('konto_registrieren2.html', **context)
    return error(500, 'custom', ['Beim Versenden der Verifikations-E-Mail ist ein Fehler aufgetreten. Bitte '
                                 'kontaktieren Sie den*die Betreiber*in, damit dieser Fehler behoben werden kann.'])


@app.route('/konto/registrieren3', methods=['POST'])
def route_konto_registrieren3():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if context['signed_in']:
        return redirect('/')
    random_sleep()
    form = dict(request.form)
    if 'code' not in form:
        return error(400, 'custom', 'Das Eingabefeld \'Code\' wurde nicht an den Server übermittelt.')
    if 'mail_id' not in session:
        return error(400, 'custom', 'Das Cookie \'mail_id\' konnte nicht gefunden werden. Bitte kontrollieren Sie, '
                                    'dass Cookies aktiviert sind und versuchen Sie den Registrationsprozess erneut.')
    result = query_db('SELECT id, name, mail, salt, hash, newsletter, valid, code, class, grade FROM mail WHERE id=?',
                      (session['mail_id'],), True)
    if not result:
        return error(404, 'custom', ['ID nicht gefunden', 'Einen Datenbank-Eintrag mit der ID, welche in Ihren '
                                                          'Cookies spezifiziert ist, konnte nicht gefunden werden.'])
    if result[6] < get_current_time():
        return error(400, 'custom', ['Code abgelaufen', 'Der Verifikations-Code ist abgelaufen. Bitte versuchen Sie '
                                                        'den Registrationsprozess erneut.'])
    if result[7] != form['code']:
        return error(400, 'custom', ['Falscher Code', 'Der Verifikations-Code stimmt nicht überein. Bitte versuchen'
                                                      ' Sie es erneut.'])
    query_db('UPDATE mail SET valid=? WHERE id=?', ('0000-00-00_00-00-00', session['mail_id']))
    acc_id = rand_base64(8)
    query_db('INSERT INTO account VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
             (acc_id, result[1], result[2], result[3], result[4], result[5], get_current_time(),
              'hell', 0, '0000-00-00_00-00-00', '____', 'DuckDuckGo', result[8], result[9]))
    login = rand_base64(43)
    query_db('INSERT INTO login VALUES (?, ?, ?, ?)',
             (login, acc_id, (datetime.now() + timedelta(days=96)).strftime('%Y-%m-%d_%H-%M-%S'),
              extract_browser(request.user_agent)))
    session['account'] = login
    return redirect('/')


@app.route('/konto/anmelden', methods=['GET'])
def route_konto_anmelden():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if context['signed_in']:
        return redirect('/')
    return render_template('konto_anmelden.html', **context)


@app.route('/konto/anmelden2', methods=['POST'])
def route_konto_anmelden2():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if context['signed_in']:
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
    result = query_db('SELECT id, mail, salt, hash FROM account WHERE mail=?', (form['mail'],), True)
    fail = False
    if not result:
        fail = True
    elif hash_password(form['password'], result[2]) != result[3]:
        fail = True
    if fail:
        return error(422, 'custom', ['Falsches Passwort oder E-Mail',
                                     'Entweder wurde ein falsches Passwort eingegeben oder ein Konto mit dieser E-Mail '
                                     'existiert nicht. Damit Hacker*innen nicht herausfinden können, ob eine '
                                     'spezifische E-Mail-Adresse registriert ist, wird keine genauere Auskunft '
                                     'gegeben.'])
    login = rand_base64(43)
    query_db('INSERT INTO login VALUES (?, ?, ?, ?)',
             (login, result[0], (datetime.now() + timedelta(days=96)).strftime('%Y-%m-%d_%H-%M-%S'),
              extract_browser(request.user_agent)))
    session['account'] = login
    return redirect('/')


@app.route('/konto/abmelden', methods=['GET'])
def route_konto_abmelden():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if 'account' in session and context['signed_in']:
        query_db('DELETE FROM login WHERE id=?', (session['account'],))
    return redirect('/')


@app.route('/konto/einstellungen', methods=['GET'])
def route_konto_einstellungen():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if not context['signed_in']:
        return redirect('/konto/anmelden')
    try:
        scale = float(session.get('scale-factor', '1.0'))
    except ValueError:
        scale = 1.0
    return render_template('konto_einstellungen.html', **context, themes=list(_THEMES.keys()),
                           engines=list(_SEARCH_ENGINES.keys()), grades=_GRADES, scale=str(round(scale * 100)))


@app.route('/konto/einstellungen/<path:path>', methods=['GET', 'POST'])
def route_konto_einstellungen_(path: str):
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if not context['signed_in']:
        return redirect('/konto/anmelden')
    setting = path.split('/')
    match setting[0]:
        case 'password':
            form = dict(request.form)
            required = {
                'password': ['Passwort', 0, 1024],
                'password-new': ['neues Passwort', 8, 128],
                'password-new-repeat': ['neues Passwort wiederholen', 8, 128]
            }
            for _, (key, val) in enumerate(required.items()):
                if key not in form:
                    return error(400, 'custom', ['Fehlendes Eingabefeld',
                                                 f"Das Eingabefeld '{val[0]}' wurde nicht an den Server übermittelt."])
                length = len(form[key])
                if length < val[1]:
                    return error(422, 'custom', ['Ungültiges Eingabefeld',
                                                 f"Der Inhalt des Eingabefeldes '{val[0]}' ist zu kurz."])
                if length > val[2]:
                    return error(422, 'custom', ['Ungültiges Eingabefeld',
                                                 f"Der Inhalt des Eingabefeldes '{val[0]}' ist zu lang."])
            result = query_db('SELECT id, mail, salt, hash FROM account WHERE mail=?', (context['id'],), True)
            if not result:
                return error(404)
            if hash_password(form['password'], result[2]) != result[3]:
                return error(422, 'custom', ['Falsches Passwort', 'Sie haben ein falsches Passwort eingegeben. Bitte '
                                                                  'versuchen Sie es erneut.'])
            salt = rand_salt()
            query_db('UPDATE account SET salt=?, hash=? WHERE id=?',
                     (salt, hash_password(form['password-new'], salt), context['id']))
        case 'iframes':
            if len(setting) < 2:
                return error(400)
            if setting[1] == 'true':
                value = 1
            elif setting[1] == 'false':
                value = 0
            else:
                return error(400)
            query_db('UPDATE account SET iframe=? WHERE id=?', (value, context['id']))
        case 'scale':
            form = dict(request.form)
            if 'scale' not in form:
                return error(400, 'custom', ['Fehlendes Eingabefeld', f"Das Eingabefeld 'Skalierungsfaktor' wurde "
                                                                      f"nicht an den Server übermittelt."])
            try:
                scale = int(form['scale'])
            except ValueError:
                return error(400, 'custom', ['Ungültiger Wert', f"Der Wert des Eingabefeldes 'Skalierungsfaktor' kann "
                                                                f"nicht verstanden werden."])
            session['scale-factor'] = str(scale / 100)
        case 'newsletter':
            if len(setting) < 2:
                return error(400)
            if setting[1] == 'true':
                value = 1
            elif setting[1] == 'false':
                value = 0
            else:
                return error(400)
            query_db('UPDATE account SET newsletter=? WHERE id=?', (value, context['id']))
        case 'theme':
            if len(setting) < 2:
                return error(400)
            if setting[1] not in _THEMES:
                return error(400)
            if not context['paid']:
                return error(403, 'premium')
            query_db('UPDATE account SET theme=? WHERE id=?', (setting[1], context['id']))
        case 'search_engine':
            if len(setting) < 2:
                return error(400)
            if setting[1] not in _SEARCH_ENGINES:
                return error(400)
            query_db('UPDATE account SET search_engine=? WHERE id=?', (setting[1], context['id']))
        case 'class':
            form = dict(request.form)
            if 'class' not in form:
                return error(400, 'custom', ['Fehlendes Eingabefeld', f"Das Eingabefeld 'Klasse' wurde "
                                                                      f"nicht an den Server übermittelt."])
            if not(0 < len(form['class']) < 5):
                return error(422, 'form-missing')
            query_db('UPDATE account SET class=? WHERE id=?', (form['class'], context['id']))
        case 'grade':
            form = dict(request.form)
            if 'grade' not in form:
                return error(400, 'custom', ['Fehlendes Eingabefeld', f"Das Eingabefeld 'Klasse' wurde "
                                                                      f"nicht an den Server übermittelt."])
            if form['grade'] not in _GRADES:
                return error(422, 'form-missing')
            query_db('UPDATE account SET grade=? WHERE id=?', (form['grade'], context['id']))
        case _:
            return error(400)
    return redirect('/konto/einstellungen')


########################################################################################################################
# DOCUMENTS
########################################################################################################################


@app.route('/dokumente', methods=['GET'])
def route_dokumente():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    class_ = request.args.get('klasse', default='', type=str)
    grade_ = request.args.get('klassenstufe', default='', type=str)
    return render_template('dokumente.html', **context, show_class=not bool(class_), show_grade=not bool(grade_),
                           use_class_=class_, use_grade_=grade_)


@app.route('/dokumente/documents.json', methods=['GET'])
def route_dokumente_documents():
    class_ = request.args.get('class', default='', type=str)
    grade_ = request.args.get('grade', default='', type=str)
    indices = ['id', 'title', 'subject', 'description', 'class', 'grade', 'language', 'owner', 'edited', 'created',
               'extension', 'size']
    if class_:
        result = query_db(f"SELECT {', '.join(indices)} FROM document WHERE class=?", (class_,))  # noqa
    elif grade_:
        result = query_db(f"SELECT {', '.join(indices)} FROM document WHERE grade=?", (grade_,))  # noqa
    else:
        result = query_db(f"SELECT {', '.join(indices)} FROM document")  # noqa
    documents = []
    for _, val in enumerate(result):
        document = {}
        for i, v in enumerate(indices):
            document[v] = val[i]
        document['owner'] = account_name(document['owner'])
        documents.append(document)
    return jsonify(documents)


@app.route('/dokumente/vorschau/<string:doc_id>', methods=['GET'])
def route_dokumente_vorschau(doc_id):
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    result1 = query_db('SELECT title, subject, description, class, grade, language, owner, edited, created, extension, '
                       'size, mimetype FROM document WHERE id=?', (doc_id,), True)
    if not result1:
        return error(404)
    allow_iframe = False
    if context['signed_in']:
        allow_iframe = bool(context['iframe'])
    iframe_available = True  # temporary
    download = f"{secure_filename(result1[0])}.{result1[9].lower()}"
    comments = []
    result3 = query_db('SELECT id, content, author, posted FROM comment WHERE document=?', (doc_id,))
    for i in result3:
        comments.append([account_name(i[2]), i[3], i[0], i[1]])
    return render_template('dokumente_vorschau.html', **context, subject=result1[1], title=result1[0],
                           extension=result1[9].upper(), size=result1[10], edited1=result1[7].split('_')[0],
                           edited2=result1[7].split('_')[1].replace('-', ':'), created1=result1[8].split('_')[0],
                           created2=result1[8].split('_')[1].replace('-', ':'), author=account_name(result1[6]),
                           doc_class=result1[3], doc_grade=result1[4], doc_language=result1[5], document_id=doc_id,
                           download=download, allow_iframe=allow_iframe, iframe_available=iframe_available,
                           comments=comments, description=result1[2])


@app.route('/dokumente/dokument/<string:doc_id>/<path:_>', methods=['GET'])
def route_dokumente_dokument(doc_id, _):
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    result = query_db('SELECT mimetype FROM document WHERE id=?', (doc_id,), True)
    if not result:
        return error(404)
    resp = make_response(send_from_directory(join(app.root_path, 'users/documents'), doc_id))
    resp.mimetype = result[0]
    return resp


@app.route('/dokumente/neu', methods=['GET'])
def route_dokumente_neu():
    context = create_context(session)
    if is_banned(3, context['banned']):
        return error(403, 'banned', [3])
    if not context['signed_in']:
        return error(401, 'account')
    return render_template('dokumente_neu.html', **context, subjects=_SUBJECTS.items(), languages=_LANGUAGES,
                           grades=_GRADES)


@app.route('/dokumente/neu/post', methods=['POST'])
def route_dokumente_neu_post():
    context = create_context(session)
    if is_banned(3, context['banned']):
        return error(403, 'banned', [3])
    if not context['signed_in']:
        return error(401, 'account')
    form = dict(request.form)
    german_form_names = ['Titel', 'Fach', 'Sprache', 'Klasse', 'Klassenstufe', 'Beschreibung']
    for i, v in enumerate(['title', 'subject', 'language', 'class', 'grade', 'description']):
        if v not in form:
            return error(400, 'custom', ['Fehlende Eingabe',
                                         f"Das Eingabefeld '{german_form_names[i]}' wurde nicht ausgefüllt"])
    if len(form['title']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Titel' wurde nicht ausgefüllt"])
    if len(form['title']) > 64:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Titel' ist zu lang. "
                                                         f"({len(form['title'])} von 64 Zeichen)"])
    if len(form['description']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Beschreibung' wurde nicht ausgefüllt"])
    if len(form['description']) > 2048:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Beschreibung' ist zu lang. "
                                                         f"({len(form['description'])} von 64 Zeichen)"])
    if len(form['class']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Klasse' wurde nicht ausgefüllt"])
    if len(form['class']) > 4:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Klasse' ist zu lang. "
                                                         f"({len(form['class'])} von 4 Zeichen)"])
    if form['subject'] not in _SUBJECTS:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Fach' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    if form['language'] not in _LANGUAGES:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Sprache' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    if form['grade'] not in _GRADES:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Klassenstufe' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    if 'file' not in request.files:
        return error(400, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Datei' wurde nicht ausgefüllt"])
    doc_id = rand_base64(10)
    path = join(app.root_path, 'users/documents', doc_id)
    file = request.files['file']
    file.save(path)
    file.close()
    mimetype = type_from_file(path, mime=True)
    extension = _EXTENSIONS.get(mimetype, '---')
    file_size = getsize(path)
    exponent = 0
    while file_size >= 1000:
        file_size //= 1000
        exponent += 1
    size = f"{file_size} {_SIZE_UNITS[exponent]}"
    query_db('INSERT INTO document VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
             (doc_id, form['title'], form['subject'], form['description'], form['class'], form['grade'],
              form['language'], context['id'], get_current_time(), get_current_time(), extension, mimetype, size))
    return redirect(f"/dokumente/vorschau/{doc_id}")


@app.route('/dokumente/bearbeiten', methods=['GET'])
def route_dokumente_bearbeiten():
    context = create_context(session)
    if is_banned(3, context['banned']):
        return error(403, 'banned', [3])
    if not context['signed_in']:
        return error(401, 'account')
    doc_id = request.args.get('id', '', str)
    result = query_db('SELECT title, subject, description, class, grade, language, owner, edited, created, extension, '
                      'size, mimetype FROM document WHERE id=?', (doc_id,), True)
    if not result:
        return error(404)
    if result[6] != context['id']:
        return error(403, 'custom', ['Keine Berechtigung', 'Sie sind nicht berechtigt, diese Funktion zu nutzen.'])
    return render_template('dokumente_bearbeiten.html', **context, subject=result[1], title=result[0],
                           doc_class=result[3], doc_grade=result[4], doc_language=result[5], document_id=doc_id,
                           description=result[2])


@app.route('/dokumente/bearbeiten/post', methods=['GET'])
def route_dokumente_bearbeiten_post():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [3])
    if not context['signed_in']:
        return error(401, 'account')
    doc_id = request.args.get('id', '', str)
    result = query_db('SELECT owner, created FROM document WHERE id=?', (doc_id,), True)
    if not result:
        return error(404)
    if result[0] != context['id']:
        return error(403, 'custom', ['Keine Berechtigung', 'Sie sind nicht berechtigt, diese Funktion zu nutzen.'])
    form = dict(request.form)
    german_form_names = ['Titel', 'Fach', 'Sprache', 'Klasse', 'Klassenstufe', 'Beschreibung']
    for i, v in enumerate(['title', 'subject', 'language', 'class', 'grade', 'description']):
        if v not in form:
            return error(400, 'custom', ['Fehlende Eingabe',
                                         f"Das Eingabefeld '{german_form_names[i]}' wurde nicht ausgefüllt"])
    if len(form['title']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Titel' wurde nicht ausgefüllt"])
    if len(form['title']) > 64:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Titel' ist zu lang. "
                                                         f"({len(form['title'])} von 64 Zeichen)"])
    if len(form['description']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Beschreibung' wurde nicht ausgefüllt"])
    if len(form['description']) > 2048:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Beschreibung' ist zu lang. "
                                                         f"({len(form['description'])} von 64 Zeichen)"])
    if len(form['class']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Klasse' wurde nicht ausgefüllt"])
    if len(form['class']) > 4:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Klasse' ist zu lang. "
                                                         f"({len(form['class'])} von 4 Zeichen)"])
    if form['subject'] not in _SUBJECTS:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Fach' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    if form['language'] not in _LANGUAGES:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Sprache' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    if form['grade'] not in _GRADES:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Klassenstufe' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    if 'file' not in request.files:
        return error(400, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Datei' wurde nicht ausgefüllt"])
    path = join(app.root_path, 'users/documents', doc_id)
    file = request.files['file']
    file.save(path)
    file.close()
    mimetype = type_from_file(path, mime=True)
    extension = _EXTENSIONS.get(mimetype, '---')
    file_size = getsize(path)
    exponent = 0
    while file_size >= 1000:
        file_size //= 1000
        exponent += 1
    size = f"{file_size} {_SIZE_UNITS[exponent]}"
    query_db('UPDATE document SET title=?, subject=?, description=?, class=?, grade=?, language=?, edited=?, '
             'extension=?, mimetype=?, size=? WHERE id=?',
             (form['title'], form['subject'], form['description'], form['class'], form['grade'],
              form['language'], get_current_time(), extension, mimetype, size, doc_id))
    return redirect(f"/dokumente/vorschau/{doc_id}")


@app.route('/dokumente/klasse', methods=['GET'])
def route_dokumente_klasse():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if not context['signed_in']:
        return error(401, 'account')
    result = query_db('SELECT class FROM account WHERE id=?', (context['id'],), True)
    return redirect(f"/dokumente?klasse={result[0]}")


@app.route('/dokumente/klassenstufe', methods=['GET'])
def route_dokumente_klassenstufe():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if not context['signed_in']:
        return error(401, 'account')
    result = query_db('SELECT grade FROM account WHERE id=?', (context['id'],), True)
    return redirect(f"/dokumente?klassenstufe={result[0]}")


########################################################################################################################
# LEARNING SETS
########################################################################################################################


@app.route('/lernsets', methods=['GET'])
def route_lernsets():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    class_ = request.args.get('klasse', default='', type=str)
    grade_ = request.args.get('klassenstufe', default='', type=str)
    return render_template('lernsets.html', **context, show_class=not bool(class_), show_grade=not bool(grade_),
                           use_class_=class_, use_grade_=grade_)


@app.route('/lernsets/klasse', methods=['GET'])
def route_lernsets_klasse():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if not context['signed_in']:
        return error(401, 'account')
    result = query_db('SELECT class FROM account WHERE id=?', (context['id'],), True)
    return redirect(f"/lernsets?klasse={result[0]}")


@app.route('/lernsets/klassenstufe', methods=['GET'])
def route_lernsets_klassenstufe():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if not context['signed_in']:
        return error(401, 'account')
    result = query_db('SELECT grade FROM account WHERE id=?', (context['id'],), True)
    return redirect(f"/lernsets?klassenstufe={result[0]}")


@app.route('/lernsets/sets.json', methods=['GET'])
def route_lernsets_sets():
    class_ = request.args.get('class', default='', type=str)
    grade_ = request.args.get('grade', default='', type=str)
    sets_ = request.args.get('sets', default='', type=str)
    as_list = request.args.get('as_list', default=False, type=bool)
    sets = sets_.split('$')
    indices = ['id', 'title', 'subject', 'description', 'class', 'grade', 'language', 'owner', 'edited', 'created']
    if class_:
        result1 = query_db(f"SELECT {', '.join(indices)} FROM learn_set WHERE class=?", (class_,))  # noqa
    elif grade_:
        result1 = query_db(f"SELECT {', '.join(indices)} FROM learn_set WHERE grade=?", (grade_,))  # noqa
    elif sets_:
        allowed = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_$'
        for char in sets_:
            if char not in allowed:
                return 'error: request contains characters which are not allowed', 400
        query = []
        for i in sets:
            query.append(f"id='{i}'")
        result1 = query_db(f"SELECT {', '.join(indices)} FROM learn_set WHERE {' OR '.join(query)}")  # noqa
    else:
        result1 = query_db(f"SELECT {', '.join(indices)} FROM learn_set")  # noqa
    if as_list:
        learn_sets = []
        for _, val in enumerate(result1):
            learn_set = {}
            for i, v in enumerate(indices):
                learn_set[v] = val[i]
            learn_set['owner'] = account_name(learn_set['owner'])
            result2 = query_db('SELECT id FROM learn_exercise WHERE set_id=?', (learn_set['id'],))
            learn_set['size'] = '0'
            if result2:
                learn_set['size'] = str(len(result2))
            learn_sets.append(learn_set)
    else:
        learn_sets = {}
        for _, val in enumerate(result1):
            learn_set = {}
            for i, v in enumerate(indices):
                learn_set[v] = val[i]
            learn_set['owner'] = account_name(learn_set['owner'])
            result2 = query_db('SELECT id FROM learn_exercise WHERE set_id=?', (learn_set['id'],))
            learn_set['size'] = '0'
            if result2:
                learn_set['size'] = str(len(result2))
            learn_sets[learn_set['id']] = learn_set
    return jsonify(learn_sets)


@app.route('/lernsets/exercises.json', methods=['GET'])
def route_lernsets_exercises():
    sets_ = request.args.get('sets', default='', type=str)
    sets = sets_.split('$')
    indices = ['id', 'set_id', 'question', 'answer', 'answers', 'frequency', 'auto_check']
    if sets_:
        allowed = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_$'
        for char in sets_:
            if char not in allowed:
                return 'error: request contains characters that are not allowed', 400
        query = []
        for i in sets:
            query.append(f"set_id='{i}'")
        result = query_db(f"SELECT {', '.join(indices)} FROM learn_exercise WHERE {' OR '.join(query)}")  # noqa
    else:
        result = query_db(f"SELECT {', '.join(indices)} FROM learn_exercise")  # noqa
    exercises = {}
    for _, val in enumerate(result):
        exercise = {}
        for i, v in enumerate(indices):
            exercise[v] = val[i]
        exercises[exercise['id']] = exercise
    return jsonify(exercises)


@app.route('/lernsets/stats.json', methods=['GET'])
def route_lernsets_stats():
    context = create_context(session)
    if not context['signed_in']:
        return 'error: not signed-in', 401
    sets_ = request.args.get('sets', default='', type=str)
    sets = sets_.split('$')
    indices = ['id', 'exercise_id', 'correct', 'wrong']
    if sets_:
        allowed = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_$'
        for char in sets_:
            if char not in allowed:
                return 'error: request contains characters that are not allowed', 400
        query = []
        for i in sets:
            query.append(f"id='{i}'")
        result = query_db(f"SELECT {', '.join(indices)} FROM learn_stat WHERE owner=? OR "  # noqa
                          f"({' OR '.join(query)})", (context['id'],))  # noqa
    else:
        result = query_db(f"SELECT {', '.join(indices)} FROM learn_stat")  # noqa
    stats = {}
    for _, val in enumerate(result):
        stat = {}
        for i, v in enumerate(indices):
            stat[v] = val[i]
        stats[stat['id']] = stat
    return jsonify(stats)


@app.route('/lernsets/start', methods=['POST'])
def route_lernsets_start():
    form = dict(request.form)
    for i in ['submit', 'submit1', 'submit2']:
        if i in form:
            del form[i]
    selected_sets = form.keys()
    return redirect(f"/lernsets/lernen/{'$'.join(selected_sets)}")


@app.route('/lernsets/statistics', methods=['POST'])
def route_lernsets_statistics():
    context = create_context(session)
    if not context['signed_in']:
        return 'error: not signed-in', 401
    try:
        data = request.json()
    except Exception:
        return 'error: request is not json', 400
    for i in ['exercise_id', 'answer', 'correct']:
        if i not in data:
            return 'error: request is malformed', 400
    result0 = query_db('SELECT id FROM learn_stat WHERE owner=? AND exercise_id=?', (context['id'],), True)
    if result0:
        stat_id = result0[0]
    else:
        stat_id = rand_base64(13)
        query_db('INSERT INTO learn_stat VALUES (?, ?, ?, 0, 0)', (stat_id, data['exercise_id'], context['id']))
    if data['correct']:
        query_db('UPDATE learn_stat SET correct = correct + 1 WHERE id=?', (stat_id,))
    else:
        query_db('UPDATE learn_stat SET wrong = wrong + 1 WHERE id=?', (stat_id,))
    return 'success', 200


@app.route('/lernsets/neu', methods=['GET'])
def route_lernsets_neu():
    context = create_context(session)
    if is_banned(3, context['banned']):
        return error(403, 'banned', [3])
    if not context['signed_in']:
        return error(401, 'account')
    return render_template('lernsets_neu.html', **context, subjects=_SUBJECTS.items(), languages=_LANGUAGES,
                           grades=_GRADES)


@app.route('/lernsets/neu/post', methods=['POST'])
def route_lernsets_neu_post():
    context = create_context(session)
    if is_banned(3, context['banned']):
        return error(403, 'banned', [3])
    if not context['signed_in']:
        return error(401, 'account')
    form = dict(request.form)
    german_form_names = ['Titel', 'Fach', 'Sprache', 'Klasse', 'Klassenstufe', 'Beschreibung']
    for i, v in enumerate(['title', 'subject', 'language', 'class', 'grade', 'description']):
        if v not in form:
            return error(400, 'custom', ['Fehlende Eingabe',
                                         f"Das Eingabefeld '{german_form_names[i]}' wurde nicht ausgefüllt"])
    if len(form['title']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Titel' wurde nicht ausgefüllt"])
    if len(form['title']) > 64:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Titel' ist zu lang. "
                                                         f"({len(form['title'])} von 64 Zeichen)"])
    if len(form['description']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Beschreibung' wurde nicht ausgefüllt"])
    if len(form['description']) > 2048:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Beschreibung' ist zu lang. "
                                                         f"({len(form['description'])} von 64 Zeichen)"])
    if len(form['class']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Klasse' wurde nicht ausgefüllt"])
    if len(form['class']) > 4:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Klasse' ist zu lang. "
                                                         f"({len(form['class'])} von 4 Zeichen)"])
    if form['subject'] not in _SUBJECTS:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Fach' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    if form['language'] not in _LANGUAGES:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Sprache' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    if form['grade'] not in _GRADES:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Klassenstufe' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    set_id = rand_base64(7)
    content = {}
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            data = file.stream.read().decode()
            file.close()
            try:
                content, trigger_error = learning_set_upload(data, set_id)
            except Exception as err:
                return error(403, 'custom', ['Ein Fehler ist aufgetreten.',
                                             f"Während dem erstellen des Lernsets ist folgender, unbekannter Fehler "
                                             f"aufgetreten: \"{err}\""])
            if trigger_error is not None:
                return error(422, 'custom', ['Ein Fehler ist aufgetreten.',
                                             f"Während dem erstellen des Lernsets ist folgender, unbekannter Fehler "
                                             f"aufgetreten: \"{trigger_error}\""])
    query_db('INSERT INTO learn_set VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
             (set_id, form['title'], form['subject'], form['description'], form['class'], form['grade'],
              form['language'], context['id'], get_current_time(), get_current_time()))
    for _, (ex_id, v) in enumerate(content.items()):
        query_db('INSERT INTO learn_exercise VALUES (?, ?, ?, ?, ?, ?, ?)', (ex_id, set_id, v['question'], v['answer'],
                                                                             v['answers'], v['frequency'], 0))
    return redirect('/lernsets')


@app.route('/lernsets/bearbeiten', methods=['GET'])
def route_lernsets_bearbeiten():
    context = create_context(session)
    if is_banned(3, context['banned']):
        return error(403, 'banned', [3])
    if not context['signed_in']:
        return error(401, 'account')
    set_id = request.args.get('id', '', str)
    result = query_db('SELECT title, subject, description, class, grade, language, owner, edited, created '
                      'FROM learn_set WHERE id=?', (set_id,), True)
    if not result:
        return error(404)
    if result[6] != context['id']:
        return error(403, 'custom', ['Keine Berechtigung', 'Sie sind nicht berechtigt, diese Funktion zu nutzen.'])
    return render_template('lernsets_bearbeiten.html', **context, subject=result[1], title=result[0],
                           set_class=result[3], set_grade=result[4], set_language=result[5], set_id=set_id,
                           description=result[2])


@app.route('/lernsets/bearbeiten/post', methods=['GET'])
def route_lernsets_bearbeiten_post():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [3])
    if not context['signed_in']:
        return error(401, 'account')
    set_id = request.args.get('id', '', str)
    result = query_db('SELECT owner, created FROM learn_set WHERE id=?', (set_id,), True)
    if not result:
        return error(404)
    if result[0] != context['id']:
        return error(403, 'custom', ['Keine Berechtigung', 'Sie sind nicht berechtigt, diese Funktion zu nutzen.'])
    form = dict(request.form)
    german_form_names = ['Titel', 'Fach', 'Sprache', 'Klasse', 'Klassenstufe', 'Beschreibung']
    for i, v in enumerate(['title', 'subject', 'language', 'class', 'grade', 'description']):
        if v not in form:
            return error(400, 'custom', ['Fehlende Eingabe',
                                         f"Das Eingabefeld '{german_form_names[i]}' wurde nicht ausgefüllt"])
    if len(form['title']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Titel' wurde nicht ausgefüllt"])
    if len(form['title']) > 64:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Titel' ist zu lang. "
                                                         f"({len(form['title'])} von 64 Zeichen)"])
    if len(form['description']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Beschreibung' wurde nicht ausgefüllt"])
    if len(form['description']) > 2048:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Beschreibung' ist zu lang. "
                                                         f"({len(form['description'])} von 64 Zeichen)"])
    if len(form['class']) == 0:
        return error(422, 'custom', ['Fehlende Eingabe', f"Das Eingabefeld 'Klasse' wurde nicht ausgefüllt"])
    if len(form['class']) > 4:
        return error(422, 'custom', ['Zu lange Eingabe', f"Ihre Angabe für das Eingabefeld 'Klasse' ist zu lang. "
                                                         f"({len(form['class'])} von 4 Zeichen)"])
    if form['subject'] not in _SUBJECTS:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Fach' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    if form['language'] not in _LANGUAGES:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Sprache' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    if form['grade'] not in _GRADES:
        return error(422, 'custom', ['Eingabe nicht erlaubt', f"Ihre Angabe für das Eingabefeld 'Klassenstufe' erfüllt "
                                                              f"nicht die erforderlichen Bedingungen."])
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            data = file.stream.read().decode()
            file.close()
            try:
                content, trigger_error = learning_set_upload(data, set_id)
            except Exception as err:
                return error(403, 'custom', ['Ein Fehler ist aufgetreten.',
                                             f"Während dem erstellen des Lernsets ist folgender, unbekannter Fehler "
                                             f"aufgetreten: \"{err}\""])
            if trigger_error is not None:
                return error(422, 'custom', ['Ein Fehler ist aufgetreten.',
                                             f"Während dem erstellen des Lernsets ist folgender, unbekannter Fehler "
                                             f"aufgetreten: \"{trigger_error}\""])
            query_db('DELETE FROM learn_exercise WHERE set_id=?', (set_id,))
            for _, (ex_id, v) in enumerate(content.items()):
                query_db('INSERT INTO learn_exercise VALUES (?, ?, ?, ?, ?, ?, ?)',
                         (ex_id, set_id, v['question'], v['answer'],
                          v['answers'], v['frequency'], 0))
    query_db('UPDATE learn_set SET title=?, subject=?, description=?, class=?, grade=?, language=?, edited=? '
             'WHERE id=?', (form['title'], form['subject'], form['description'], form['class'], form['grade'],
                            form['language'], get_current_time(), set_id))
    return redirect('/lernsets')


@app.route('/lernsets/lernen/', methods=['GET'])
def route_lernsets_lernen_():
    return error(400, 'custom', ['Keine Auswahl',
                                 'Sie haben keine Lernsets ausgewählt. Das Lernprogramm kann nicht gestartet werden'])


@app.route('/lernsets/lernen/<string:sets>', methods=['GET'])
def route_lernsets_lernen(sets):
    context = create_context(session)
    if is_banned(3, context['banned']):
        return error(403, 'banned', [3])
    if not sets:
        return error(400, 'custom', ['Keine Auswahl',
                                     'Sie haben keine Lernsets ausgewählt. Das Lernprogramm kann nicht gestartet werden'])
    return render_template('lernsets_lernen.html', **context, sets=sets)


@app.route('/lernsets/vorschau/<string:set_id>', methods=['GET'])
def route_lernsets_vorschau(set_id):
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    result1 = query_db('SELECT title, subject, description, class, grade, language, owner, edited, created FROM learn_set '
                       'WHERE id=?', (set_id,), True)
    if not result1:
        return error(404)
    lernset = []
    result2 = query_db('SELECT id, question, answer FROM learn_exercise WHERE set_id=?', (set_id,))
    stats = {}
    if context['signed_in']:
        query = []
        for v in result2:
            query.append(f"exercise_id='{v[0]}'")
        if len(query) > 0:
            result3 = query_db(f"SELECT exercise_id, correct, wrong FROM learn_stat WHERE owner=? "  # noqa
                               f"AND ({' OR '.join(query)})", (context['id'],))
            for v in result3:
                stats[v[0]] = {'true': v[1], 'false': v[2]}
    for v in result2:
        if context['signed_in']:
            cur_stats = stats.get(v[0], {'true': 0, 'false': 0})
        else:
            cur_stats = {'true': 0, 'false': 0}
        lernset.append([v[0], v[1], v[2], cur_stats['true'], cur_stats['false']])
    comments = []
    result3 = query_db('SELECT id, content, author, posted FROM comment WHERE document=?', (set_id,))
    for i in result3:
        comments.append([account_name(i[2]), i[3], i[0], i[1]])
    return render_template('lernsets_vorschau.html', **context, subject=result1[1], title=result1[0], comments=comments,
                           edited1=result1[7].split('_')[0], edited2=result1[7].split('_')[1].replace('-', ':'),
                           created1=result1[8].split('_')[0], created2=result1[8].split('_')[1].replace('-', ':'),
                           author=account_name(result1[6]), size=len(result2), lernset=lernset, lernset_id=set_id)


@app.route('/lernsets/statistics/delete', methods=['POST'])
def route_lernsets_statistics_delete():
    context = create_context(session)
    if is_banned(0, context['banned']):
        return error(403, 'banned', [0])
    if not context['signed_in']:
        return error(401, 'account')
    form = dict(request.form)
    if 'id' not in form:
        return error(400, 'form-missing')
    result = query_db('SELECT id FROM learn_exercise WHERE set_id=?', (form['id']))
    if not result:
        return error(404)
    query = []
    for v in result:
        query.append(f"exercise_id='{v[0]}'")
    query_db(f"DELETE FROM learn_stat WHERE owner=? AND ({' OR '.join(query)})", (context['id'],))  # noqa
    return redirect(f"/lernsets/vorschau/{form['id']}")


########################################################################################################################
# MAIN
########################################################################################################################


if __name__ == '__main__':
    try:
        app.run('0.0.0.0', 8000)
    except Exception as e:
        print(e)
        logging_log(LOG_ERROR, e)
