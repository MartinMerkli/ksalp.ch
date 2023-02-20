#!/usr/bin/env python3

########################################################################################################################
# IMPORTS
########################################################################################################################


from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime
from flask import Flask
from hashlib import pbkdf2_hmac
from logging import FileHandler as LogFileHandler, StreamHandler as LogStreamHandler, log as logging_log
from logging import basicConfig as log_basicConfig, getLogger as GetLogger, Formatter as LogFormatter
from logging import ERROR as LOG_ERROR, INFO as LOG_INFO
from os import environ, urandom
from os.path import exists, join
from random import uniform
from sqlite3 import connect as sqlite_connect
from time import sleep


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


conn = sqlite_connect('database.db')
db = conn.cursor()


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
        result = db.execute('select * from used_ids where id=?', (n,)).fetchone()
        if result is None:
            db.execute('insert into used_ids values (?, ?)', (n, get_current_time()))
            conn.commit()
            return n


def rand_base16(digits):
    while True:
        n = urandom(digits).hex()[:digits]
        result = db.execute('select * from used_ids where id=?', (n,)).fetchone()
        if result is None:
            db.execute('insert into used_ids values (?, ?)', (n, get_current_time()))
            conn.commit()
            return n


def rand_salt():
    return urlsafe_b64encode(urandom(32)).decode()


########################################################################################################################
# ACCOUNT
########################################################################################################################


def is_signed_in(cookies):
    if 'id' in cookies:
        result = db.execute('select valid from login where id = ?', (cookies['id'],)).fetchone()
        if result is None:
            return False
        if result[0] >= get_current_time():
            return True
    return False


########################################################################################################################
# PROTECTION
########################################################################################################################


def random_sleep():
    sleep(0.1 + uniform(0.0, 0.1))


def hash_password(password, salt):
    return urlsafe_b64encode(pbkdf2_hmac('sha3_512', urlsafe_b64decode(environ['HASH_PEPPER_1']) + password.encode() +
                                         urlsafe_b64decode(environ['HASH_PEPPER_2']), urlsafe_b64decode(salt),
                                         int(environ['HASH_ITERATIONS']))).decode()


########################################################################################################################
# MAIN
########################################################################################################################


if __name__ == '__main__':
    try:
        app.run('0.0.0.0', 8000)
    except Exception as e:
        print(e)
        logging_log(LOG_ERROR, e)
    try:
        conn.close()
    except Exception as e:
        print(e)
        logging_log(LOG_ERROR, e)
