#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Email Manager  --  نسخة محسّنة
====================================
مدير حملات البريد الإلكتروني: حسابات SMTP/IMAP متعددة، موظفون، قوالب،
حملات إرسال على دفعات مجدولة، صندوق وارد مع رد فردي / رد تلقائي.

أهم ما تم إصلاحه/تحسينه مقارنة بالنسخة القديمة
------------------------------------------------
1.  رسائل flash أصبحت تُعرض فعلاً (Jinja layout + بلوك للتنبيهات).
2.  المُجدوِل (scheduler) يقرأ الإعدادات في كل دورة، فتغيير الفترة أو
    تفعيل/إيقاف الجدولة يسري فوراً بدون إعادة تشغيل، ويسجّل آخر تشغيل.
3.  مفهوم "الحملات": كل حملة لها قالب + قائمة مستلمين بحالة مستقلة
    (pending / sent / failed)، فيمكن إعادة الإرسال وإعادة محاولة الفاشل
    وتشغيل أكثر من حملة، بدل شرط "لم يُرسل له إطلاقاً".
4.  كل مخرجات HTML تمر عبر Jinja مع auto-escape → لا حقن HTML ولا كسر
    الصفحة بسبب الأقواس { } في نص المستخدم.
5.  كلمات مرور الحسابات تُشفّر على القرص عبر Fernet (لو مكتبة cryptography
    متاحة)، مع ترحيل تلقائي للصفوف القديمة المخزّنة كنص صريح.
6.  إعداد SMTP صار صريحاً: STARTTLS / SSL / بدون تشفير، بدل منطق معكوس.
7.  IMAP: فك ترميز العناوين (MIME encoded-words)، تحليل عنوان المرسل،
    كشف charset، منع التكرار عبر Message-ID، تخزين التاريخ كـ ISO.
8.  صندوق الوارد: صفحة تفاصيل + رد فردي + ربط المرسل بالموظف + فلترة.
9.  قاعدة البيانات: WAL + مفاتيح أجنبية + busy_timeout + فهارس +
    ترحيل آمن (PRAGMA user_version) يضيف الأعمدة الناقصة دون فقد بيانات.
10. تسجيل (logging) لملف + الطرفية، ومفتاح جلسة ثابت، وإعداد عبر متغيرات بيئة.
11. توقيع لكل موظف: حقول (المنصب/القسم/الهاتف) + قالب توقيع عام يُملأ لكل واحد،
    أو توقيع خاص يدوي لكل موظف يتجاوز القالب.
12. حماية من البلوك: تأخير عشوائي بين كل رسالة، حد ساعي/يومي لكل حساب،
    ترتيب مستلمين عشوائي + اختيار حساب مرسِل عشوائي، وحفظ نسخة في مجلد Sent.
    لا تعمل دفعتان في وقت واحد (قفل)، والتقدّم يُحفظ بعد كل رسالة.
"""

import os
import csv
import io
import json
import re
import glob
import shutil
import subprocess
import base64
import ssl
import time
import random
import logging
import sqlite3
import smtplib
import imaplib
import threading
import webbrowser
from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import (parseaddr, parsedate_to_datetime, formataddr,
                         make_msgid, formatdate)
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
from contextlib import contextmanager

import hashlib
import secrets
from flask import (
    Flask, request, redirect, url_for, flash, abort,
    render_template, Response, session, send_file,
)
from jinja2 import DictLoader, ChoiceLoader

# ------------------------------------------------------------------ الإعدادات
import sys

if getattr(sys, "frozen", False):
    # ملف تنفيذي مبني بـ PyInstaller → data بجوار الـ .exe
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_NAME = os.environ.get("EM_DB", os.path.join(DATA_DIR, "email_manager.db"))
# PostgreSQL اختياري: لو EM_PG (DSN) متظبط، البرنامج يشتغل على Postgres — وإلا SQLite.
PG_DSN = os.environ.get("EM_PG", "").strip()
USE_PG = bool(PG_DSN)
psycopg = None
if USE_PG:
    import psycopg as _psycopg   # noqa: E402
    import psycopg.errors        # noqa: E402,F401
    psycopg = _psycopg
KEY_FILE = os.path.join(DATA_DIR, "secret.key")
FLASK_SECRET_FILE = os.path.join(DATA_DIR, "flask_secret")
LOG_FILE = os.path.join(DATA_DIR, "email_manager.log")
# مجلد النسخ الاحتياطي (يُشارَك مع حاوية النسخ التلقائي عبر volume)
BACKUP_DIR = os.environ.get("EM_BACKUP_DIR", os.path.join(DATA_DIR, "backups"))
BACKUP_KEEP = int(os.environ.get("EM_BACKUP_KEEP", "14"))   # عدد النسخ المحفوظة

HOST = os.environ.get("EM_HOST", "127.0.0.1")
PORT = int(os.environ.get("EM_PORT", "8000"))
SMTP_TIMEOUT = int(os.environ.get("EM_SMTP_TIMEOUT", "20"))
IMAP_TIMEOUT = int(os.environ.get("EM_IMAP_TIMEOUT", "20"))
# سيرفر البريد الداخلي المدمج (SMTP/IMAP فعليان يخدمان صناديق البرنامج)
INT_SMTP_PORT = int(os.environ.get("EM_INT_SMTP_PORT", "8025"))
INT_IMAP_PORT = int(os.environ.get("EM_INT_IMAP_PORT", "8143"))
INT_MAIL_ENABLED = os.environ.get("EM_INT_MAIL", "1") == "1"
SCHEDULER_TICK = 15          # ثوانٍ بين فحوصات المُجدوِل
INBOX_FETCH_LIMIT = 50       # أقصى عدد رسائل جديدة تُجلب لكل حساب في المرة
SCHEMA_VERSION = 8
APP_VERSION = "1.1.34"       # رقم إصدار البرنامج — يزيد مع كل تحديث
DEFAULT_MAILBOX_PASS = "022001"   # كلمة مرور افتراضية لأي صندوق يُنشأ بدون واحدة
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "admin"

# قالب توقيع افتراضي (يُطبَّق على كل موظف ببياناته)
# {phone} و {website} قيمتهما ثابتة من الإعدادات (هاتف/موقع الشركة الموحّد)
DEFAULT_SIGNATURE_TPL = ("--\n{name}\n{title} | {department}\nEmail: {email}\n"
                         "Phone: {phone}\n{website}")

# ------------------------------------------------------------------ التسجيل
_handlers = [logging.FileHandler(LOG_FILE, encoding="utf-8")]
if sys.stderr is not None:          # لا يوجد stderr في نسخة .exe بدون كونسول
    _handlers.append(logging.StreamHandler())
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=_handlers,
)
log = logging.getLogger("email_manager")

# ------------------------------------------------------------------ التشفير
try:
    from cryptography.fernet import Fernet, InvalidToken
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    HAVE_CRYPTO = False
    InvalidToken = Exception
    log.warning("مكتبة cryptography غير مثبّتة → كلمات المرور ستُخزَّن كنص صريح. "
                "ثبّتها بـ:  pip install cryptography")

_fernet = None
if HAVE_CRYPTO:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as fh:
            _key = fh.read().strip()
    else:
        _key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as fh:
            fh.write(_key)
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass
    _fernet = Fernet(_key)

_ENC_PREFIX = "enc::"


def encrypt_secret(text: str) -> str:
    """تشفير كلمة المرور قبل تخزينها."""
    if not text:
        return ""
    if _fernet is None:
        return text
    return _ENC_PREFIX + _fernet.encrypt(text.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str:
    """فك التشفير عند الاستخدام (يتحمّل الصفوف القديمة كنص صريح)."""
    if not token:
        return ""
    if token.startswith(_ENC_PREFIX) and _fernet is not None:
        try:
            return _fernet.decrypt(token[len(_ENC_PREFIX):].encode("ascii")).decode("utf-8")
        except InvalidToken:
            log.error("تعذّر فك تشفير كلمة مرور حساب (مفتاح مختلف؟).")
            return ""
    return token  # legacy plaintext


# ------------------------------------------------------------------ كلمات مرور الدخول
def hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", (pw or "").encode("utf-8"), bytes.fromhex(salt), 200_000)
    return f"pbkdf2$200000${salt}${h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _algo, iters, salt, h = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", (pw or "").encode("utf-8"),
                                   bytes.fromhex(salt), int(iters))
        return secrets.compare_digest(calc.hex(), h)
    except Exception:
        return False


# ------------------------------------------------------------------ قاعدة البيانات
# ================================================================ طبقة توافق PostgreSQL
# تخلّي نفس كود SQLite (علامات ? و PRAGMA و INSERT OR IGNORE و lastrowid) يشتغل على Postgres.
_PG_ID_TABLES = {"accounts", "employees", "reverse_queue", "emp_replies", "templates",
                 "users", "campaigns", "campaign_recipients", "sent_emails",
                 "mail_domains", "mail_boxes", "mail_messages"}
_PG_INS_RE = re.compile(r"^\s*INSERT\s+INTO\s+([a-zA-Z_]+)", re.I)
_PG_ORIGN_RE = re.compile(r"INSERT\s+OR\s+IGNORE\s+INTO", re.I)
_PG_TBLINFO_RE = re.compile(r"^\s*PRAGMA\s+table_info\s*\(\s*([a-zA-Z_]+)\s*\)", re.I)


class _PgRow:
    """صف يدعم الوصول بالاسم row['x'] وبالفهرس row[0] و .keys() و dict(row) — زي sqlite3.Row."""
    __slots__ = ("_c", "_v", "_m")
    def __init__(self, cols, values):
        self._c = cols
        self._v = list(values)
        self._m = dict(zip(cols, self._v))
    def __getitem__(self, k):
        return self._v[k] if isinstance(k, int) else self._m[k]
    def keys(self):
        return list(self._c)
    def get(self, k, d=None):
        return self._m.get(k, d)
    def __contains__(self, k):
        return k in self._m
    def __iter__(self):
        return iter(self._v)
    def __len__(self):
        return len(self._v)


def _pg_rowfactory(cursor):
    desc = cursor.description
    cols = [c.name for c in desc] if desc else []
    def make(values):
        return _PgRow(cols, values)
    return make


def _pg_translate(sql, has_params=False):
    """يترجم استعلام SQLite إلى Postgres. تحويل ? و % يتم فقط لو فيه معاملات."""
    m = _PG_TBLINFO_RE.match(sql)
    if m:
        return ("SELECT column_name AS name FROM information_schema.columns "
                "WHERE table_name = '%s'" % m.group(1).lower())
    if re.match(r"^\s*PRAGMA\s+user_version\s*=", sql, re.I):
        return "SELECT NULL WHERE 1=0"      # ضبط النسخة — لا لزوم له في Postgres
    if re.match(r"^\s*PRAGMA\s+user_version", sql, re.I):
        return "SELECT 0 AS user_version"   # قراءة — نبدأ من 0 (يشغّل الترحيلات)
    if re.match(r"^\s*PRAGMA", sql, re.I):
        return "SELECT NULL AS name WHERE 1=0"
    q = sql
    # INSERT OR REPLACE INTO app_settings → ON CONFLICT (key) DO UPDATE
    if re.search(r"INSERT\s+OR\s+REPLACE\s+INTO\s+app_settings", q, re.I):
        q = re.sub(r"INSERT\s+OR\s+REPLACE\s+INTO", "INSERT INTO", q, flags=re.I)
        q = q + " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
    q = re.sub(r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", "SERIAL PRIMARY KEY", q, flags=re.I)
    q = re.sub(r"TIMESTAMP\s+DEFAULT\s+CURRENT_TIMESTAMP", "TEXT DEFAULT (now()::text)", q, flags=re.I)
    q = re.sub(r"\bCURRENT_TIMESTAMP\b", "now()::text", q, flags=re.I)
    q = re.sub(r"\bTIMESTAMP\b", "TEXT", q)
    if _PG_ORIGN_RE.search(q):
        q = _PG_ORIGN_RE.sub("INSERT INTO", q) + " ON CONFLICT DO NOTHING"
    # psycopg يعالج % و placeholders فقط عند وجود معاملات
    if has_params:
        q = q.replace("%", "%%").replace("?", "%s")
    return q


def _pg_needs_returning(sql):
    if _PG_ORIGN_RE.search(sql) or " RETURNING " in sql.upper():
        return False
    m = _PG_INS_RE.match(sql)
    return bool(m) and m.group(1).lower() in _PG_ID_TABLES


class _PgCursor:
    def __init__(self, raw):
        self._c = raw
        self.lastrowid = None
    def execute(self, sql, params=None):
        q = _pg_translate(sql, bool(params))
        ret = _pg_needs_returning(sql)
        if ret:
            q = q.rstrip().rstrip(";") + " RETURNING id"
        try:
            self._c.execute(q, tuple(params) if params else None)
        except psycopg.errors.IntegrityError as exc:
            self._c.connection.rollback()
            raise sqlite3.IntegrityError(str(exc))
        except psycopg.Error:
            try:
                self._c.connection.rollback()
            except Exception:  # noqa: BLE001
                pass
            raise
        self.lastrowid = None
        if ret:
            try:
                row = self._c.fetchone()
                self.lastrowid = row[0] if row else None
            except Exception:  # noqa: BLE001
                self.lastrowid = None
        return self
    def executemany(self, sql, seq):
        q = _pg_translate(sql, True)
        self._c.executemany(q, [tuple(p) for p in seq])
        return self
    def executescript(self, script):
        for stmt in script.split(";"):
            if stmt.strip():
                self._c.execute(_pg_translate(stmt, False))
        return self
    def fetchone(self):
        return self._c.fetchone()
    def fetchall(self):
        return self._c.fetchall()
    @property
    def rowcount(self):
        return self._c.rowcount
    def close(self):
        self._c.close()


class _PgConn:
    """غلاف اتصال Postgres يحاكي sqlite3.Connection."""
    def __init__(self, raw):
        self._conn = raw
    def cursor(self):
        return _PgCursor(self._conn.cursor())
    def execute(self, sql, params=None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur
    def executemany(self, sql, seq):
        cur = self.cursor()
        cur.executemany(sql, seq)
        return cur
    def executescript(self, script):
        cur = self.cursor()
        cur.executescript(script)
        return cur
    def commit(self):
        self._conn.commit()
    def close(self):
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass


def get_connection():
    if USE_PG:
        last = None
        for attempt in range(15):
            try:
                raw = psycopg.connect(PG_DSN, row_factory=_pg_rowfactory)
                return _PgConn(raw)
            except psycopg.OperationalError as exc:   # السيرفر لسه بيشتغل — أعِد المحاولة
                last = exc
                time.sleep(0.6 * (attempt + 1))
        raise last
    # لا نضبط journal_mode هنا — يُضبط مرة واحدة في init_db.
    last = None
    for attempt in range(5):
        try:
            conn = sqlite3.connect(DB_NAME, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 30000")
            return conn
        except sqlite3.OperationalError as exc:  # اتصال متعثّر عبر المشاركة — أعِد المحاولة
            last = exc
            time.sleep(0.25 * (attempt + 1))
    raise last


def _init_journal_mode():
    """SQLite فقط: يضبط وضع دفتر اليومية مرة واحدة."""
    if USE_PG:
        return
    try:
        conn = sqlite3.connect(DB_NAME, timeout=30)
        conn.execute("PRAGMA journal_mode = %s"
                     % ("WAL" if os.environ.get("EM_WAL") == "1" else "DELETE"))
        conn.close()
    except sqlite3.OperationalError as exc:  # noqa: BLE001
        log.warning("تعذّر ضبط journal_mode: %s", exc)


def _table_columns(cur, table):
    cur.execute(f"PRAGMA table_info({table})")
    return {row["name"] for row in cur.fetchall()}


def init_db():
    _init_journal_mode()
    conn = get_connection()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            email        TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL DEFAULT '',
            password     TEXT NOT NULL,
            smtp_server  TEXT NOT NULL,
            smtp_port    INTEGER NOT NULL DEFAULT 587,
            imap_server  TEXT NOT NULL,
            imap_port    INTEGER NOT NULL DEFAULT 993,
            security     TEXT NOT NULL DEFAULT 'starttls',   -- starttls | ssl | none
            active       INTEGER NOT NULL DEFAULT 1,
            verify_ok    INTEGER NOT NULL DEFAULT 0,          -- آخر تحقق اتصال نجح؟
            last_verified TIMESTAMP,
            signature    TEXT NOT NULL DEFAULT '',
            internal     INTEGER NOT NULL DEFAULT 0,          -- حساب بريد داخلي (بدون SMTP)
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS employees (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            email      TEXT NOT NULL UNIQUE,
            title      TEXT NOT NULL DEFAULT '',
            department TEXT NOT NULL DEFAULT '',
            phone      TEXT NOT NULL DEFAULT '',
            signature  TEXT NOT NULL DEFAULT '',
            password   TEXT NOT NULL DEFAULT '',   -- بيانات دخول صندوق الموظف (مشفّرة)
            emp_last_check TIMESTAMP,              -- آخر فحص لإنبوكس الموظف
            emp_connected  INTEGER NOT NULL DEFAULT 0,  -- نجح الاتصال بصندوقه
            owner_account_id INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
                                                   -- الحساب المسؤول عن إرسال هذا الموظف
            active     INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- نص الرد العكسي لكل حساب مرسِل + تأخيره الخاص
        CREATE TABLE IF NOT EXISTS account_replies (
            account_id    INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
            body          TEXT NOT NULL DEFAULT '',
            delay_minutes INTEGER NOT NULL DEFAULT 0   -- 0 = استخدم التأخير العام
        );

        -- طابور الردود العكسية: كل رد له موعد استحقاق
        CREATE TABLE IF NOT EXISTS reverse_queue (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id   INTEGER REFERENCES employees(id) ON DELETE CASCADE,
            account_email TEXT NOT NULL,
            folder        TEXT NOT NULL DEFAULT 'INBOX',
            uid           INTEGER,
            msgid         TEXT,
            subject       TEXT,
            received_at   TIMESTAMP,
            due_at        TIMESTAMP,
            status        TEXT NOT NULL DEFAULT 'pending',   -- pending | sent | failed
            error         TEXT,
            sent_at       TIMESTAMP,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(employee_id, msgid)
        );

        -- قوالب الرد العكسي حسب القسم
        CREATE TABLE IF NOT EXISTS dept_replies (
            department TEXT PRIMARY KEY,
            body       TEXT NOT NULL DEFAULT ''
        );

        -- سجل ردود الموظفين العكسية (منع الرد المكرر)
        CREATE TABLE IF NOT EXISTS emp_replies (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id    INTEGER REFERENCES employees(id) ON DELETE CASCADE,
            sender_account TEXT,
            in_reply_to    TEXT,
            subject        TEXT,
            body           TEXT,
            status         TEXT,
            error          TEXT,
            replied_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(employee_id, in_reply_to)
        );

        CREATE TABLE IF NOT EXISTS templates (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            subject    TEXT NOT NULL,
            body       TEXT NOT NULL,
            signature  TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'employee',   -- admin | employee
            employee_id   INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            full_name     TEXT NOT NULL DEFAULT '',
            active        INTEGER NOT NULL DEFAULT 1,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS schedule_settings (
            id               INTEGER PRIMARY KEY CHECK (id = 1),
            batch_size       INTEGER NOT NULL DEFAULT 10,
            interval_minutes INTEGER NOT NULL DEFAULT 30,
            enabled          INTEGER NOT NULL DEFAULT 0,
            last_run         TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS campaigns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            template_id INTEGER NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
            status      TEXT NOT NULL DEFAULT 'active',       -- active | paused | completed
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- قالب مختلف لكل قسم داخل الحملة (وإلا يُستخدم قالب الحملة الافتراضي)
        CREATE TABLE IF NOT EXISTS campaign_dept_templates (
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            department  TEXT NOT NULL,
            template_id INTEGER NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
            PRIMARY KEY (campaign_id, department)
        );

        CREATE TABLE IF NOT EXISTS campaign_recipients (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
            employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
            account_id  INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
            status      TEXT NOT NULL DEFAULT 'pending',      -- pending | sent | failed
            attempts    INTEGER NOT NULL DEFAULT 0,
            error       TEXT,
            sent_at     TIMESTAMP,
            UNIQUE(campaign_id, employee_id)
        );

        CREATE TABLE IF NOT EXISTS sent_emails (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id  INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
            employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
            campaign_id INTEGER REFERENCES campaigns(id) ON DELETE SET NULL,
            to_email    TEXT,
            subject     TEXT,
            body        TEXT,
            status      TEXT,
            error       TEXT,
            sent_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- نظام البريد الداخلي المدمج (بدون سيرفر خارجي): دومينات + صناديق
        CREATE TABLE IF NOT EXISTS mail_domains (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL UNIQUE,
            active     INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS mail_boxes (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id    INTEGER NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
            local_part   TEXT NOT NULL,           -- الجزء قبل الـ@
            email        TEXT NOT NULL UNIQUE,    -- local_part@domain (للبحث السريع)
            display_name TEXT NOT NULL DEFAULT '',
            role         TEXT NOT NULL DEFAULT 'sub',  -- main | sub
            password     TEXT NOT NULL DEFAULT '',     -- مشفّرة (Fernet)
            active       INTEGER NOT NULL DEFAULT 1,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(domain_id, local_part)
        );

        -- رسائل البريد الداخلي (محرّك التسليم المدمج — بدون SMTP/IMAP)
        CREATE TABLE IF NOT EXISTS mail_messages (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            box_email    TEXT NOT NULL,           -- صاحب النسخة دي (صندوقه)
            folder       TEXT NOT NULL DEFAULT 'inbox',   -- inbox | sent
            from_email   TEXT NOT NULL,
            from_name    TEXT NOT NULL DEFAULT '',
            to_email     TEXT NOT NULL,
            subject      TEXT NOT NULL DEFAULT '',
            body         TEXT NOT NULL DEFAULT '',   -- HTML
            msg_id       TEXT,
            in_reply_to  TEXT,
            is_read      INTEGER NOT NULL DEFAULT 0,
            is_replied   INTEGER NOT NULL DEFAULT 0,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

    """)

    # صف إعدادات الجدولة الافتراضي
    cur.execute("SELECT COUNT(*) AS c FROM schedule_settings")
    if cur.fetchone()["c"] == 0:
        cur.execute("INSERT INTO schedule_settings (id, batch_size, interval_minutes, enabled) "
                    "VALUES (1, 10, 30, 0)")

    # مستخدم مدير افتراضي عند أول تشغيل
    # المستخدم الرئيسي admin موجود دائماً ولا يُحذف — يُعاد إنشاؤه لو غاب
    adm = cur.execute("SELECT id FROM users WHERE username=?", (DEFAULT_ADMIN_USER,)).fetchone()
    if adm is None:
        cur.execute("INSERT INTO users (username, password_hash, role, full_name, active) "
                    "VALUES (?, ?, 'admin', 'المدير', 1)",
                    (DEFAULT_ADMIN_USER, hash_password(DEFAULT_ADMIN_PASS)))
        log.warning("أُنشئ المستخدم الرئيسي: %s / %s", DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS)
    else:
        # اضمن إنه مدير ونشط دائماً
        cur.execute("UPDATE users SET role='admin', active=1 WHERE username=?",
                    (DEFAULT_ADMIN_USER,))
    # إعادة ضبط باسورد admin مرة واحدة (طلب المستخدم: الباسورد = admin)
    if cur.execute("SELECT value FROM app_settings WHERE key='admin_pw_v1'").fetchone() is None:
        cur.execute("UPDATE users SET password_hash=? WHERE username=?",
                    (hash_password(DEFAULT_ADMIN_PASS), DEFAULT_ADMIN_USER))
        cur.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('admin_pw_v1','1')")

    # إعدادات التطبيق الافتراضية
    defaults = {
        "auto_reply_enabled": "0",
        "auto_reply_subject": "",
        "auto_reply_body": "",
        "mark_seen_on_fetch": "1",
        "signature_template": DEFAULT_SIGNATURE_TPL,
        "send_min_delay": "8",           # ثوانٍ (أقل تأخير بين رسالتين)
        "send_max_delay": "25",          # ثوانٍ (أكبر تأخير بين رسالتين)
        "campaign_spread_seconds": "60", # توزيع إرسال الحملة الداخلية على كام ثانية (0=لحظي)
        "per_account_hourly_limit": "0", # 0 = بلا حد
        "per_account_daily_limit": "0",  # 0 = بلا حد
        "randomize_send": "1",           # ترتيب عشوائي للمستلمين + اختيار حساب عشوائي
        "save_to_sent": "1",             # حفظ نسخة في مجلد Sent عبر IMAP
        # ---- الرد العكسي (الموظفون يردّون على الحسابات الـ5) ----
        "reverse_enabled": "1",
        "reverse_default_reply": "شكراً على رسالتكم، تم الاطلاع وسيتم الرد قريباً.\n\n{name}\n{title}",
        "reverse_batch_size": "20",      # عدد صناديق الموظفين المفحوصة كل دورة
        "reverse_min_delay": "8",
        "reverse_max_delay": "25",
        "reverse_delay_seconds": "20",   # الرد يوصل بعد كام ثانية من استلام الرسالة
        "emp_imap_server": "",     # فارغ = اكتشاف تلقائي من نطاق بريد كل موظف
        "emp_imap_port": "",
        "emp_smtp_server": "",
        "emp_smtp_port": "",
        "emp_security": "",
        # ---- بيانات ثابتة لكل التواقيع ----
        "company_phone": "920035640",            # هاتف موحّد يظهر في {phone} بكل التواقيع
        "company_website": "www.solutionstech.sa",  # موقع موحّد يظهر في {website}
        "global_logo": "",                        # لوجو موحّد (data URI) لكل التواقيع
        "signature_style": "rich",                # rich = التصميم الاحترافي · text = نصّي بسيط
        "auto_backup_hours": "6",                 # نسخة احتياطية تلقائية كل كام ساعة (0=إيقاف)
    }
    for k, v in defaults.items():
        cur.execute("INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)", (k, v))

    # -------- ترحيل من مخطّط النسخة القديمة --------
    cur.execute("PRAGMA user_version")
    user_version = cur.fetchone()[0]

    acc_cols = _table_columns(cur, "accounts")
    if "security" not in acc_cols and "use_ssl_smtp" in acc_cols:
        log.info("ترحيل: تحويل use_ssl_smtp → security")
        cur.execute("ALTER TABLE accounts ADD COLUMN security TEXT NOT NULL DEFAULT 'starttls'")
        # في النسخة القديمة: use_ssl_smtp=1 يعني STARTTLS، =0 يعني SSL مباشر
        cur.execute("UPDATE accounts SET security = CASE WHEN use_ssl_smtp = 0 THEN 'ssl' ELSE 'starttls' END")
    for col, ddl in [("active", "INTEGER NOT NULL DEFAULT 1"),
                     ("created_at", "TIMESTAMP"),
                     ("display_name", "TEXT NOT NULL DEFAULT ''"),
                     ("verify_ok", "INTEGER NOT NULL DEFAULT 0"),
                     ("last_verified", "TIMESTAMP"),
                     ("signature", "TEXT NOT NULL DEFAULT ''"),
                     ("internal", "INTEGER NOT NULL DEFAULT 0"),
                     ("logo", "TEXT NOT NULL DEFAULT ''")]:
        if col not in acc_cols:
            cur.execute(f"ALTER TABLE accounts ADD COLUMN {col} {ddl}")

    emp_cols = _table_columns(cur, "employees")
    for col in ("title", "department", "phone", "signature", "password", "logo",
                "iqama", "emp_number"):
        if col not in emp_cols:
            cur.execute(f"ALTER TABLE employees ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
    if "emp_last_check" not in emp_cols:
        cur.execute("ALTER TABLE employees ADD COLUMN emp_last_check TIMESTAMP")

    # قوالب النسخة القديمة كانت تحمل حقول الرد التلقائي → انقلها إلى app_settings
    tpl_cols = _table_columns(cur, "templates")
    cur_auto = cur.execute("SELECT value FROM app_settings WHERE key='auto_reply_body'").fetchone()
    if "auto_reply_body" in tpl_cols and not (cur_auto and cur_auto["value"]):
        cur.execute("SELECT auto_reply_subject, auto_reply_body FROM templates "
                    "WHERE auto_reply_body IS NOT NULL AND auto_reply_body != '' LIMIT 1")
        row = cur.fetchone()
        if row:
            cur.execute("UPDATE app_settings SET value = ? WHERE key = 'auto_reply_subject'",
                        (row["auto_reply_subject"] or "",))
            cur.execute("UPDATE app_settings SET value = ? WHERE key = 'auto_reply_body'",
                        (row["auto_reply_body"] or "",))
            log.info("ترحيل: نُقلت إعدادات الرد التلقائي من القالب إلى الإعدادات العامة")

    if "emp_connected" not in emp_cols:
        cur.execute("ALTER TABLE employees ADD COLUMN emp_connected INTEGER NOT NULL DEFAULT 0")
    if "owner_account_id" not in emp_cols:
        cur.execute("ALTER TABLE employees ADD COLUMN owner_account_id INTEGER "
                    "REFERENCES accounts(id) ON DELETE SET NULL")

    sent_cols = _table_columns(cur, "sent_emails")
    for col, ddl in [("campaign_id", "INTEGER"), ("to_email", "TEXT"), ("error", "TEXT")]:
        if col not in sent_cols:
            cur.execute(f"ALTER TABLE sent_emails ADD COLUMN {col} {ddl}")

    # تاريخ/وقت مخصّص لكل حملة (إرسال + تسليم الرد)
    camp_cols = _table_columns(cur, "campaigns")
    for col in ("send_date", "send_time", "reply_date", "reply_time"):
        if col not in camp_cols:
            cur.execute(f"ALTER TABLE campaigns ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")

    # ربط رسالة الحملة بصندوق الموظف (لتحديد تاريخ الرد من الحملة نفسها)
    mm_cols = _table_columns(cur, "mail_messages")
    if "campaign_id" not in mm_cols:
        cur.execute("ALTER TABLE mail_messages ADD COLUMN campaign_id INTEGER")

    # القالب: الحسابات المرسِلة له + رد الموظفين الخاص به (إرسال + استقبال داخل القالب)
    tpl_cols = _table_columns(cur, "templates")
    if "send_accounts" not in tpl_cols:
        cur.execute("ALTER TABLE templates ADD COLUMN send_accounts TEXT NOT NULL DEFAULT ''")
    if "reply_body" not in tpl_cols:
        cur.execute("ALTER TABLE templates ADD COLUMN reply_body TEXT NOT NULL DEFAULT ''")

    # الرسائل صارت تُقرأ حيّاً من السيرفر — لم يعد هناك تخزين محلي لها
    cur.execute("DROP INDEX IF EXISTS idx_inbox_msgid")
    cur.execute("DROP TABLE IF EXISTS inbox")

    # علّم الحسابات المحلية (المُنشأة من صفحة الدومينات) كحسابات داخلية
    if "internal" in _table_columns(cur, "accounts"):
        cur.execute("""UPDATE accounts SET internal=1, verify_ok=1
                       WHERE internal=0 AND security='none'
                         AND smtp_server IN ('127.0.0.1', 'localhost')""")
        # وجّه الحسابات الداخلية لسيرفر البريد المدمج
        cur.execute("UPDATE accounts SET smtp_server='127.0.0.1', imap_server='127.0.0.1', "
                    "smtp_port=?, imap_port=?, security='none' WHERE internal=1",
                    (INT_SMTP_PORT, INT_IMAP_PORT))
        # وجّه صناديق الموظفين لنفس السيرفر (لو فيه دومينات داخلية)
        if cur.execute("SELECT 1 FROM mail_domains LIMIT 1").fetchone():
            for k, v in (("emp_imap_server", "127.0.0.1"), ("emp_imap_port", str(INT_IMAP_PORT)),
                         ("emp_smtp_server", "127.0.0.1"), ("emp_smtp_port", str(INT_SMTP_PORT)),
                         ("emp_security", "none")):
                cur.execute("UPDATE app_settings SET value=? WHERE key=?", (v, k))

    for stmt in [
        "CREATE INDEX IF NOT EXISTS idx_recipients_status ON campaign_recipients(status)",
        "CREATE INDEX IF NOT EXISTS idx_emp_owner ON employees(owner_account_id)",
        "CREATE INDEX IF NOT EXISTS idx_revq_due ON reverse_queue(status, due_at)",
        "CREATE INDEX IF NOT EXISTS idx_recipients_campaign ON campaign_recipients(campaign_id)",
        "CREATE INDEX IF NOT EXISTS idx_sent_campaign ON sent_emails(campaign_id)",
        "CREATE INDEX IF NOT EXISTS idx_mailboxes_domain ON mail_boxes(domain_id)",
        "CREATE INDEX IF NOT EXISTS idx_mailmsg_box ON mail_messages(box_email, folder)",
        "CREATE INDEX IF NOT EXISTS idx_mailmsg_campaign ON mail_messages(campaign_id)",
        "CREATE INDEX IF NOT EXISTS idx_mailmsg_scan ON mail_messages(box_email, folder, is_replied)",
        "CREATE INDEX IF NOT EXISTS idx_emp_replies_emp ON emp_replies(employee_id)",
        "CREATE INDEX IF NOT EXISTS idx_emp_active ON employees(active)",
        "CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email)",
        "CREATE INDEX IF NOT EXISTS idx_employees_email ON employees(email)",
    ]:
        cur.execute(stmt)

    # تشفير كلمات المرور المخزّنة كنص صريح (مرة واحدة فقط)
    if _fernet is not None:
        legacy = [r for r in cur.execute("SELECT id, password FROM accounts").fetchall()
                  if not r["password"].startswith(_ENC_PREFIX)]
        for row in legacy:
            cur.execute("UPDATE accounts SET password = ? WHERE id = ?",
                        (encrypt_secret(row["password"]), row["id"]))
        if legacy:
            log.info("ترحيل: تشفير %d كلمة مرور كانت مخزّنة كنص صريح", len(legacy))

    cur.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()
    conn.close()
    if USE_PG:
        _pg_migrate_from_sqlite()
    log.info("قاعدة البيانات جاهزة: %s", "PostgreSQL" if USE_PG else DB_NAME)


def _pg_migrate_from_sqlite():
    """ينقل بيانات SQLite الموجودة إلى Postgres مرة واحدة (لو Postgres فاضي)."""
    if not os.path.exists(DB_NAME):
        return
    conn = get_connection()
    try:
        has = conn.execute("SELECT COUNT(*) AS c FROM accounts").fetchone()["c"]
        acnt = conn.execute("SELECT COUNT(*) AS c FROM app_settings").fetchone()["c"]
    except Exception:  # noqa: BLE001
        conn.close()
        return
    # لو فيه بيانات فعلية (غير الإعدادات الافتراضية) نعتبره منقول
    if has > 0:
        conn.close()
        return
    try:
        src = sqlite3.connect(DB_NAME, timeout=30)
        src.row_factory = sqlite3.Row
    except sqlite3.OperationalError:
        conn.close()
        return
    order = ["accounts", "mail_domains", "employees", "templates", "campaigns",
             "campaign_dept_templates", "campaign_recipients", "sent_emails",
             "account_replies", "dept_replies", "reverse_queue", "emp_replies",
             "mail_messages", "mail_boxes", "users", "app_settings", "schedule_settings"]
    moved = 0
    for tbl in order:
        try:
            rows = src.execute("SELECT * FROM %s" % tbl).fetchall()
        except sqlite3.OperationalError:
            continue
        if not rows:
            continue
        cols = rows[0].keys()
        collist = ", ".join(cols)
        ph = ", ".join(["?"] * len(cols))
        for r in rows:
            try:
                conn.execute("INSERT OR IGNORE INTO %s (%s) VALUES (%s)" % (tbl, collist, ph),
                             tuple(r[c] for c in cols))
                moved += 1
            except Exception as exc:  # noqa: BLE001
                log.warning("نقل %s: تخطّي صف — %s", tbl, exc)
        conn.commit()
    src.close()
    # إعادة ضبط تسلسلات الـ id في Postgres
    for tbl in _PG_ID_TABLES:
        try:
            conn.execute("SELECT setval(pg_get_serial_sequence('%s','id'), "
                         "COALESCE((SELECT MAX(id) FROM %s), 1))" % (tbl, tbl))
        except Exception:  # noqa: BLE001
            pass
    conn.commit()
    conn.close()
    log.info("تم نقل %d صف من SQLite إلى PostgreSQL", moved)


def get_setting(key, default=None):
    conn = get_connection()
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key, value):
    conn = get_connection()
    conn.execute("INSERT INTO app_settings (key, value) VALUES (?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, str(value)))
    conn.commit()
    conn.close()


# ------------------------------------------------------------------ اكتشاف إعدادات البريد
# (smtp_server, smtp_port, security, imap_server, imap_port)
_MAIL_PROVIDERS = {
    "gmail.com":      ("smtp.gmail.com", 587, "starttls", "imap.gmail.com", 993),
    "googlemail.com": ("smtp.gmail.com", 587, "starttls", "imap.gmail.com", 993),
    # Microsoft (Outlook.com / Hotmail / Live / Office365)
    "outlook.com":    ("smtp-mail.outlook.com", 587, "starttls", "outlook.office365.com", 993),
    "hotmail.com":    ("smtp-mail.outlook.com", 587, "starttls", "outlook.office365.com", 993),
    "hotmail.co.uk":  ("smtp-mail.outlook.com", 587, "starttls", "outlook.office365.com", 993),
    "live.com":       ("smtp-mail.outlook.com", 587, "starttls", "outlook.office365.com", 993),
    "live.com.sa":    ("smtp-mail.outlook.com", 587, "starttls", "outlook.office365.com", 993),
    "msn.com":        ("smtp-mail.outlook.com", 587, "starttls", "outlook.office365.com", 993),
    "office365.com":  ("smtp.office365.com", 587, "starttls", "outlook.office365.com", 993),
    "outlook.sa":     ("smtp.office365.com", 587, "starttls", "outlook.office365.com", 993),
    # Yahoo
    "yahoo.com":      ("smtp.mail.yahoo.com", 465, "ssl", "imap.mail.yahoo.com", 993),
    "ymail.com":      ("smtp.mail.yahoo.com", 465, "ssl", "imap.mail.yahoo.com", 993),
    "rocketmail.com": ("smtp.mail.yahoo.com", 465, "ssl", "imap.mail.yahoo.com", 993),
    # Apple
    "icloud.com":     ("smtp.mail.me.com", 587, "starttls", "imap.mail.me.com", 993),
    "me.com":         ("smtp.mail.me.com", 587, "starttls", "imap.mail.me.com", 993),
    "mac.com":        ("smtp.mail.me.com", 587, "starttls", "imap.mail.me.com", 993),
    # Zoho (النطاقات العالمية والإقليمية)
    "zoho.com":       ("smtp.zoho.com", 465, "ssl", "imap.zoho.com", 993),
    "zohomail.com":   ("smtp.zoho.com", 465, "ssl", "imap.zoho.com", 993),
    "zoho.eu":        ("smtp.zoho.eu", 465, "ssl", "imap.zoho.eu", 993),
    "zoho.in":        ("smtp.zoho.in", 465, "ssl", "imap.zoho.in", 993),
    "zoho.sa":        ("smtp.zoho.sa", 465, "ssl", "imap.zoho.sa", 993),
    # أخرى
    "aol.com":        ("smtp.aol.com", 587, "starttls", "imap.aol.com", 993),
    "yandex.com":     ("smtp.yandex.com", 465, "ssl", "imap.yandex.com", 993),
    "gmx.com":        ("mail.gmx.com", 587, "starttls", "imap.gmx.com", 993),
    "mail.com":       ("smtp.mail.com", 587, "starttls", "imap.mail.com", 993),
}

# نطاقات تُدار عبر Microsoft 365 حتى لو كانت نطاق شركة مخصّص
_M365_IMAP = ("outlook.office365.com", 993)
_M365_SMTP = ("smtp.office365.com", 587, "starttls")
# نطاقات تُدار عبر Google Workspace
_GW_IMAP = ("imap.gmail.com", 993)
_GW_SMTP = ("smtp.gmail.com", 587, "starttls")


def guess_mail_config(email):
    """يخمّن إعدادات SMTP/IMAP من نطاق البريد. غير المعروف → mail.<domain>."""
    domain = (email or "").split("@")[-1].lower().strip()
    if domain in _MAIL_PROVIDERS:
        return _MAIL_PROVIDERS[domain]
    return (f"mail.{domain}", 587, "starttls", f"mail.{domain}", 993)


# ------------------------------------------------------------------ دوال البريد
def _smtp_connect(account):
    host = account["smtp_server"]
    port = int(account["smtp_port"])
    security = account["security"]
    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT,
                                  context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT)
        server.ehlo()
        if security == "starttls":
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
    server.login(account["email"], decrypt_secret(account["password"]))
    return server


def build_message(account, to_email, subject, body):
    """يبني رسالة MIME نصية مع اسم عرض المرسِل و Message-ID."""
    msg = MIMEMultipart()
    display = (account["display_name"] if "display_name" in account.keys() else "") or ""
    msg["From"] = formataddr((str(make_header(decode_header(display))), account["email"])) \
        if display else account["email"]
    msg["To"] = to_email
    msg["Subject"] = str(make_header(decode_header(subject))) if subject else "(بدون موضوع)"
    try:
        msg["Message-ID"] = make_msgid(domain=account["email"].split("@")[-1])
    except Exception:
        pass
    msg["Date"] = formatdate(localtime=True)
    msg.attach(MIMEText(body or "", "plain", "utf-8"))
    return msg


def _append_to_sent(account, raw_bytes):
    """يحفظ نسخة من الرسالة في مجلد Sent عبر IMAP (أفضل جهد، لا يوقف الإرسال)."""
    try:
        mail = _imap_open(account["imap_server"], account["imap_port"],
                          account["email"], decrypt_secret(account["password"]))
        folder = _find_sent_folder(mail)
        if folder:
            mail.append(folder, r"(\Seen)", imaplib.Time2Internaldate(time.time()), raw_bytes)
        mail.logout()
        return bool(folder)
    except Exception as exc:  # noqa: BLE001
        log.warning("تعذّر حفظ نسخة في Sent لحساب %s: %s", account["email"], exc)
        return False


def _find_sent_folder(mail):
    typ, data = mail.list()
    if typ != "OK" or not data:
        return None
    fallback = None
    for line in data:
        s = line.decode(errors="ignore")
        low = s.lower()
        # اسم المجلد بين آخر علامتي اقتباس أو آخر كلمة
        name = s.split(' "')[-1].strip().strip('"') if ' "' in s else s.split()[-1].strip('"')
        if "\\sent" in low:
            return name
        if name.lower().endswith("sent") or "sent mail" in low or "sent items" in low:
            fallback = fallback or name
    return fallback


def send_email(account, to_email, subject, body, save_to_sent=False):
    """يرسل رسالة نصية واحدة. يعيد (نجاح: bool، رسالة: str)."""
    msg = build_message(account, to_email, subject, body)
    try:
        server = _smtp_connect(account)
        try:
            server.sendmail(account["email"], [to_email], msg.as_string())
        finally:
            try:
                server.quit()
            except Exception:
                pass
    except Exception as exc:  # noqa: BLE001
        log.warning("فشل الإرسال إلى %s عبر %s: %s", to_email, account["email"], exc)
        return False, str(exc)

    if save_to_sent:
        _append_to_sent(account, msg.as_bytes())
    return True, "تم الإرسال بنجاح"


# ================================================================ محرّك البريد الداخلي
# تسليم مدمج بالكامل: الرسالة تتخزّن في mail_messages — نسخة "inbox" للمستقبِل ونسخة
# "sent" للمرسِل — بدون أي SMTP/IMAP أو سيرفر خارجي. المستقبِل يشوفها في صندوقه الداخلي.

def _text_to_html(text):
    """يحوّل نص عادي (بأسطر) لـ HTML بسيط مع الحفاظ على فواصل الأسطر."""
    import html as _html
    return "<br>".join(_html.escape(line) for line in (text or "").split("\n"))


LOGO_MAX_BYTES = 3 * 1024 * 1024   # أقصى حجم للوجو (3 ميجا)


def _read_logo(file_storage):
    """يقرأ صورة مرفوعة. يعيد (data_uri, error). error='' عند النجاح، و('','') لو مفيش ملف."""
    if not file_storage or not file_storage.filename:
        return "", ""
    raw = file_storage.read()
    if not raw:
        return "", "الملف فارغ"
    if len(raw) > LOGO_MAX_BYTES:
        return "", ("حجم الصورة %.1f ميجا — الأقصى %d ميجا (صغّر الصورة وحاول تاني)"
                    % (len(raw) / 1048576.0, LOGO_MAX_BYTES // 1048576))
    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
            "gif": "image/gif", "webp": "image/webp", "svg": "image/svg+xml"}.get(ext)
    if not mime:
        return "", ("صيغة غير مدعومة (%s) — المسموح: PNG, JPG, GIF, WEBP, SVG"
                    % (ext or "بدون امتداد"))
    return "data:%s;base64,%s" % (mime, base64.b64encode(raw).decode("ascii")), ""


def _logo_data_uri(file_storage):
    """غلاف قديم: يعيد data URI فقط (أو '' لو غير صالح)."""
    return _read_logo(file_storage)[0]


def _effective_logo(account_logo=""):
    """اللوجو الفعلي لأي توقيع: اللوجو الموحّد العام إن وُجد، وإلا لوجو الحساب."""
    return (get_setting("global_logo", "") or "").strip() or (account_logo or "")


def _signature_html(text, logo=""):
    """يبني HTML التوقيع: اللوجو على الشمال والنص على اليمين (لو فيه لوجو)."""
    txt_html = _text_to_html(text.strip()) if (text or "").strip() else ""
    if not logo:
        return txt_html
    img = '<img src="%s" style="max-height:90px;display:block" alt="logo">' % logo
    if not txt_html:
        return img
    # جدول dir=ltr: الخلية الأولى (اللوجو) تظهر على الشمال والنص على يمينها
    return ('<table dir="ltr" style="border-collapse:collapse"><tr>'
            '<td style="vertical-align:top;padding-right:16px">%s</td>'
            '<td style="vertical-align:top">%s</td></tr></table>') % (img, txt_html)


# -------- التوقيع الاحترافي (تصميم ثابت تُملأ بياناته من بيانات الموظف) --------
SIG_TEAL = "#15505f"
_SIG_ICON_PATHS = {
    "phone": ("M3.654 1.328a.678.678 0 0 0-1.015-.063L1.605 2.3c-.483.484-.661 1.169-.45 "
              "1.77a17.6 17.6 0 0 0 4.168 6.608 17.6 17.6 0 0 0 6.608 4.168c.601.211 1.286.033 "
              "1.77-.45l1.034-1.034a.678.678 0 0 0-.063-1.015l-2.307-1.794a.68.68 0 0 0-.58-.122l-2.19."
              "547a1.75 1.75 0 0 1-1.657-.459L5.482 8.062a1.75 1.75 0 0 1-.46-1.657l.548-2.19a.68.68 "
              "0 0 0-.122-.58z"),
    "mail": ("M.05 3.555A2 2 0 0 1 2 2h12a2 2 0 0 1 1.95 1.555L8 8.414zM0 4.697v7.104l5.803-3.558zM"
             "6.761 8.83l-6.57 4.027A2 2 0 0 0 2 14h12a2 2 0 0 0 1.808-1.144l-6.57-4.027L8 9.586zM"
             "10.197 8.343 16 11.9V4.697z"),
    "pin": ("M8 16s6-5.686 6-10A6 6 0 0 0 2 6c0 4.314 6 10 6 10m0-7a3 3 0 1 1 0-6 3 3 0 0 1 0 6"),
    "web": ("M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8m7.5-6.923c-.67.204-1.335.82-1.887 1.855A8 8 0 0 0 "
            "5.145 4H7.5zM4.09 4a9.3 9.3 0 0 1 .64-1.539 7 7 0 0 1 .597-.933A7.03 7.03 0 0 0 2.255 "
            "4zm-.582 3.5c.03-.877.138-1.718.312-2.5H1.674a7 7 0 0 0-.656 2.5zM4.847 5a12.5 12.5 0 0 "
            "0-.338 2.5H7.5V5zM8.5 5v2.5h2.99a12.5 12.5 0 0 0-.337-2.5zM4.51 8.5a12.5 12.5 0 0 0 "
            ".337 2.5H7.5V8.5zm3.99 0V11h2.653c.187-.765.306-1.608.338-2.5zM5.145 12q.208.58.468 "
            "1.068c.552 1.035 1.218 1.65 1.887 1.855V12zm.182 2.472a7 7 0 0 1-.597-.933A9.3 9.3 0 0 "
            "1 4.09 12H2.255a7 7 0 0 0 3.072 2.472M3.82 11a13.7 13.7 0 0 1-.312-2.5h-2.49c.062.89.291 "
            "1.733.656 2.5zm6.853 0c.173-.782.282-1.623.312-2.5h2.49a7 7 0 0 1-.656 2.5zm.555-5a9.3 "
            "9.3 0 0 0-.64-1.539 7 7 0 0 0-.597-.933A7.03 7.03 0 0 1 13.745 4zm-5.64-2.923c.67.204 "
            "1.335.82 1.887 1.855q.26.487.468 1.068H8.5zM8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1"),
}


def _sig_icon(kind):
    """دائرة بإطار teal بداخلها أيقونة SVG."""
    d = _SIG_ICON_PATHS.get(kind, "")
    svg = ('<svg width="14" height="14" viewBox="0 0 16 16" fill="%s" '
           'style="vertical-align:middle"><path d="%s"/></svg>' % (SIG_TEAL, d)) if d else ""
    return ('<span style="display:inline-block;width:30px;height:30px;border:1.5px solid %s;'
            'border-radius:50%%;line-height:28px;text-align:center;vertical-align:middle">%s</span>'
            % (SIG_TEAL, svg))


def _rich_signature_html(entity, logo=""):
    """توقيع احترافي بتصميم ثابت — اللوجو يسار، فاصل مزدوج، ثم الاسم/الوظيفة وصفوف
    الهاتف/الإيميل/القسم/الموقع. البيانات من بيانات الموظف + الهاتف/الموقع الموحّدين."""
    def g(k):
        try:
            return (entity[k] or "").strip()
        except (KeyError, IndexError, TypeError):
            v = entity.get(k, "") if isinstance(entity, dict) else ""
            return (v or "").strip()
    name = g("name")
    title = g("title")
    dept = g("department")
    email = g("email")
    phone = get_setting("company_phone", "920035640")
    website = get_setting("company_website", "www.solutionstech.sa")
    web_href = website if website.startswith("http") else "https://" + website

    def row(icon, text, href=""):
        if not text:
            return ""
        val = ('<a href="%s" style="color:%s;text-decoration:none">%s</a>' % (href, SIG_TEAL, text)
               ) if href else text
        return ('<tr><td style="padding:4px 0;vertical-align:middle">%s</td>'
                '<td style="padding:4px 12px;vertical-align:middle;font-size:14px;color:%s" '
                'dir="ltr">%s</td></tr>') % (_sig_icon(icon), SIG_TEAL, val)

    rows = (row("phone", phone) + row("mail", email, "mailto:%s" % email)
            + row("pin", dept) + row("web", website, web_href))
    details = '<div style="font-size:30px;font-weight:bold;color:%s;line-height:1.05">%s</div>' % (
        SIG_TEAL, name)
    if title:
        details += ('<div style="font-size:13px;letter-spacing:4px;color:%s;margin:5px 0 12px;'
                    'text-transform:uppercase">%s</div>' % (SIG_TEAL, title))
    else:
        details += '<div style="margin-bottom:12px"></div>'
    details += ('<table cellpadding="0" cellspacing="0" style="border-collapse:collapse">%s</table>'
                % rows)

    left = ""
    if logo:
        left = ('<td style="vertical-align:middle;text-align:center;padding-right:6px">'
                '<img src="%s" style="max-width:170px;max-height:130px;display:block" alt="logo">'
                '</td>'
                '<td style="padding:0 22px;vertical-align:middle">'
                '<table cellpadding="0" cellspacing="0" style="height:130px"><tr>'
                '<td style="border-left:2px solid %s;padding-left:5px"></td>'
                '<td style="border-left:2px solid %s"></td></tr></table></td>') % (
                    logo, SIG_TEAL, SIG_TEAL)
    return ('<div dir="ltr" style="font-family:Arial,Helvetica,sans-serif;text-align:left">'
            '<div style="font-size:20px;font-weight:bold;color:#1a1a1a;margin-bottom:14px">'
            'Thanks &amp; Best Regards</div>'
            '<table dir="ltr" cellpadding="0" cellspacing="0" style="border-collapse:collapse">'
            '<tr>%s<td style="vertical-align:middle">%s</td></tr></table></div>') % (left, details)


def internal_deliver(from_email, from_name, to_email, subject, body_html,
                     in_reply_to=None, conn=None, date_override=None, campaign_id=None):
    """يسلّم رسالة داخلياً: نسخة inbox للمستقبِل + نسخة sent للمرسِل.
    body_html = نص HTML جاهز (بالتوقيع). يعيد (نجاح, msg_id)."""
    own = conn is None
    if own:
        conn = get_connection()
    msg_id = make_msgid(domain="internal.local")
    now = (date_override.isoformat(timespec="seconds") if date_override
           else datetime.now().isoformat(timespec="seconds"))
    try:
        # نسخة المستقبِل (وارد)
        conn.execute(
            """INSERT INTO mail_messages (box_email, folder, from_email, from_name,
                   to_email, subject, body, msg_id, in_reply_to, created_at, campaign_id)
               VALUES (?, 'inbox', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (to_email.lower(), from_email.lower(), from_name or "", to_email.lower(),
             subject, body_html, msg_id, in_reply_to, now, campaign_id))
        # نسخة المرسِل (مُرسَل)
        conn.execute(
            """INSERT INTO mail_messages (box_email, folder, from_email, from_name,
                   to_email, subject, body, msg_id, in_reply_to, created_at, campaign_id)
               VALUES (?, 'sent', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (from_email.lower(), from_email.lower(), from_name or "", to_email.lower(),
             subject, body_html, msg_id, in_reply_to, now, campaign_id))
        if own:
            conn.commit()
        return True, msg_id
    except Exception as exc:  # noqa: BLE001
        log.warning("فشل التسليم الداخلي إلى %s: %s", to_email, exc)
        return False, str(exc)
    finally:
        if own:
            conn.close()


def build_rich_message(account, to_list, cc_list, subject, body, attachments=None,
                       in_reply_to=None, references=None, date_override=None, html_body=False):
    """رسالة MIME كاملة: نص + مرفقات + ترويسات الرد (للاستخدام في واجهة البريد)."""
    msg = MIMEMultipart()
    display = (account["display_name"] if "display_name" in account.keys() else "") or ""
    msg["From"] = formataddr((str(make_header(decode_header(display))), account["email"])) \
        if display else account["email"]
    msg["To"] = ", ".join(to_list)
    if cc_list:
        msg["Cc"] = ", ".join(cc_list)
    msg["Subject"] = str(make_header(decode_header(subject))) if subject else "(بدون موضوع)"
    try:
        msg["Message-ID"] = make_msgid(domain=account["email"].split("@")[-1])
    except Exception:
        pass
    if date_override is not None:
        msg["Date"] = formatdate(time.mktime(date_override.timetuple()), localtime=True)
    else:
        msg["Date"] = formatdate(localtime=True)
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    if html_body:
        import re as _re
        plain = _re.sub(r"<br\s*/?>", "\n", body or "")
        plain = _re.sub(r"<[^>]+>", "", plain)
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(plain, "plain", "utf-8"))
        alt.attach(MIMEText(body or "", "html", "utf-8"))
        msg.attach(alt)
    else:
        msg.attach(MIMEText(body or "", "plain", "utf-8"))
    for filename, ctype, data in (attachments or []):
        maintype, _, subtype = (ctype or "application/octet-stream").partition("/")
        part = MIMEBase(maintype or "application", subtype or "octet-stream")
        part.set_payload(data)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", "attachment",
                        filename=("utf-8", "", filename or "attachment"))
        msg.attach(part)
    return msg


def send_mail_full(account, to_list, cc_list, subject, body, attachments=None,
                   in_reply_to=None, references=None, sent_folder=None, date_override=None,
                   html_body=False):
    """إرسال رسالة من واجهة البريد + حفظ نسخة في مجلد المُرسَل على السيرفر."""
    msg = build_rich_message(account, to_list, cc_list, subject, body, attachments,
                             in_reply_to, references, date_override=date_override,
                             html_body=html_body)
    recipients = list(to_list) + list(cc_list or [])
    try:
        server = _smtp_connect(account)
        try:
            server.sendmail(account["email"], recipients, msg.as_string())
        finally:
            try:
                server.quit()
            except Exception:
                pass
    except Exception as exc:  # noqa: BLE001
        log.warning("فشل الإرسال من %s إلى %s: %s", account["email"], recipients, exc)
        return False, str(exc)
    if sent_folder:
        mail_append(account, sent_folder, msg.as_bytes())
    return True, "تم الإرسال"


def test_account(account):
    """اختبار اتصال SMTP فقط (تسجيل الدخول)."""
    try:
        server = _smtp_connect(account)
        server.quit()
        return True, "اتصال SMTP وتسجيل الدخول ناجح"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _decode_hdr(value):
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def _extract_body(msg):
    """يستخرج نص الرسالة، مفضّلاً text/plain ثم text/html مبسّطاً."""
    def decode_part(part):
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="ignore")
        except LookupError:
            return payload.decode("utf-8", errors="ignore")

    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp.lower():
                continue
            if ctype == "text/plain" and not plain:
                plain = decode_part(part)
            elif ctype == "text/html" and not html:
                html = decode_part(part)
    else:
        if msg.get_content_type() == "text/html":
            html = decode_part(msg)
        else:
            plain = decode_part(msg)

    if plain.strip():
        return plain.strip()
    if html.strip():
        import re
        text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.S | re.I)
        text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
        text = re.sub(r"</p>", "\n\n", text, flags=re.I)
        text = re.sub(r"<[^>]+>", "", text)
        return re.sub(r"\n{3,}", "\n\n", text).strip()
    return ""


def fetch_unread_emails(account, limit=INBOX_FETCH_LIMIT, mark_seen=True):
    results = []
    try:
        mail = imaplib.IMAP4_SSL(account["imap_server"], int(account["imap_port"]),
                                 timeout=IMAP_TIMEOUT)
        mail.login(account["email"], decrypt_secret(account["password"]))
        mail.select("INBOX")
        status, data = mail.search(None, "UNSEEN")
        if status != "OK":
            mail.logout()
            return results

        ids = data[0].split()
        if limit:
            ids = ids[-limit:]

        fetch_cmd = "(RFC822)" if mark_seen else "(BODY.PEEK[])"
        for eid in ids:
            status, msg_data = mail.fetch(eid, fetch_cmd)
            if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                continue
            msg = message_from_bytes(msg_data[0][1])
            name, addr = parseaddr(_decode_hdr(msg.get("From")))
            try:
                received = parsedate_to_datetime(msg.get("Date"))
                received_iso = received.astimezone().replace(tzinfo=None).isoformat(timespec="seconds")
            except Exception:
                received_iso = datetime.now().isoformat(timespec="seconds")
            results.append({
                "message_id": (_decode_hdr(msg.get("Message-ID")) or f"nomsgid-{eid.decode()}").strip(),
                "sender_name": name or "",
                "sender_email": (addr or "").lower(),
                "subject": _decode_hdr(msg.get("Subject")),
                "body": _extract_body(msg),
                "received_at": received_iso,
            })
        mail.logout()
    except Exception as exc:  # noqa: BLE001
        log.error("خطأ في جلب البريد لحساب %s: %s", account["email"], exc)
    return results


# --------------------------------------------------- اكتشاف تلقائي + تحقق اتصال
def _mx_hosts(domain):
    """سجلّات MX عبر DNS-over-HTTPS (أفضل جهد، تُرجع [] عند أي خطأ)."""
    import json
    from urllib.request import urlopen, Request
    for url in (f"https://dns.google/resolve?name={domain}&type=MX",
                f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX"):
        try:
            req = Request(url, headers={"accept": "application/dns-json",
                                        "User-Agent": "EmailManager"})
            with urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
            hosts = [a.get("data", "").lower().rstrip(".") for a in data.get("Answer", [])]
            if hosts:
                return hosts
        except Exception:
            continue
    return []


def _imap_open(host, port, email, password, timeout=IMAP_TIMEOUT):
    """يفتح جلسة IMAP ويسجّل الدخول.
    - المنفذ الداخلي (INT_IMAP_PORT): IMAP4 عادي بدون تشفير (سيرفر داخلي على نفس الجهاز).
    - 993: IMAP4 عبر SSL.  - 143 وغيره: IMAP4 مع STARTTLS/SSL."""
    port = int(port)
    if port == INT_IMAP_PORT:
        m = imaplib.IMAP4(host, port, timeout=timeout)   # داخلي — بدون TLS
    elif port == 143:
        m = imaplib.IMAP4(host, port, timeout=timeout)
        m.starttls(ssl.create_default_context())
    else:
        m = imaplib.IMAP4_SSL(host, port, timeout=timeout)
    m.login(email, password)
    return m


def _imap_login_test(host, port, email, password, timeout=15):
    m = _imap_open(host, port, email, password, timeout)
    try:
        m.logout()
    except Exception:
        pass
    return True


def _smtp_login_test(host, port, security, email, password, timeout=15):
    if security == "ssl":
        s = smtplib.SMTP_SSL(host, int(port), timeout=timeout, context=ssl.create_default_context())
    else:
        s = smtplib.SMTP(host, int(port), timeout=timeout)
        s.ehlo()
        if security == "starttls":
            s.starttls(context=ssl.create_default_context())
            s.ehlo()
    try:
        s.login(email, password)
    finally:
        try:
            s.quit()
        except Exception:
            pass
    return True


def _thunderbird_autoconfig(domain):
    """إعدادات من قاعدة Mozilla ISPDB (أفضل جهد، تتجاهل أي خطأ شبكة)."""
    import xml.etree.ElementTree as ET
    from urllib.request import urlopen, Request
    urls = [
        f"https://autoconfig.thunderbird.net/v1.1/{domain}",
        f"https://autoconfig.{domain}/mail/config-v1.1.xml",
        f"https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml",
    ]
    sec_map = {"SSL": "ssl", "STARTTLS": "starttls", "plain": "none", "none": "none"}
    for u in urls:
        try:
            with urlopen(Request(u, headers={"User-Agent": "EmailManager"}), timeout=6) as r:
                root = ET.fromstring(r.read())
            imap = root.find(".//incomingServer[@type='imap']")
            smtp = root.find(".//outgoingServer[@type='smtp']")
            if imap is None or smtp is None:
                continue

            def g(node, tag, dflt=""):
                e = node.find(tag)
                return e.text.strip() if e is not None and e.text else dflt
            return {
                "imap_server": g(imap, "hostname"),
                "imap_port": int(g(imap, "port", "993")),
                "smtp_server": g(smtp, "hostname"),
                "smtp_port": int(g(smtp, "port", "587")),
                "security": sec_map.get(g(smtp, "socketType", "STARTTLS"), "starttls"),
            }
        except Exception:
            continue
    return None


def autodiscover(email, password):
    """يكتشف إعدادات SMTP/IMAP بتجربة اتصال فعلي بكلمة المرور.
    يعيد dict {smtp_server, smtp_port, security, imap_server, imap_port}.
    يرمي RuntimeError برسالة عربية عند تعذّر الاتصال."""
    email = email.strip()
    domain = email.split("@")[-1].lower().strip()
    errs = []

    imap_candidates, smtp_candidates = [], []

    if domain in _MAIL_PROVIDERS:
        s, sp, sec, i, ip = _MAIL_PROVIDERS[domain]
        imap_candidates.append((i, ip))
        smtp_candidates.append((s, sp, sec))
    else:
        # 1) قاعدة Mozilla ISPDB / autoconfig الخاص بالنطاق
        tb = _thunderbird_autoconfig(domain)
        if tb and tb["imap_server"]:
            imap_candidates.append((tb["imap_server"], tb["imap_port"]))
            smtp_candidates.append((tb["smtp_server"], tb["smtp_port"], tb["security"]))
        # 2) هل النطاق مُدار عبر Microsoft 365 أو Google Workspace؟ (من سجلّات MX)
        mx = _mx_hosts(domain)
        if any("outlook" in m or "office365" in m or "protection.outlook" in m for m in mx):
            imap_candidates.append(_M365_IMAP)
            smtp_candidates.append(_M365_SMTP)
        if any("google" in m or "googlemail" in m or "aspmx" in m for m in mx):
            imap_candidates.append(_GW_IMAP)
            smtp_candidates.append(_GW_SMTP)
        # 3) أنماط الأسماء الشائعة على خوادم النطاق نفسه
        for h in (f"imap.{domain}", f"mail.{domain}", domain,
                  f"imap.mail.{domain}", f"mx.{domain}", f"webmail.{domain}"):
            imap_candidates.append((h, 993))
            imap_candidates.append((h, 143))          # IMAP STARTTLS (نادراً لكن موجود)
        for h in (f"smtp.{domain}", f"mail.{domain}", domain,
                  f"smtp.mail.{domain}", f"send.{domain}"):
            smtp_candidates.append((h, 587, "starttls"))
            smtp_candidates.append((h, 465, "ssl"))

    imap_ok = None
    seen = set()
    for host, port in imap_candidates:
        if not host or (host, port) in seen:
            continue
        seen.add((host, port))
        try:
            _imap_login_test(host, port, email, password)
            imap_ok = (host, port)
            break
        except Exception as e:  # noqa: BLE001
            errs.append(f"IMAP {host}:{port} → {e}")
    if not imap_ok:
        raise RuntimeError("تعذّر الاتصال بخادم IMAP أو كلمة المرور غير صحيحة. "
                           + (errs[-1] if errs else ""))

    smtp_ok = None
    seen = set()
    for host, port, sec in smtp_candidates:
        if not host or (host, port) in seen:
            continue
        seen.add((host, port))
        try:
            _smtp_login_test(host, port, sec, email, password)
            smtp_ok = (host, port, sec)
            break
        except Exception as e:  # noqa: BLE001
            errs.append(f"SMTP {host}:{port} → {e}")
    if not smtp_ok:
        raise RuntimeError("تعذّر الاتصال بخادم SMTP. " + (errs[-1] if errs else ""))

    return {"imap_server": imap_ok[0], "imap_port": imap_ok[1],
            "smtp_server": smtp_ok[0], "smtp_port": smtp_ok[1], "security": smtp_ok[2]}


def verify_account_full(acct):
    """تحقق SMTP + IMAP لحساب (dict فيه الحقول وكلمة المرور المشفّرة)."""
    pw = decrypt_secret(acct["password"])
    try:
        _imap_login_test(acct["imap_server"], acct["imap_port"], acct["email"], pw)
    except Exception as e:  # noqa: BLE001
        return False, f"IMAP: {e}"
    try:
        _smtp_login_test(acct["smtp_server"], acct["smtp_port"], acct["security"], acct["email"], pw)
    except Exception as e:  # noqa: BLE001
        return False, f"SMTP: {e}"
    return True, "تم الاتصال بنجاح (SMTP + IMAP)"


def _set_account_verified(conn, account_id, ok):
    conn.execute("UPDATE accounts SET verify_ok=?, last_verified=? WHERE id=?",
                 (1 if ok else 0,
                  datetime.now().isoformat(timespec="seconds") if ok else None,
                  account_id))
    conn.commit()


# ============================================================ طبقة البريد الحيّة (وضع أوتلوك)
# لا تُخزَّن أي رسالة على القرص — السيرفر هو المصدر الوحيد للحقيقة.
# نفتح جلسة IMAP لكل صندوق ونعيد استخدامها، ونجلب العناوين فقط عند عرض
# القائمة، وجسم الرسالة والمرفقات عند فتحها. حالة «مقروء/مردود عليه/مهم»
# كلها أعلام (FLAGS) على السيرفر، والحذف نقل لمجلد المحذوفات — زي أوتلوك.

IMAP_SESSION_TTL = 240        # ثانية: بعدها نعيد فتح الجلسة
IMAP_NOOP_AFTER = 25          # ثانية: بعدها نتأكد أن الجلسة حيّة قبل الاستخدام
MAIL_PAGE_SIZE = 50           # عدد الرسائل في صفحة القائمة


# ------------------------------------------------- Modified UTF-7 (أسماء المجلدات)
def imap_utf7_decode(name):
    """يحوّل اسم مجلد IMAP (Modified UTF-7) إلى نص مقروء."""
    if isinstance(name, bytes):
        name = name.decode("ascii", "replace")
    out, i = [], 0
    while i < len(name):
        ch = name[i]
        if ch != "&":
            out.append(ch)
            i += 1
            continue
        j = name.find("-", i)
        if j < 0:
            out.append(name[i:])
            break
        chunk = name[i + 1:j]
        if not chunk:
            out.append("&")
        else:
            try:
                data = chunk.replace(",", "/")
                data += "=" * (-len(data) % 4)
                out.append(base64.b64decode(data).decode("utf-16-be"))
            except Exception:
                out.append(name[i:j + 1])
        i = j + 1
    return "".join(out)


def imap_utf7_encode(name):
    """يحوّل اسم مجلد مقروء إلى Modified UTF-7 لإرساله للسيرفر."""
    out, buf = [], []

    def flush():
        if buf:
            raw = base64.b64encode("".join(buf).encode("utf-16-be")).decode("ascii")
            out.append("&" + raw.rstrip("=").replace("/", ",") + "-")
            del buf[:]

    for ch in name:
        if ch == "&":
            flush()
            out.append("&-")
        elif 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append(ch)
        else:
            buf.append(ch)
    flush()
    return "".join(out)


def _q(folder):
    """اسم مجلد جاهز لأمر IMAP (مشفّر UTF-7 وبين علامتي اقتباس)."""
    safe = imap_utf7_encode(folder).replace("\\", "\\\\").replace('"', '\\"')
    return '"%s"' % safe


# ------------------------------------------------- تجميع الجلسات (اتصال لكل صندوق)
class _MailSession:
    def __init__(self, key):
        self.key = key
        self.conn = None
        self.sel = None          # (folder, readonly)
        self.last = 0.0
        self.lock = threading.RLock()

    def close(self):
        if self.conn is not None:
            try:
                self.conn.logout()
            except Exception:
                pass
        self.conn = None
        self.sel = None


_sessions = {}
_sessions_lock = threading.Lock()


def _session_key(acct):
    return ((acct["email"] or "").lower(), acct["imap_server"], int(acct["imap_port"]))


def _session_for(acct):
    key = _session_key(acct)
    with _sessions_lock:
        s = _sessions.get(key)
        if s is None:
            s = _MailSession(key)
            _sessions[key] = s
        return s


def close_mail_sessions(acct=None):
    """يقفل جلسة صندوق واحد أو كل الجلسات (عند تعديل/حذف حساب أو الإغلاق)."""
    with _sessions_lock:
        if acct is None:
            targets = list(_sessions.values())
            _sessions.clear()
        else:
            key = _session_key(acct)
            targets = [_sessions.pop(key)] if key in _sessions else []
    for s in targets:
        with s.lock:
            s.close()


@contextmanager
def imap_conn(acct):
    """جلسة IMAP حيّة لهذا الصندوق (تُعاد تهيئتها تلقائياً عند انقطاعها)."""
    s = _session_for(acct)
    s.lock.acquire()
    try:
        now = time.time()
        if s.conn is not None and now - s.last > IMAP_SESSION_TTL:
            s.close()
        if s.conn is not None and now - s.last > IMAP_NOOP_AFTER:
            try:
                s.conn.noop()
            except Exception:
                s.close()
        if s.conn is None:
            s.conn = _imap_open(acct["imap_server"], acct["imap_port"],
                                acct["email"], decrypt_secret(acct["password"]))
            s.sel = None
        try:
            yield s
        except Exception:
            s.close()
            raise
        s.last = time.time()
    finally:
        s.lock.release()


def _caps(s):
    try:
        return {c.upper() for c in (s.conn.capabilities or ())}
    except Exception:
        return set()


def _first(data):
    try:
        v = data[0]
        return v.decode(errors="ignore") if isinstance(v, bytes) else str(v)
    except Exception:
        return ""


def _select(s, folder, readonly=True):
    if s.sel == (folder, readonly):
        return
    typ, data = s.conn.select(_q(folder), readonly=readonly)
    if typ != "OK":
        s.sel = None
        raise RuntimeError("تعذّر فتح المجلد %s: %s" % (folder, _first(data)))
    s.sel = (folder, readonly)


# ------------------------------------------------- المجلدات
_LIST_RE = re.compile(r'^\((?P<flags>[^)]*)\)\s+(?:"(?P<delim>[^"]*)"|NIL)\s+(?P<name>.+)$')

FOLDER_LABELS = {
    "inbox": "البريد الوارد",
    "drafts": "المسودّات",
    "sent": "العناصر المرسلة",
    "trash": "المحذوفات",
    "junk": "البريد العشوائي",
    "archive": "الأرشيف",
}
FOLDER_ICONS = {
    "inbox": "bi-inbox-fill", "drafts": "bi-file-earmark-text", "sent": "bi-send-fill",
    "trash": "bi-trash-fill", "junk": "bi-exclamation-octagon-fill",
    "archive": "bi-archive-fill", "other": "bi-folder-fill",
}
_FOLDER_ORDER = {"inbox": 0, "drafts": 1, "sent": 2, "trash": 3, "junk": 4, "archive": 5,
                 "other": 6}

_KIND_RULES = [
    ("inbox", ("\\inbox",), ("inbox", "الوارد", "البريد الوارد")),
    ("sent", ("\\sent",), ("sent", "sent items", "sent mail", "sent messages",
                           "المرسل", "العناصر المرسلة", "البريد المرسل")),
    ("drafts", ("\\drafts",), ("draft", "drafts", "المسودات", "مسودات", "المسودّات")),
    ("trash", ("\\trash", "\\deleted"), ("trash", "deleted", "deleted items", "bin",
                                         "المحذوفات", "سلة المحذوفات", "العناصر المحذوفة")),
    ("junk", ("\\junk", "\\spam"), ("junk", "spam", "bulk mail", "junk e-mail",
                                    "العشوائي", "البريد العشوائي", "الرسائل غير المرغوبة")),
    ("archive", ("\\archive",), ("archive", "archives", "الأرشيف")),
]


def _folder_kind(flags_low, name_low):
    leaf = name_low.rsplit("/", 1)[-1].rsplit(".", 1)[-1].strip()
    for kind, flags, names in _KIND_RULES:
        if any(f in flags_low for f in flags):
            return kind
        if leaf in names or name_low in names:
            return kind
    return "other"


def _parse_list_line(line):
    """يعيد (flags, raw_name) من سطر LIST مهما كان شكله."""
    if isinstance(line, tuple):
        head = (line[0] or b"").decode("ascii", "replace")
        raw_name = (line[1] or b"").decode("ascii", "replace")
        flags = head[head.find("(") + 1:head.find(")")] if "(" in head else ""
        return flags, raw_name
    txt = (line or b"").decode("ascii", "replace").strip()
    m = _LIST_RE.match(txt)
    if not m:
        return None, None
    raw_name = m.group("name").strip()
    if raw_name.startswith('"') and raw_name.endswith('"'):
        raw_name = raw_name[1:-1]
    raw_name = raw_name.replace('\\"', '"').replace("\\\\", "\\")
    return m.group("flags"), raw_name


def mail_folders(acct, counts=True):
    """كل مجلدات السيرفر مع عدد الرسائل وغير المقروء (جزء المجلدات في أوتلوك)."""
    with imap_conn(acct) as s:
        typ, data = s.conn.list()
        if typ != "OK" or not data:
            return []
        rows, seen_kinds = [], set()
        for line in data:
            flags, raw_name = _parse_list_line(line)
            if raw_name is None:
                continue
            flags_low = (flags or "").lower()
            if "\\noselect" in flags_low or "\\nonexistent" in flags_low:
                continue
            name = imap_utf7_decode(raw_name)
            kind = _folder_kind(flags_low, name.lower())
            if kind != "other" and kind in seen_kinds:
                kind = "other"
            seen_kinds.add(kind)
            rows.append({
                "name": name, "kind": kind,
                "label": FOLDER_LABELS.get(kind) or name.rsplit("/", 1)[-1],
                "icon": FOLDER_ICONS.get(kind, FOLDER_ICONS["other"]),
                "total": None, "unseen": 0,
            })
        rows.sort(key=lambda r: (_FOLDER_ORDER.get(r["kind"], 9), r["name"].lower()))
        if counts:
            for r in rows[:40]:
                try:
                    typ, d = s.conn.status(_q(r["name"]), "(MESSAGES UNSEEN)")
                    if typ == "OK" and d:
                        txt = d[0].decode(errors="ignore")
                        mt = re.search(r"MESSAGES\s+(\d+)", txt, re.I)
                        mu = re.search(r"UNSEEN\s+(\d+)", txt, re.I)
                        r["total"] = int(mt.group(1)) if mt else None
                        r["unseen"] = int(mu.group(1)) if mu else 0
                except Exception as exc:  # noqa: BLE001
                    log.debug("STATUS %s: %s", r["name"], exc)
        return rows


def folder_by_kind(folders, kind, fallback="INBOX"):
    for f in folders or []:
        if f["kind"] == kind:
            return f["name"]
    return fallback


# ------------------------------------------------- قائمة الرسائل (العناوين فقط)
_UID_RE = re.compile(rb"UID\s+(\d+)")
_FLAGS_RE = re.compile(rb"FLAGS\s+\(([^)]*)\)")
_SIZE_RE = re.compile(rb"RFC822\.SIZE\s+(\d+)")
_INTDATE_RE = re.compile(rb'INTERNALDATE\s+"([^"]+)"')
_HDR_FIELDS = "(FROM TO CC SUBJECT DATE MESSAGE-ID)"


def _search_uids(s, query="", unseen_only=False):
    """UIDs مرتّبة من الأحدث للأقدم (يستخدم SORT لو السيرفر يدعمه)."""
    caps = _caps(s)
    crit, literal = [], None
    if unseen_only:
        crit.append("UNSEEN")
    query = (query or "").strip()
    if query:
        if query.isascii():
            safe = query.replace("\\", "").replace('"', "")
            crit += ["OR", "OR", "FROM", '"%s"' % safe, "SUBJECT", '"%s"' % safe,
                     "TEXT", '"%s"' % safe]
        else:
            crit += ["TEXT"]
            literal = query.encode("utf-8")
    if not crit:
        crit = ["ALL"]

    def _run(cmd, *args):
        if literal is not None:
            s.conn.literal = literal
        return s.conn.uid(cmd, *args)

    if "SORT" in caps:
        try:
            typ, data = _run("SORT", "(REVERSE DATE)", "UTF-8", *crit)
            if typ == "OK" and data:
                return (data[0] or b"").split()
        except Exception as exc:  # noqa: BLE001
            log.debug("SORT غير متاح فعلياً، سنستخدم SEARCH: %s", exc)
    args = (["CHARSET", "UTF-8"] + crit) if literal is not None else crit
    typ, data = _run("SEARCH", *args)
    if typ != "OK" or not data:
        return []
    uids = (data[0] or b"").split()
    uids.reverse()          # الأحدث أولاً
    return uids


def _parse_headers_fetch(data):
    recs, order, cur = {}, [], None
    for item in data:
        if isinstance(item, tuple):
            prefix, payload = item[0] or b"", item[1] or b""
        else:
            prefix, payload = item or b"", b""
        m = _UID_RE.search(prefix)
        if m:
            cur = int(m.group(1))
            if cur not in recs:
                recs[cur] = {"uid": cur, "flags": b"", "size": 0, "idate": None,
                             "hdr": b"", "attach": False}
                order.append(cur)
        if cur is None:
            continue
        r = recs[cur]
        mf = _FLAGS_RE.search(prefix)
        if mf:
            r["flags"] = mf.group(1)
        ms = _SIZE_RE.search(prefix)
        if ms:
            r["size"] = int(ms.group(1))
        mi = _INTDATE_RE.search(prefix)
        if mi:
            r["idate"] = mi.group(1).decode(errors="ignore")
        if b'"attachment"' in prefix.lower():
            r["attach"] = True
        if payload and not r["hdr"]:
            r["hdr"] = payload
    return [recs[u] for u in order]


def _msg_date(msg, idate):
    raw = msg.get("Date") if msg is not None else None
    if raw:
        try:
            return parsedate_to_datetime(raw).astimezone().replace(tzinfo=None)
        except Exception:
            pass
    if idate:
        try:
            tt = imaplib.Internaldate2tuple(b'INTERNALDATE "%s"' % idate.encode())
            return datetime.fromtimestamp(time.mktime(tt))
        except Exception:
            pass
    return None


def mail_list(acct, folder, page=1, per_page=MAIL_PAGE_SIZE, query="", unseen_only=False):
    """صفحة من رسائل المجلد — عناوين فقط، بدون تحميل الأجسام."""
    try:
        page = max(1, int(page or 1))
    except (TypeError, ValueError):
        page = 1
    items = []
    with imap_conn(acct) as s:
        _select(s, folder, readonly=True)
        uids = _search_uids(s, query, unseen_only)
        total = len(uids)
        start = (page - 1) * per_page
        chunk = uids[start:start + per_page]
        if chunk:
            typ, data = s.conn.uid(
                "FETCH", b",".join(chunk),
                "(UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE "
                "BODY.PEEK[HEADER.FIELDS %s])" % _HDR_FIELDS)
            if typ == "OK" and data:
                by_uid = {r["uid"]: r for r in _parse_headers_fetch(data)}
                for raw_uid in chunk:
                    r = by_uid.get(int(raw_uid))
                    if not r:
                        continue
                    msg = message_from_bytes(r["hdr"])
                    fname, faddr = parseaddr(_decode_hdr(msg.get("From")))
                    tname, taddr = parseaddr(_decode_hdr(msg.get("To")))
                    flags_low = r["flags"].decode(errors="ignore").lower()
                    dt = _msg_date(msg, r["idate"])
                    items.append({
                        "uid": r["uid"],
                        "from_name": fname or faddr or "",
                        "from_email": (faddr or "").lower(),
                        "to_name": tname or taddr or "",
                        "to_email": (taddr or "").lower(),
                        "subject": _decode_hdr(msg.get("Subject")) or "(بدون موضوع)",
                        "message_id": (_decode_hdr(msg.get("Message-ID")) or "").strip(),
                        "date": dt.isoformat(timespec="seconds") if dt else "",
                        "seen": "\\seen" in flags_low,
                        "answered": "\\answered" in flags_low,
                        "flagged": "\\flagged" in flags_low,
                        "draft": "\\draft" in flags_low,
                        "attach": r["attach"],
                        "size": r["size"],
                    })
    pages = max(1, (total + per_page - 1) // per_page)
    return {"items": items, "total": total, "page": min(page, pages), "pages": pages,
            "per_page": per_page}


# ------------------------------------------------- رسالة واحدة + المرفقات
def _is_attachment(part):
    disp = (part.get("Content-Disposition") or "").lower()
    if "attachment" in disp:
        return True
    if part.get_filename():
        return True
    ctype = part.get_content_type()
    if ctype in ("message/rfc822",):
        return False
    return part.get_content_maintype() not in ("text", "multipart") and "inline" not in disp


def _decode_text_part(part):
    try:
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return ""


def _part_html_text(msg):
    """يعيد (html, text) من رسالة MIME."""
    html_parts, text_parts = [], []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart" or _is_attachment(part):
                continue
            ctype = part.get_content_type()
            if ctype == "text/html":
                html_parts.append(_decode_text_part(part))
            elif ctype == "text/plain":
                text_parts.append(_decode_text_part(part))
    else:
        if msg.get_content_type() == "text/html":
            html_parts.append(_decode_text_part(msg))
        else:
            text_parts.append(_decode_text_part(msg))
    return ("\n".join(p for p in html_parts if p).strip(),
            "\n".join(p for p in text_parts if p).strip())


_SCRIPT_RE = re.compile(r"<(script|style|iframe|object|embed)[^>]*>.*?</\1>", re.S | re.I)
_SELFCLOSE_RE = re.compile(r"<(script|link|meta|iframe|object|embed)\b[^>]*/?>", re.I)
_ON_ATTR_RE = re.compile(r"""\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", re.I)
_JS_URL_RE = re.compile(r"""(href|src|action)\s*=\s*(["'])\s*javascript:[^"']*\2""", re.I)
_REMOTE_IMG_RE = re.compile(r"""(<img\b[^>]*?)\bsrc\s*=\s*(["'])(https?://[^"']+)\2""", re.I)


def sanitize_html(html, block_images=True):
    """تنظيف HTML الرسالة + حجب الصور الخارجية (سلوك أوتلوك الافتراضي)."""
    if not html:
        return "", False
    out = _SCRIPT_RE.sub(" ", html)
    out = _SELFCLOSE_RE.sub(" ", out)
    out = _ON_ATTR_RE.sub(" ", out)
    out = _JS_URL_RE.sub(r"\1=\2#\2", out)
    blocked = False
    if block_images:
        blocked = bool(_REMOTE_IMG_RE.search(out))
        out = _REMOTE_IMG_RE.sub(r"\1data-blocked=\2\3\2", out)
    return out, blocked


def mail_message(acct, folder, uid, mark_seen=True):
    """يجلب رسالة كاملة من السيرفر (ويعلّمها مقروءة عند الفتح مثل أوتلوك)."""
    uid = str(int(uid))
    flags_low, raw = "", b""
    with imap_conn(acct) as s:
        _select(s, folder, readonly=not mark_seen)
        typ, data = s.conn.uid("FETCH", uid, "(FLAGS BODY.PEEK[])")
        if typ != "OK" or not data or data[0] is None:
            raise LookupError("الرسالة لم تعد موجودة على السيرفر (نُقلت أو حُذفت)")
        flags = b""
        for item in data:
            head = item[0] if isinstance(item, tuple) else item
            mf = _FLAGS_RE.search(head or b"")
            if mf:
                flags = mf.group(1)
            if isinstance(item, tuple) and item[1]:
                raw = item[1]
        if not raw:
            raise LookupError("تعذّر تحميل الرسالة من السيرفر")
        flags_low = flags.decode(errors="ignore").lower()
        if mark_seen and "\\seen" not in flags_low:
            try:
                s.conn.uid("STORE", uid, "+FLAGS", r"(\Seen)")
                flags_low += r" \seen"
            except Exception as exc:  # noqa: BLE001
                log.debug("تعذّر تعليم الرسالة كمقروءة: %s", exc)

    msg = message_from_bytes(raw)
    html, text = _part_html_text(msg)
    atts = []
    for idx, part in enumerate(msg.walk()):
        if part.get_content_maintype() == "multipart" or not _is_attachment(part):
            continue
        try:
            size = len(part.get_payload(decode=True) or b"")
        except Exception:
            size = 0
        atts.append({"idx": idx, "filename": _decode_hdr(part.get_filename()) or "مرفق",
                     "ctype": part.get_content_type(), "size": size})
    dt = _msg_date(msg, None)
    fname, faddr = parseaddr(_decode_hdr(msg.get("From")))
    return {
        "uid": int(uid), "folder": folder, "raw_size": len(raw),
        "from_name": fname or faddr or "", "from_email": (faddr or "").lower(),
        "to": _decode_hdr(msg.get("To")), "cc": _decode_hdr(msg.get("Cc")),
        "subject": _decode_hdr(msg.get("Subject")) or "(بدون موضوع)",
        "message_id": (_decode_hdr(msg.get("Message-ID")) or "").strip(),
        "references": (_decode_hdr(msg.get("References")) or "").strip(),
        "date": dt.isoformat(timespec="seconds") if dt else "",
        "html": html, "text": text or _extract_body(msg),
        "attachments": atts,
        "seen": "\\seen" in flags_low, "answered": "\\answered" in flags_low,
        "flagged": "\\flagged" in flags_low,
    }


def mail_raw(acct, folder, uid):
    """الرسالة الخام من السيرفر."""
    uid = str(int(uid))
    with imap_conn(acct) as s:
        _select(s, folder, readonly=True)
        typ, data = s.conn.uid("FETCH", uid, "(BODY.PEEK[])")
        for item in data or []:
            if isinstance(item, tuple) and item[1]:
                return item[1]
    return b""


def mail_attachment(acct, folder, uid, idx):
    """ينزّل مرفقاً بعينه مباشرة من السيرفر."""
    msg = message_from_bytes(mail_raw(acct, folder, uid))
    for i, part in enumerate(msg.walk()):
        if i != int(idx):
            continue
        return (_decode_hdr(part.get_filename()) or "attachment",
                part.get_content_type(), part.get_payload(decode=True) or b"")
    raise LookupError("المرفق غير موجود")


# ------------------------------------------------- أعلام / نقل / حذف
def _uidset(uids):
    return ",".join(str(int(u)) for u in uids)


def mail_flag(acct, folder, uids, flag, on=True):
    r"""تعليم/إلغاء تعليم (\Seen, \Flagged, \Answered, \Deleted)."""
    if not uids:
        return 0
    with imap_conn(acct) as s:
        _select(s, folder, readonly=False)
        typ, _ = s.conn.uid("STORE", _uidset(uids), "+FLAGS" if on else "-FLAGS",
                            "(%s)" % flag)
        if typ != "OK":
            raise RuntimeError("تعذّر تعديل حالة الرسائل")
    return len(uids)


def _expunge(s, seq):
    try:
        if "UIDPLUS" in _caps(s):
            s.conn.uid("EXPUNGE", seq)
        else:
            s.conn.expunge()
    except Exception as exc:  # noqa: BLE001
        log.debug("expunge: %s", exc)


def mail_move(acct, folder, uids, dest):
    """نقل رسائل لمجلد آخر على السيرفر (UID MOVE أو COPY + حذف)."""
    if not uids or dest == folder:
        return 0
    with imap_conn(acct) as s:
        _select(s, folder, readonly=False)
        seq = _uidset(uids)
        if "MOVE" in _caps(s):
            typ, _ = s.conn.uid("MOVE", seq, _q(dest))
            if typ == "OK":
                return len(uids)
        typ, _ = s.conn.uid("COPY", seq, _q(dest))
        if typ != "OK":
            raise RuntimeError("تعذّر نقل الرسائل إلى %s" % dest)
        s.conn.uid("STORE", seq, "+FLAGS", r"(\Deleted)")
        _expunge(s, seq)
    return len(uids)


def mail_delete(acct, folder, uids, trash=None, purge=False):
    """حذف = نقل للمحذوفات، وحذف نهائي لو كنّا داخل المحذوفات (زي أوتلوك)."""
    if not uids:
        return 0, ""
    if purge or (trash and folder == trash) or not trash:
        with imap_conn(acct) as s:
            _select(s, folder, readonly=False)
            seq = _uidset(uids)
            s.conn.uid("STORE", seq, "+FLAGS", r"(\Deleted)")
            _expunge(s, seq)
        return len(uids), "تم الحذف نهائياً"
    n = mail_move(acct, folder, uids, trash)
    return n, "تم النقل إلى «%s»" % trash


def mail_append(acct, folder, raw_bytes, flags=r"(\Seen)"):
    """يحفظ رسالة في مجلد على السيرفر (نسخة المُرسَل / مسودّة)."""
    try:
        with imap_conn(acct) as s:
            s.conn.append(_q(folder), flags, imaplib.Time2Internaldate(time.time()),
                          raw_bytes)
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("تعذّر حفظ نسخة في %s لـ %s: %s", folder, acct.get("email"), exc)
        return False


def mailbox_quick_counts(acct):
    """عدّاد سريع للوارد (الإجمالي/غير المقروء) بدون فتح كل المجلدات."""
    with imap_conn(acct) as s:
        typ, d = s.conn.status(_q("INBOX"), "(MESSAGES UNSEEN)")
        if typ != "OK" or not d:
            return {"total": 0, "unseen": 0}
        txt = d[0].decode(errors="ignore")
        mt = re.search(r"MESSAGES\s+(\d+)", txt, re.I)
        mu = re.search(r"UNSEEN\s+(\d+)", txt, re.I)
        return {"total": int(mt.group(1)) if mt else 0,
                "unseen": int(mu.group(1)) if mu else 0}


# ------------------------------------------------------------------ منطق الحملات
def _fill_placeholders(text, emp):
    """استبدال بسيط للمتغيرات (بدون str.format حتى لا تكسر الأقواس { })."""
    def g(k):
        try:
            return emp[k] or ""
        except (KeyError, IndexError):
            return ""
    name = g("name")
    # الهاتف والموقع ثابتان لكل التواقيع (موحّدان من الإعدادات) — وليس من حقل الموظف
    company_phone = get_setting("company_phone", "920035640")
    company_site = get_setting("company_website", "www.solutionstech.sa")
    mapping = {
        "{name}": name,
        "{first_name}": name.split(" ")[0] if name else "",
        "{email}": g("email"),
        "{title}": g("title"),
        "{department}": g("department"),
        "{phone}": company_phone,
        "{company_phone}": company_phone,
        "{website}": company_site,
        "{site}": company_site,
    }
    for key, val in mapping.items():
        text = text.replace(key, val)
    return text


def _render_sig_text(tpl, entity):
    """يملأ قالب توقيع ببيانات كيان (موظف/حساب) ويحذف الأسطر الفارغة."""
    if not (tpl or "").strip():
        return ""
    lines = []
    for ln in _fill_placeholders(tpl, entity).split("\n"):
        if ln.strip() in ("", "هاتف:", "هاتف: ", "Tel:", "Phone:"):
            continue
        lines.append(ln)
    return "\n".join(lines).strip()


def resolve_signature(conn, emp):
    """يحسب توقيع الموظف بالتتابع: توقيعه الخاص ← توقيع حسابه الرئيسي ← القالب العام.
    يعيد (نص التوقيع, اللوجو). emp = صف/قاموس فيه signature, logo, owner_account_id + الحقول."""
    def gv(k):
        try:
            return emp[k]
        except (KeyError, IndexError, TypeError):
            return emp.get(k) if isinstance(emp, dict) else ""
    own_sig = (gv("signature") or "").strip()
    own_logo = gv("logo") or ""
    if own_sig:
        return _render_sig_text(own_sig, emp), own_logo
    owner_id = gv("owner_account_id")
    if owner_id:
        acc = conn.execute("SELECT signature, logo FROM accounts WHERE id=?",
                           (owner_id,)).fetchone()
        if acc and (acc["signature"] or "").strip():
            return _render_sig_text(acc["signature"], emp), (own_logo or acc["logo"])
    return _render_sig_text(get_setting("signature_template", ""), emp), own_logo


def render_signature(emp, signature_template=None):
    """توقيع الموظف: تعديله اليدوي إن وُجد، وإلا قالب التوقيع العام مملوءاً ببياناته."""
    try:
        override = (emp["signature"] or "").strip()
    except (KeyError, IndexError):
        override = ""
    if override:
        return _fill_placeholders(override, emp).strip()
    tpl = signature_template if signature_template is not None else get_setting("signature_template", "")
    tpl = (tpl or "").strip()
    if not tpl:
        return ""
    # احذف الأسطر التي أصبحت فارغة بعد الاستبدال (حقول ناقصة)
    lines = []
    for ln in _fill_placeholders(tpl, emp).split("\n"):
        stripped = ln.strip()
        if stripped in ("", "هاتف:", "هاتف: ", "Tel:", "Phone:"):
            continue
        lines.append(ln)
    return "\n".join(lines).strip()


def render_email_body(template_row, employee_row, signature_template=None):
    body = _fill_placeholders(template_row["body"] or "", employee_row)
    sig = render_signature(employee_row, signature_template)
    if not sig:
        sig = (template_row["signature"] or "").strip()   # fallback: توقيع القالب
    return (body + ("\n\n" + sig if sig else "")).strip()


_batch_lock = threading.Lock()


def _account_send_counts(cur, account_id):
    """عدد الرسائل الناجحة من هذا الحساب خلال آخر ساعة / آخر 24 ساعة."""
    now = datetime.now()
    hour_ago = (now - timedelta(hours=1)).isoformat(timespec="seconds")
    day_ago = (now - timedelta(days=1)).isoformat(timespec="seconds")
    h = cur.execute("SELECT COUNT(*) c FROM sent_emails WHERE account_id=? AND status='sent' "
                    "AND sent_at >= ?", (account_id, hour_ago)).fetchone()["c"]
    d = cur.execute("SELECT COUNT(*) c FROM sent_emails WHERE account_id=? AND status='sent' "
                    "AND sent_at >= ?", (account_id, day_ago)).fetchone()["c"]
    return h, d


def _batch_config(cur):
    def gi(key, default):
        row = cur.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
        try:
            return int(row["value"])
        except (TypeError, ValueError):
            return default
    return {
        "min_delay": max(0, gi("send_min_delay", 8)),
        "max_delay": max(0, gi("send_max_delay", 25)),
        "hourly_limit": max(0, gi("per_account_hourly_limit", 0)),
        "daily_limit": max(0, gi("per_account_daily_limit", 0)),
        "randomize": gi("randomize_send", 1) == 1,
        "save_to_sent": gi("save_to_sent", 1) == 1,
    }


def process_batch(limit=None):
    """يرسل دفعة واحدة من المستلمين المعلّقين، موزَّعة على الحسابات النشطة،
    مع تأخير عشوائي بين كل رسالة واحترام حدود كل حساب. لا تعمل دفعتان معاً."""
    if not _batch_lock.acquire(blocking=False):
        return {"sent": 0, "failed": 0, "skipped": 0, "message": "دفعة قيد التنفيذ بالفعل"}
    try:
        return _process_batch_inner(limit)
    finally:
        _batch_lock.release()


def _process_batch_inner(limit):
    conn = get_connection()
    cur = conn.cursor()

    s = cur.execute("SELECT * FROM schedule_settings WHERE id = 1").fetchone()
    batch_size = limit or (s["batch_size"] if s else 10)
    cfg = _batch_config(cur)
    sig_tpl = get_setting("signature_template", "")
    sig_style = get_setting("signature_style", "rich")
    # تاريخ/وقت إرسال عام (من إعدادات الجدولة) — يُستخدم كاحتياطي لو الحملة ملهاش تاريخ خاص
    def _parse_date(d, t):
        d = (d or "").strip()
        if not d:
            return None
        t = (t or "12:00").strip() or "12:00"
        try:
            return datetime.fromisoformat(d + "T" + t)
        except ValueError:
            return None
    global_campaign_date = _parse_date(get_setting("campaign_send_date", ""),
                                       get_setting("campaign_send_time", ""))

    accounts = cur.execute("SELECT * FROM accounts WHERE active = 1 ORDER BY id").fetchall()
    if not accounts:
        conn.close()
        return {"sent": 0, "failed": 0, "skipped": 0, "message": "لا توجد حسابات نشطة"}

    # نظام داخلي بالكامل: التسليم فوري محلياً، فلا داعي لتقطيع الإرسال على دفعات
    # متكرّرة — نرسل كل المستحق دفعة واحدة حتى تخلص الحملة فوراً ولا تتكرر.
    all_internal = all((a["internal"] if "internal" in a.keys() else 0) for a in accounts)
    if limit is None and all_internal:
        batch_size = 1000000

    order = "RANDOM()" if cfg["randomize"] else "r.id"
    now_iso = datetime.now().isoformat(timespec="seconds")
    rows = cur.execute(f"""
        SELECT r.id AS rid, r.campaign_id, r.employee_id, e.owner_account_id,
               e.name, e.email, e.title, e.department, e.phone, e.signature,
               t.subject, t.body, t.signature AS tpl_signature,
               c.send_date AS c_send_date, c.send_time AS c_send_time
        FROM campaign_recipients r
        JOIN campaigns c ON c.id = r.campaign_id
        JOIN employees e ON e.id = r.employee_id
        JOIN templates t ON t.id = COALESCE(
            (SELECT dt.template_id FROM campaign_dept_templates dt
             WHERE dt.campaign_id = r.campaign_id AND dt.department = e.department),
            c.template_id)
        WHERE r.status = 'pending' AND c.status = 'active' AND e.active = 1
          AND (c.send_date='' OR
               (c.send_date || 'T' ||
                CASE WHEN c.send_time='' THEN '12:00' ELSE c.send_time END) <= ?)
        ORDER BY {order}
        LIMIT ?
    """, (now_iso, batch_size)).fetchall()

    if not rows:
        conn.close()
        return {"sent": 0, "failed": 0, "skipped": 0, "message": "لا يوجد مستلمون بانتظار الإرسال"}

    sent = failed = skipped = 0
    rr = 0
    touched = set()
    stop_reason = ""
    by_id = {a["id"]: a for a in accounts}

    # توزيع الإرسال الداخلي على مدة (افتراضي 60 ثانية): فجوة بين كل رسالة = المدة/العدد
    spread_total = max(0, _gi("campaign_spread_seconds", 60))
    internal_gap = (spread_total / len(rows)) if (all_internal and len(rows) > 0) else 0

    for idx, row in enumerate(rows):
        # احترام الإيقاف/الإلغاء أثناء الإرسال: لو الحملة اتوقفت أو اتحذفت → سيب الباقي
        if _stop_event.is_set():
            stop_reason = "تم إيقاف الإرسال"
            break
        _cs = cur.execute("SELECT status FROM campaigns WHERE id=?",
                          (row["campaign_id"],)).fetchone()
        if not _cs or _cs[0] != "active":
            continue   # الحملة دي اتوقفت/اتحذفت — ما نكملش إرسالها
        # اختر حساباً لم يتجاوز حدّه الساعي/اليومي
        available = []
        for a in accounts:
            h, d = _account_send_counts(cur, a["id"])
            if (cfg["hourly_limit"] == 0 or h < cfg["hourly_limit"]) and \
               (cfg["daily_limit"] == 0 or d < cfg["daily_limit"]):
                available.append(a)
        if not available:
            skipped = len(rows) - idx
            stop_reason = "توقّفت الدفعة: كل الحسابات وصلت الحد المسموح به"
            break

        # الموظف المرتبط بحساب مسؤول يُرسَل منه هو فقط
        owner_id = row["owner_account_id"]
        if owner_id and owner_id in by_id:
            if not any(a["id"] == owner_id for a in available):
                skipped += 1          # حسابه المسؤول بلغ حدّه — يُؤجَّل للدورة القادمة
                continue
            account = by_id[owner_id]
        else:
            account = random.choice(available) if cfg["randomize"] else available[rr % len(available)]
            rr += 1

        # تاريخ الحملة: الخاص بها إن وُجد، وإلا العام من الجدولة
        campaign_date = (_parse_date(row["c_send_date"], row["c_send_time"])
                         or global_campaign_date)
        emp = {"name": row["name"], "email": row["email"], "title": row["title"],
               "department": row["department"], "phone": row["phone"],
               "signature": row["signature"]}
        tpl = {"body": row["body"], "signature": row["tpl_signature"]}
        full_body = render_email_body(tpl, emp, sig_tpl)
        subject = _fill_placeholders(row["subject"] or "", emp)

        acc_internal = ("internal" in account.keys() and account["internal"])
        # قاعدة صارمة: ما نكررش نفس رسالة الحملة لنفس الموظف مهما حصل
        if acc_internal and row["campaign_id"] and cur.execute(
                "SELECT 1 FROM mail_messages WHERE box_email=? AND folder='inbox' AND campaign_id=?",
                (row["email"].lower(), row["campaign_id"])).fetchone():
            cur.execute("UPDATE campaign_recipients SET status='sent', attempts=attempts+1, "
                        "sent_at=? WHERE id=?",
                        (datetime.now().isoformat(timespec="seconds"), row["rid"]))
            conn.commit()
            touched.add(row["campaign_id"])
            continue
        if acc_internal:
            # المحتوى مشخصن للمستقبِل + توقيع ولوجو الحساب الرئيسي المرسِل
            content = _fill_placeholders(row["body"] or "", emp)
            html = _text_to_html(content)
            acc_as_entity = {"name": account["display_name"] or "", "email": account["email"],
                             "title": "", "department": "", "phone": ""}
            acc_logo = _effective_logo(account["logo"] if "logo" in account.keys() else "")
            if sig_style == "rich":
                sig_html = _rich_signature_html(acc_as_entity, acc_logo)
            else:
                acc_sig = _fill_placeholders(
                    account["signature"] if "signature" in account.keys() else "", acc_as_entity)
                acc_sig = "\n".join(ln for ln in acc_sig.split("\n")
                                    if ln.strip() not in ("", "هاتف:", "Phone:", "Tel:")).strip()
                sig_html = _signature_html(acc_sig, acc_logo)
            if sig_html:
                html += "<br><br>" + sig_html
            ok, message = internal_deliver(
                account["email"], account["display_name"] or "", row["email"], subject, html,
                date_override=campaign_date, campaign_id=row["campaign_id"])
        else:
            ok, message = send_email(account, row["email"], subject, full_body,
                                     save_to_sent=cfg["save_to_sent"])
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute("""UPDATE campaign_recipients
                       SET status=?, attempts=attempts+1, error=?, account_id=?, sent_at=?
                       WHERE id=?""",
                    ("sent" if ok else "failed", None if ok else message,
                     account["id"], now if ok else None, row["rid"]))
        cur.execute("""INSERT INTO sent_emails (account_id, employee_id, campaign_id, to_email,
                                                subject, body, status, error, sent_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (account["id"], row["employee_id"], row["campaign_id"], row["email"],
                     subject, full_body, "sent" if ok else "failed",
                     None if ok else message, now))
        conn.commit()   # ثبّت التقدّم بعد كل رسالة
        touched.add(row["campaign_id"])
        sent += ok
        failed += (not ok)
        log.info("%s %s عبر %s", "OK " if ok else "FAIL", row["email"], account["email"])

        # الفاصل قبل الرسالة التالية:
        #  - داخلي: نوزّع كل الحملة على مدة spread (افتراضي 60 ثانية) فتخلص مرة واحدة
        #    بشكل منتظم بدل اللحظي أو الدفعات المتباعدة.
        #  - خارجي: تأخير عشوائي للحماية من البلوك.
        if idx < len(rows) - 1 and not _stop_event.is_set():
            if acc_internal:
                if internal_gap > 0:
                    _stop_event.wait(internal_gap)
            elif cfg["max_delay"] > 0:
                lo, hi = sorted((cfg["min_delay"], cfg["max_delay"]))
                _stop_event.wait(random.uniform(lo, hi))

    # علّم الحملات المكتملة
    for cid in touched:
        left = cur.execute("SELECT COUNT(*) c FROM campaign_recipients "
                           "WHERE campaign_id=? AND status='pending'", (cid,)).fetchone()["c"]
        if left == 0:
            cur.execute("UPDATE campaigns SET status='completed' WHERE id=? AND status='active'", (cid,))
    conn.commit()
    conn.close()

    msg = stop_reason or (f"تم إرسال {sent}" + (f" وفشل {failed}" if failed else "")
                          + (f" · {skipped} مؤجّل (حد الحساب المسؤول)" if skipped else ""))
    log.info("انتهت الدفعة: نجح=%d فشل=%d مؤجّل=%d", sent, failed, skipped)
    return {"sent": sent, "failed": failed, "skipped": skipped, "message": msg}


# ------------------------------------------------------------------ الرد العكسي (مؤجَّل)
# بعد ما تستلم صناديق الموظفين رسائل الحسابات الـ5، يُسجَّل كل رد في طابور
# بموعد استحقاق = وقت وصول الرسالة + التأخير (افتراضياً 15 دقيقة)، ثم يُرسَل
# الرد للحساب الذي أرسل بالضبط، بالنص المخصّص لذلك الحساب.
_reverse_lock = threading.Lock()
_reverse_scan_lock = threading.Lock()
_last_reverse_scan = [0.0]

REVERSE_DELAY_DEFAULT = 15        # دقيقة بين الاستلام والرد
REVERSE_SCAN_DEFAULT = 5          # دقيقة بين كل فحص لصناديق الموظفين


def _emp_account(emp):
    """يبني كائن حساب من بيانات الموظف. لو إعدادات سيرفر الموظفين غير مضبوطة،
    تُكتشف تلقائياً من نطاق بريد كل موظف."""
    def gi(key, dflt):
        try:
            return int(get_setting(key, str(dflt)))
        except (TypeError, ValueError):
            return dflt
    imap_server = (get_setting("emp_imap_server", "") or "").strip()
    smtp_server = (get_setting("emp_smtp_server", "") or "").strip()
    security    = (get_setting("emp_security", "") or "").strip()
    # نظام بريد داخلي بالكامل: عند غياب إعداد سيرفر الموظفين نوجّه الاتصال
    # لسيرفر البريد المدمج (127.0.0.1) بدل تخمين سيرفر خارجي من نطاق البريد
    # (التخمين الخارجي يفشل بـ DNS: "Name or service not known").
    return {
        "email": emp["email"],
        "display_name": emp["name"],
        "password": emp["password"],
        "smtp_server": smtp_server or LOCAL_MAIL_HOST,
        "smtp_port": gi("emp_smtp_port", 0) or INT_SMTP_PORT,
        "security": security or "none",
        "imap_server": imap_server or LOCAL_MAIL_HOST,
        "imap_port": gi("emp_imap_port", 0) or INT_IMAP_PORT,
    }


def _gi(key, dflt):
    try:
        return int(get_setting(key, str(dflt)))
    except (TypeError, ValueError):
        return dflt


def _reverse_reply_text(conn, emp, account_email, campaign_id=None):
    """نص الرد: رد القالب (لو الرسالة من حملة) ← نص الحساب المرسِل ← نص القسم ← الافتراضي."""
    # 0) رد خاص بالقالب المستخدَم في الحملة (الاستقبال المحدَّد داخل القالب)
    if campaign_id:
        trow = conn.execute(
            """SELECT t.reply_body FROM campaigns c JOIN templates t ON t.id=c.template_id
               WHERE c.id=?""", (campaign_id,)).fetchone()
        if trow and (trow["reply_body"] or "").strip():
            return trow["reply_body"]
    row = conn.execute("""SELECT r.body FROM account_replies r JOIN accounts a ON a.id=r.account_id
                          WHERE lower(a.email)=?""", (account_email.lower(),)).fetchone()
    if row and (row["body"] or "").strip():
        return row["body"]
    row = conn.execute("SELECT body FROM dept_replies WHERE department=?",
                       (emp["department"],)).fetchone()
    if row and (row["body"] or "").strip():
        return row["body"]
    return get_setting("reverse_default_reply", "") or ""


def _reverse_delay_minutes(conn, account_email):
    row = conn.execute("""SELECT r.delay_minutes FROM account_replies r
                          JOIN accounts a ON a.id=r.account_id
                          WHERE lower(a.email)=?""", (account_email.lower(),)).fetchone()
    if row and row["delay_minutes"]:
        return max(0, int(row["delay_minutes"]))
    return max(0, _gi("reverse_delay_minutes", REVERSE_DELAY_DEFAULT))


def scan_reverse_inboxes(limit=None):
    """يفحص دفعة من صناديق الموظفين ويُدرج الردود المستحقّة في الطابور."""
    if not _reverse_scan_lock.acquire(blocking=False):
        return {"queued": 0, "checked": 0, "message": "فحص جارٍ بالفعل"}
    try:
        conn = get_connection()
        cur = conn.cursor()
        senders = {r["email"].lower(): r["id"]
                   for r in cur.execute("SELECT id, email FROM accounts").fetchall()}
        if not senders:
            conn.close()
            return {"queued": 0, "checked": 0, "message": "لا توجد حسابات مرسِلة"}

        n = limit or _gi("reverse_batch_size", 20)
        emps = cur.execute("""
            SELECT * FROM employees
            WHERE active = 1 AND password != ''
            ORDER BY (emp_last_check IS NOT NULL), emp_last_check ASC, id ASC
            LIMIT ?
        """, (n,)).fetchall()
        if not emps:
            conn.close()
            return {"queued": 0, "checked": 0, "message": "لا يوجد موظفون ببيانات دخول"}

        queued = checked = 0
        now = datetime.now()
        for emp in emps:
            acct = _emp_account(emp)
            try:
                folders = cached_folders(acct)
                inbox_folder = folder_by_kind(folders, "inbox", "INBOX")
                res = mail_list(acct, inbox_folder, per_page=60, unseen_only=True)
                cur.execute("UPDATE employees SET emp_connected=1, emp_last_check=? WHERE id=?",
                            (now.isoformat(timespec="seconds"), emp["id"]))
            except Exception as exc:  # noqa: BLE001
                log.warning("رد عكسي: تعذّر فحص صندوق %s: %s", emp["email"], exc)
                cur.execute("UPDATE employees SET emp_connected=0, emp_last_check=? WHERE id=?",
                            (now.isoformat(timespec="seconds"), emp["id"]))
                conn.commit()
                continue
            checked += 1
            owner = emp["owner_account_id"] if "owner_account_id" in emp.keys() else None
            for m in res["items"]:
                sender = (m["from_email"] or "").lower()
                if sender not in senders or m["answered"]:
                    continue
                # الموظف يرد فقط على حسابه الرئيسي المالك له
                if owner and senders.get(sender) != owner:
                    continue
                msgid = m["message_id"] or ("uid:%s" % m["uid"])
                if cur.execute("SELECT 1 FROM emp_replies WHERE employee_id=? AND in_reply_to=?",
                               (emp["id"], msgid)).fetchone():
                    continue
                try:
                    received = datetime.fromisoformat(m["date"]) if m["date"] else now
                except ValueError:
                    received = now
                due = received + timedelta(minutes=_reverse_delay_minutes(conn, sender))
                cur.execute("""INSERT OR IGNORE INTO reverse_queue
                    (employee_id, account_email, folder, uid, msgid, subject,
                     received_at, due_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
                    (emp["id"], sender, inbox_folder, m["uid"], msgid, m["subject"],
                     received.isoformat(timespec="seconds"),
                     due.isoformat(timespec="seconds")))
                queued += cur.rowcount
            conn.commit()
        conn.close()
        log.info("فحص الرد العكسي: %d صندوق، %d رد في الطابور", checked, queued)
        return {"queued": queued, "checked": checked,
                "message": "فُحص %d صندوق · %d رد بانتظار موعده" % (checked, queued)}
    finally:
        _reverse_scan_lock.release()


def _email_domain_internal(conn, email):
    """هل دومين الإيميل ده من الدومينات الداخلية (mail_domains)؟"""
    dom = (email or "").rsplit("@", 1)[-1].lower()
    if not dom:
        return False
    return conn.execute("SELECT 1 FROM mail_domains WHERE lower(name)=?",
                        (dom,)).fetchone() is not None


def scan_reverse_internal(conn):
    """فحص داخلي: يدرج ردود الموظفين الداخليين في الطابور من mail_messages
    (بدون IMAP). أي رسالة وصلت صندوق موظف داخلي من حساب مرسِل تدخل الطابور."""
    senders = {r["email"].lower(): r["id"]
               for r in conn.execute("SELECT id, email FROM accounts").fetchall()}
    if not senders:
        return 0
    now = datetime.now()
    queued = 0
    emps = conn.execute("SELECT * FROM employees WHERE active=1").fetchall()
    for emp in emps:
        if not _email_domain_internal(conn, emp["email"]):
            continue
        owner = emp["owner_account_id"] if "owner_account_id" in emp.keys() else None
        msgs = conn.execute(
            "SELECT * FROM mail_messages WHERE box_email=? AND folder='inbox' AND is_replied=0",
            (emp["email"].lower(),)).fetchall()
        for m in msgs:
            sender = (m["from_email"] or "").lower()
            if sender not in senders:
                continue
            # الموظف يرد فقط على حسابه الرئيسي المالك له
            if owner and senders.get(sender) != owner:
                continue
            msgid = m["msg_id"] or ("imsg:%d" % m["id"])
            if conn.execute("SELECT 1 FROM emp_replies WHERE employee_id=? AND in_reply_to=?",
                            (emp["id"], msgid)).fetchone():
                continue
            try:
                received = datetime.fromisoformat(m["created_at"]) if m["created_at"] else now
            except ValueError:
                received = now
            # الافتراضي: الرد يوصل بعد N ثانية من استلام الرسالة (N=20 افتراضياً)
            delay_secs = max(0, _gi("reverse_delay_seconds", 20))
            base_due = received + timedelta(seconds=delay_secs)
            # لو الرسالة من حملة لها تاريخ تسليم محدّد:
            #  - تاريخ قديم (باك-ديت) → يُحترم كما هو (الرد يوصل بنفس التاريخ القديم)
            #  - تاريخ الآن/قريب → نطبّق تأخير الـ20 ثانية بعد الاستلام
            campaign_due = None
            cid = m["campaign_id"] if "campaign_id" in m.keys() else None
            if cid:
                crow = conn.execute("SELECT reply_date, reply_time FROM campaigns WHERE id=?",
                                    (cid,)).fetchone()
                if crow and (crow["reply_date"] or "").strip():
                    _rt = (crow["reply_time"] or "12:00").strip() or "12:00"
                    try:
                        campaign_due = datetime.fromisoformat(crow["reply_date"].strip() + "T" + _rt)
                    except ValueError:
                        campaign_due = None
            if campaign_due is not None:
                due = campaign_due if campaign_due <= received else max(campaign_due, base_due)
            else:
                due = base_due
            cur = conn.execute("""INSERT OR IGNORE INTO reverse_queue
                (employee_id, account_email, folder, uid, msgid, subject,
                 received_at, due_at, status)
                VALUES (?, ?, 'inbox', ?, ?, ?, ?, ?, 'pending')""",
                (emp["id"], sender, m["id"], msgid, m["subject"],
                 received.isoformat(timespec="seconds"), due.isoformat(timespec="seconds")))
            queued += cur.rowcount
    conn.commit()
    if queued:
        log.info("فحص الرد العكسي الداخلي: %d رد في الطابور", queued)
    return queued


def flush_reverse_queue(limit=None):
    """يرسل الردود التي حان موعدها (كل رد يذهب للحساب الذي أرسل أصلاً)."""
    if not _reverse_lock.acquire(blocking=False):
        return {"replied": 0, "failed": 0, "message": "دورة رد عكسي قيد التنفيذ"}
    try:
        conn = get_connection()
        cur = conn.cursor()
        now = datetime.now().isoformat(timespec="seconds")
        rows = cur.execute("""
            SELECT q.*, e.name, e.email AS emp_email, e.title, e.department, e.phone,
                   e.signature, e.logo, e.password, e.owner_account_id
            FROM reverse_queue q JOIN employees e ON e.id = q.employee_id
            WHERE q.status='pending' AND q.due_at <= ? AND e.active=1
            ORDER BY q.due_at ASC
            LIMIT ?
        """, (now, limit or 100)).fetchall()
        if not rows:
            conn.close()
            return {"replied": 0, "failed": 0, "message": "لا توجد ردود مستحقّة الآن"}

        lo, hi = sorted((max(0, _gi("reverse_min_delay", 8)),
                         max(0, _gi("reverse_max_delay", 25))))
        save_sent = get_setting("save_to_sent", "1") == "1"
        sig_tpl = get_setting("signature_template", "")
        sig_style = get_setting("signature_style", "rich")
        replied = failed = 0

        for row in rows:
            emp = {"name": row["name"], "email": row["emp_email"], "title": row["title"],
                   "department": row["department"], "phone": row["phone"],
                   "signature": row["signature"], "logo": row["logo"],
                   "owner_account_id": row["owner_account_id"], "password": row["password"]}
            acct = _emp_account(emp)
            # نحدّد حملة الرسالة الأصلية (uid = id صف mail_messages) لاختيار رد القالب الخاص بها
            camp_id = None
            if row["uid"]:
                _cr = conn.execute("SELECT campaign_id FROM mail_messages WHERE id=?",
                                   (row["uid"],)).fetchone()
                if _cr:
                    camp_id = _cr["campaign_id"]
            body_tpl = _reverse_reply_text(conn, emp, row["account_email"], camp_id)
            reply_text = _fill_placeholders(body_tpl, emp)
            sig_text, sig_logo = resolve_signature(conn, emp)
            # نص عادي (للسيرفر الخارجي) = الرد + التوقيع النصّي
            body = (reply_text + ("\n\n" + sig_text if sig_text else "")).strip()
            subject = row["subject"] or "(بدون موضوع)"
            if not subject.lower().startswith("re:"):
                subject = "Re: " + subject

            in_reply_to = row["msgid"] if (row["msgid"] or "").startswith("<") else None
            # تاريخ الرد = موعد استحقاقه (تاريخ الرسالة الأصلية + التأخير) عشان
            # الرد يوصل بنفس تاريخ الحملة لو كانت بتاريخ قديم
            try:
                reply_date = datetime.fromisoformat(row["due_at"]) if row["due_at"] else None
            except (TypeError, ValueError):
                reply_date = None
            is_internal = _email_domain_internal(conn, row["emp_email"])
            if is_internal:
                # رد داخلي: يتسلّم في صندوق الحساب الرئيسي داخل البرنامج
                if sig_style == "rich":
                    # التصميم الاحترافي: نص الرد ثم توقيع احترافي ببيانات الموظف
                    html = (_text_to_html(reply_text) + "<br><br>"
                            + _rich_signature_html(emp, _effective_logo(sig_logo)))
                else:
                    html = _signature_html(body, _effective_logo(sig_logo))
                ok, res = internal_deliver(row["emp_email"], row["name"] or "",
                                           row["account_email"], subject,
                                           html, in_reply_to=in_reply_to, conn=conn,
                                           date_override=reply_date)
                err = None if ok else res
                if ok and row["uid"]:
                    conn.execute("UPDATE mail_messages SET is_replied=1 WHERE id=?", (row["uid"],))
            else:
                sent_folder = None
                if save_sent:
                    try:
                        sent_folder = folder_by_kind(cached_folders(acct), "sent", "") or None
                    except Exception:  # noqa: BLE001
                        sent_folder = None
                ok, err = send_mail_full(acct, [row["account_email"]], [], subject, body,
                                         in_reply_to=in_reply_to, references=in_reply_to,
                                         sent_folder=sent_folder)
            stamp = datetime.now().isoformat(timespec="seconds")
            cur.execute("""UPDATE reverse_queue SET status=?, error=?, sent_at=?
                           WHERE id=?""",
                        ("sent" if ok else "failed", None if ok else err,
                         stamp if ok else None, row["id"]))
            cur.execute("""INSERT OR IGNORE INTO emp_replies
                (employee_id, sender_account, in_reply_to, subject, body, status, error)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (row["employee_id"], row["account_email"], row["msgid"], subject, body,
                 "sent" if ok else "failed", None if ok else err))
            conn.commit()
            replied += ok
            failed += (not ok)
            log.info("رد عكسي %s: %s → %s (تأخير حتى %s)",
                     "OK" if ok else "FAIL", row["emp_email"], row["account_email"],
                     row["due_at"])
            if ok and row["uid"] and not is_internal:
                try:
                    mail_flag(acct, row["folder"] or "INBOX", [row["uid"]], r"\Answered", True)
                    mail_flag(acct, row["folder"] or "INBOX", [row["uid"]], r"\Seen", True)
                except Exception as exc:  # noqa: BLE001
                    log.debug("تعليم الرسالة بعد الرد: %s", exc)
            if hi > 0 and not _stop_event.is_set():
                _stop_event.wait(random.uniform(lo, hi))

        conn.close()
        return {"replied": replied, "failed": failed,
                "message": "أُرسل %d رد%s" % (replied, (" وفشل %d" % failed) if failed else "")}
    finally:
        _reverse_lock.release()


def _scan_reverse_internal_safe(limit=None):
    conn = get_connection()
    try:
        return scan_reverse_internal(conn)
    finally:
        conn.close()


def process_reverse_batch(limit=None):
    """دورة كاملة: فحص الصناديق (داخلي + IMAP) ثم إرسال ما استحقّ من الردود."""
    if get_setting("reverse_enabled", "0") != "1":
        return {"replied": 0, "failed": 0, "message": "الرد العكسي غير مفعّل"}
    q_int = _scan_reverse_internal_safe(limit)
    scan = scan_reverse_inboxes(limit)
    out = flush_reverse_queue()
    out["queued"] = scan.get("queued", 0) + q_int
    out["message"] = "%s · داخلي: %d رد · %s" % (
        scan.get("message", ""), q_int, out.get("message", ""))
    return out


def reverse_tick():
    """تُستدعى من المُجدوِل: فحص دوري + إرسال ما حان موعده في كل دورة."""
    if get_setting("reverse_enabled", "0") != "1":
        return
    every = max(1, _gi("reverse_scan_minutes", REVERSE_SCAN_DEFAULT)) * 60
    now = time.time()
    _safe_call(_scan_reverse_internal_safe)   # الفحص الداخلي رخيص — كل دورة
    if now - _last_reverse_scan[0] >= every:
        _last_reverse_scan[0] = now
        _safe_call(scan_reverse_inboxes)
    _safe_call(flush_reverse_queue)


def _safe_call(fn, *args):
    try:
        return fn(*args)
    except Exception:  # noqa: BLE001
        log.exception("خطأ في مهمة الرد العكسي")
    return None


# ------------------------------------------------------------------ المُجدوِل
_stop_event = threading.Event()


def _scheduled_send_dt():
    """وقت بدء الإرسال المجدول من إعدادات الجدولة (تاريخ + وقت)، أو None لو غير محدّد."""
    d = (get_setting("campaign_send_date", "") or "").strip()
    if not d:
        return None
    t = (get_setting("campaign_send_time", "") or "12:00").strip() or "12:00"
    try:
        return datetime.fromisoformat(d + "T" + t)
    except ValueError:
        return None


# ------------------------------------------------------------------ المراقبة الذاتية + النسخ التلقائي
_health = {
    "db":   {"ok": True, "msg": "—", "ts": ""},
    "smtp": {"ok": True, "msg": "—", "ts": ""},
    "imap": {"ok": True, "msg": "—", "ts": ""},
    "last_backup": "",
    "last_check": "",
    "fixes": [],   # آخر إجراءات الإصلاح الذاتي
}
_health_lock = threading.Lock()
_last_health_check = [0.0]
_last_autobackup = [0.0]


def _port_listening(port, host="127.0.0.1", timeout=2):
    """هل فيه حاجة بتسمع على المنفذ ده؟"""
    try:
        with _socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _restart_int_server(port, handler, name):
    """يعيد تشغيل سيرفر داخلي (يُستدعى فقط لو مفيش حد بيسمع على المنفذ)."""
    try:
        threading.Thread(target=_int_server_loop, args=(port, handler, name),
                         daemon=True).start()
        _stop_event.wait(1.0)
        return _port_listening(port)
    except Exception:  # noqa: BLE001
        log.exception("فشل إعادة تشغيل سيرفر %s", name)
        return False


def health_tick():
    """فحص صحّة النظام + إصلاح ذاتي: قاعدة البيانات + سيرفرات البريد الداخلية."""
    now = datetime.now().isoformat(timespec="seconds")
    fixes = []
    # 1) قاعدة البيانات
    try:
        c = get_connection()
        c.execute("SELECT 1").fetchone()
        c.close()
        db_ok, db_msg = True, "متصلة"
    except Exception as exc:  # noqa: BLE001
        db_ok, db_msg = False, str(exc)[:140]
        log.warning("فحص الصحّة: قاعدة البيانات متعثّرة — %s", db_msg)
    # 2) سيرفرات البريد الداخلية (إعادة تشغيل تلقائي لو وقعت)
    smtp_ok = imap_ok = True
    if INT_MAIL_ENABLED:
        smtp_ok = _port_listening(INT_SMTP_PORT)
        if not smtp_ok:
            smtp_ok = _restart_int_server(INT_SMTP_PORT, _int_smtp_client, "SMTP")
            fixes.append("إعادة تشغيل سيرفر SMTP الداخلي" + ("" if smtp_ok else " (لسه متوقف)"))
        imap_ok = _port_listening(INT_IMAP_PORT)
        if not imap_ok:
            imap_ok = _restart_int_server(INT_IMAP_PORT, _int_imap_client, "IMAP")
            fixes.append("إعادة تشغيل سيرفر IMAP الداخلي" + ("" if imap_ok else " (لسه متوقف)"))
    with _health_lock:
        _health["db"] = {"ok": db_ok, "msg": db_msg, "ts": now}
        _health["smtp"] = {"ok": smtp_ok, "msg": "يعمل" if smtp_ok else "متوقف", "ts": now}
        _health["imap"] = {"ok": imap_ok, "msg": "يعمل" if imap_ok else "متوقف", "ts": now}
        _health["last_check"] = now
        for fx in fixes:
            _health["fixes"].insert(0, {"ts": now, "action": fx})
        _health["fixes"] = _health["fixes"][:20]
    for fx in fixes:
        log.warning("إصلاح ذاتي: %s", fx)
    return fixes


def autobackup_tick():
    """نسخة احتياطية تلقائية كل عدد ساعات (من إعداد auto_backup_hours، 0=إيقاف)."""
    try:
        hours = int(get_setting("auto_backup_hours", "6"))
    except (TypeError, ValueError):
        hours = 6
    if hours <= 0:
        return
    nowt = time.time()
    if _last_autobackup[0] and (nowt - _last_autobackup[0]) < hours * 3600:
        return
    _last_autobackup[0] = nowt
    try:
        ok, msg, fname = create_backup()
    except Exception as exc:  # noqa: BLE001
        log.warning("فشل النسخ الاحتياطي التلقائي: %s", exc)
        return
    if ok:
        with _health_lock:
            _health["last_backup"] = datetime.now().isoformat(timespec="seconds")
        log.info("نسخة احتياطية تلقائية تمّت: %s", fname)
    else:
        log.warning("فشل النسخ الاحتياطي التلقائي: %s", msg)


def scheduler_loop():
    log.info("بدأ المُجدوِل (فحص كل %ds)", SCHEDULER_TICK)
    while not _stop_event.is_set():
        try:
            conn = get_connection()
            s = conn.execute("SELECT * FROM schedule_settings WHERE id = 1").fetchone()
            now_iso = datetime.now().isoformat(timespec="seconds")
            # الجدولة لكل حملة على حدة: نبعت لو فيه مستلمون معلّقون وحان موعد إرسال حملتهم.
            due_pending = conn.execute("""
                SELECT COUNT(*) c FROM campaign_recipients r
                JOIN campaigns cc ON cc.id = r.campaign_id
                WHERE r.status='pending' AND cc.status='active'
                  AND (cc.send_date='' OR
                       (cc.send_date || 'T' ||
                        CASE WHEN cc.send_time='' THEN '12:00' ELSE cc.send_time END) <= ?)
            """, (now_iso,)).fetchone()["c"]
            # نظام داخلي بالكامل؟ ساعتها الحملة المستحقة تتبعت فوراً (مش تستنى الفترة)
            all_internal_sched = bool(conn.execute(
                "SELECT COUNT(*) c FROM accounts WHERE active=1").fetchone()["c"]) and not \
                conn.execute("SELECT COUNT(*) c FROM accounts WHERE active=1 AND internal=0"
                             ).fetchone()["c"]
            conn.close()
            if due_pending and not _batch_lock.locked():
                interval = max(1, int(s["interval_minutes"])) if s else 1
                due = True
                if all_internal_sched:
                    due = True   # داخلي: ابعت فوراً عند حلول الموعد (يتوزّع على مدة spread)
                elif s and s["last_run"]:
                    try:
                        last = datetime.fromisoformat(s["last_run"])
                        due = datetime.now() >= last + timedelta(minutes=interval)
                    except ValueError:
                        due = True
                if due:
                    conn = get_connection()
                    conn.execute("UPDATE schedule_settings SET last_run = ? WHERE id = 1",
                                 (now_iso,))
                    conn.commit()
                    conn.close()
                    log.info("تشغيل دفعة مجدولة (حملات حان موعدها)")
                    # في الخلفية: التوزيع على مدة (spread) ما يعطّلش حلقة المُجدوِل/الردود
                    threading.Thread(target=_run_batch_bg, daemon=True).start()
            # الرد العكسي يعمل باستمرار: فحص دوري + إرسال ما حان موعده
            reverse_tick()
            # مراقبة ذاتية (كل ~60 ثانية) + نسخ احتياطي تلقائي
            if time.time() - _last_health_check[0] >= 60:
                _last_health_check[0] = time.time()
                health_tick()
                autobackup_tick()
        except Exception:  # noqa: BLE001
            log.exception("خطأ في حلقة المُجدوِل")
        _stop_event.wait(SCHEDULER_TICK)


# ------------------------------------------------------------------ تطبيق Flask
app = Flask(__name__)

if os.path.exists(FLASK_SECRET_FILE):
    with open(FLASK_SECRET_FILE, "rb") as fh:
        app.secret_key = fh.read()
else:
    app.secret_key = os.urandom(32)
    with open(FLASK_SECRET_FILE, "wb") as fh:
        fh.write(app.secret_key)

app.permanent_session_lifetime = timedelta(days=14)

BASE_TPL = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }} · Email Manager</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
<style>
 :root{
   --bg:#eef1f6; --surface:#ffffff; --ink:#1f2430; --muted:#6b7280;
   --border:#e3e7ee; --border-strong:#d3d9e3;
   --brand:#4f46e5; --brand-d:#4338ca; --brand-soft:#eef0fe;
   --ok:#0f9d58; --warn:#e8a33d; --danger:#e5484d;
   --shadow:0 1px 2px rgba(16,24,40,.04), 0 4px 16px rgba(16,24,40,.06);
   --radius:14px; --sidebar-w:238px;
 }
 *{scrollbar-width:thin}
 body{background:var(--bg);color:var(--ink);
   font-family:'Cairo','Segoe UI',Tahoma,sans-serif;font-size:.95rem}
 a{text-decoration:none}
 /* ===== الشريط الجانبي ===== */
 .sidebar{position:fixed;top:0;right:0;bottom:0;width:var(--sidebar-w);z-index:1045;
   background:linear-gradient(185deg,#4f46e5 0%,#5b28c4 60%,#6d28d9 100%);
   color:#fff;display:flex;flex-direction:column;transition:transform .25s ease;
   box-shadow:-4px 0 24px rgba(79,70,229,.18)}
 .sidebar-brand{padding:20px 20px 15px;font-weight:700;font-size:1.12rem;
   display:flex;align-items:center;gap:9px;border-bottom:1px solid rgba(255,255,255,.14)}
 .sidebar-nav{flex:1;overflow-y:auto;padding:14px 12px}
 .sidebar-nav a{display:flex;align-items:center;gap:12px;padding:.62rem .8rem;border-radius:11px;
   color:rgba(255,255,255,.82);font-weight:600;font-size:.9rem;margin-bottom:3px;
   transition:background .12s,color .12s}
 .sidebar-nav a:hover{background:rgba(255,255,255,.13);color:#fff}
 .sidebar-nav a.active{background:#fff;color:var(--brand-d);box-shadow:0 6px 16px rgba(0,0,0,.18)}
 .sidebar-nav a.nav-hl{background:rgba(240,180,41,.16);color:#ffe6a8;
   border:1px solid rgba(240,180,41,.4)}
 .sidebar-nav a.nav-hl i{color:#ffcf5c}
 .sidebar-nav a.nav-hl:hover{background:rgba(240,180,41,.28);color:#fff}
 .sidebar-nav a.nav-hl.active{background:#fff;color:var(--brand-d);border-color:#fff}
 .sidebar-nav a.nav-hl.active i{color:#e0a418}
 .sidebar-nav a i{font-size:1.08rem;width:20px;text-align:center;flex:0 0 20px}
 .sidebar-nav .grp{font-size:.68rem;text-transform:uppercase;letter-spacing:.7px;
   opacity:.55;margin:12px 10px 5px;font-weight:700}
 .sidebar-foot{padding:13px;border-top:1px solid rgba(255,255,255,.14)}
 .sidebar-foot .who{display:flex;align-items:center;gap:8px;font-size:.84rem;opacity:.92;margin-bottom:9px}
 .topbar{display:none}
 .app-shell{margin-right:var(--sidebar-w);min-height:100vh;display:flex;flex-direction:column}
 .app-shell.full{margin-right:0;background:#eef1f6}
 .emp-topbar{display:flex;align-items:center;gap:14px;padding:14px 26px;
   background:linear-gradient(90deg,#0f6cbd,#1560a8);color:#fff;
   box-shadow:0 2px 10px rgba(15,108,189,.25);position:sticky;top:0;z-index:1030}
 .emp-topbar .who{font-size:.9rem;opacity:.95}
 .emp-actions{display:flex;align-items:center;gap:10px;margin-inline-start:auto}
 .emp-topbar strong{font-size:1.1rem;letter-spacing:.2px}
 .emp-folder{display:inline-flex;align-items:center;gap:6px;font-size:.95rem;font-weight:600;
   background:rgba(255,255,255,.18);padding:5px 14px;border-radius:8px;white-space:nowrap}
 .emp-folder i{opacity:.9}
 .emp-topbar{position:relative}
 .emp-search{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);
   width:clamp(260px,40vw,540px);margin:0;display:flex;align-items:center;gap:8px;
   background:#fff;border-radius:10px;padding:8px 14px;box-shadow:0 2px 8px rgba(0,0,0,.12);z-index:2}
 .emp-search i{color:#0f6cbd}
 .emp-search input{border:none;outline:none;flex:1;font-size:.9rem;background:transparent;color:#242424}
 /* إطار رسمي لصفحة بريد الموظف — بعرض الشاشة كامل */
 .app-shell.full .app-main{max-width:none;padding:1px 14px 4px}
 .app-shell.full .rbn{margin-bottom:3px;padding:1px 4px}
 .app-shell.full .rbn-grp{padding:0 12px}
 .app-shell.full .rbn-top{padding-bottom:0}
 .app-shell.full .rbn-big{padding:2px 7px}
 .app-shell.full .rbn-big i{font-size:1.2rem}
 .app-shell.full .rbn-lbl{display:none}
 .app-shell.full .rbn-new{padding:2px 14px;font-size:.82rem;font-weight:600}
 .app-shell.full .rbn-new i{font-size:1.7rem}
 .app-shell.full .emp-topbar{padding:5px 22px}
 .app-shell.full .rbn-tab{padding:4px 14px}
 .app-shell.full .rbn-tell{padding:4px 12px}
 .app-shell.full .olx{border:2px solid #b7c0d0;border-bottom:none;border-radius:14px 14px 0 0;
   box-shadow:0 8px 30px rgba(20,40,80,.14);height:calc(100vh - 218px)}
 .app-shell.full .olx-status{border:2px solid #b7c0d0;border-top:none}
 .app-shell.full .olx-fold a{padding:.34rem .7rem;font-size:.88rem}
 .app-shell.full .olx-fold a i{font-size:1.02rem}
 .app-shell.full .olx-fold .mbx{padding:8px 12px;font-size:.85rem}
 .app-backdrop{display:none}
 .app-version{position:fixed;bottom:8px;left:10px;z-index:1000;font-size:.72rem;
   color:#8a94a6;background:rgba(255,255,255,.85);border:1px solid #e2e6ee;
   border-radius:6px;padding:2px 8px;letter-spacing:.3px;pointer-events:none;
   box-shadow:0 1px 3px rgba(0,0,0,.06)}
 .app-shell.full .app-version{display:none}
 .app-main{width:100%;max-width:1800px;margin:0 auto;padding:28px 24px 64px}
 @media(max-width:992px){
   .sidebar{transform:translateX(100%)}
   .sidebar.open{transform:translateX(0)}
   .app-shell{margin-right:0}
   .app-backdrop.show{display:block;position:fixed;inset:0;background:rgba(15,18,30,.45);z-index:1040}
   .topbar{display:flex;align-items:center;gap:12px;padding:11px 16px;background:var(--surface);
     border-bottom:1px solid var(--border);position:sticky;top:0;z-index:1030}
   .app-main{padding:20px 16px 44px}
 }
 .page-head{display:flex;align-items:center;justify-content:space-between;
   flex-wrap:wrap;gap:12px;margin-bottom:20px}
 .page-head h1{font-size:1.5rem;font-weight:700;margin:0}
 .page-head .sub{color:var(--muted);font-size:.9rem;margin-top:2px}
 h2{font-size:1.4rem;font-weight:700} h4{font-weight:700}
 .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
   box-shadow:var(--shadow);margin-bottom:20px}
 .card-body{padding:20px}
 .btn{border-radius:10px;font-weight:600;font-size:.86rem;padding:.45rem .9rem}
 .btn-sm{border-radius:8px;padding:.3rem .6rem;font-size:.8rem}
 .btn-primary{background:var(--brand);border-color:var(--brand)}
 .btn-primary:hover,.btn-primary:focus{background:var(--brand-d);border-color:var(--brand-d)}
 .btn-outline-primary{color:var(--brand);border-color:var(--border-strong)}
 .btn-outline-primary:hover{background:var(--brand);border-color:var(--brand)}
 .btn-outline-secondary,.btn-outline-dark,.btn-outline-info{border-color:var(--border-strong);color:#475069}
 .btn-outline-secondary:hover,.btn-outline-dark:hover{background:#eef1f6;color:var(--ink)}
 .btn-success{background:var(--ok);border-color:var(--ok)}
 .btn-warning{background:var(--warn);border-color:var(--warn);color:#fff}
 .btn-danger{background:var(--danger);border-color:var(--danger)}
 .table{--bs-table-bg:var(--surface);border-color:var(--border);margin-bottom:0}
 .table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
   box-shadow:var(--shadow);overflow:hidden;margin-bottom:20px}
 .table-wrap .table{border-radius:0}
 .table thead th{background:#f6f7fb;border-bottom:1px solid var(--border-strong);
   color:#5b6472;font-weight:700;font-size:.78rem;text-transform:uppercase;letter-spacing:.4px;
   padding:.7rem .9rem;white-space:nowrap}
 .table tbody td{padding:.7rem .9rem;border-color:var(--border);vertical-align:middle}
 .table tbody tr:hover{background:#f8f9fc}
 .table.table-striped>tbody>tr:nth-of-type(odd)>*{--bs-table-bg-type:#fbfcfe}
 .badge{font-weight:600;border-radius:7px;padding:.36em .6em;font-size:.72rem}
 .badge.bg-success{background:#e7f6ee!important;color:#0b7a43!important}
 .badge.bg-danger{background:#fdecec!important;color:#c0343a!important}
 .badge.bg-warning{background:#fdf3e3!important;color:#9a6714!important}
 .badge.bg-secondary{background:#eef0f4!important;color:#525b6c!important}
 .badge.bg-primary{background:var(--brand-soft)!important;color:var(--brand-d)!important}
 .badge.bg-info{background:#e5f4fb!important;color:#106b8a!important}
 .status-dot{display:inline-flex;align-items:center;gap:6px;font-weight:600;font-size:.8rem}
 .status-dot::before{content:"";width:8px;height:8px;border-radius:50%}
 .status-dot.on{color:#0b7a43} .status-dot.on::before{background:var(--ok);box-shadow:0 0 0 3px #e7f6ee}
 .status-dot.off{color:#9aa1ad} .status-dot.off::before{background:#c4c9d2}
 .form-control,.form-select{border-radius:10px;border-color:var(--border-strong);font-size:.9rem;padding:.5rem .75rem}
 .form-control:focus,.form-select:focus{border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-soft)}
 .form-label,label{font-weight:600;font-size:.85rem;margin-bottom:.25rem}
 .modal-content{border:none;border-radius:16px}
 .modal-header{border-bottom:1px solid var(--border);padding:1rem 1.25rem}
 .modal-body{padding:1.25rem} .modal-footer{border-top:1px solid var(--border)}
 .alert{border-radius:12px;border:1px solid transparent;font-size:.9rem}
 .alert-success{background:#e7f6ee;border-color:#bfe6ce;color:#0b6b3c}
 .alert-danger{background:#fdecec;border-color:#f4c9cb;color:#9a2c30}
 .alert-warning{background:#fdf6e7;border-color:#f0dcae;color:#7a5a12}
 .alert-info{background:#eaf1fe;border-color:#c9dbfb;color:#2c4c93}
 pre.msgbody{white-space:pre-wrap;word-break:break-word;background:var(--surface);
   border:1px solid var(--border);padding:16px;border-radius:12px;font-family:inherit;font-size:.9rem}
 code{background:#eef0f4;color:#8a2b6b;padding:.1em .4em;border-radius:5px;font-size:.85em}
 /* قائمة رسائل بنمط Gmail */
 .mlist{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
   overflow:hidden;box-shadow:var(--shadow)}
 .mlist-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;
   padding:10px 14px;border-bottom:1px solid var(--border);background:#fafbfd}
 .mrow{display:flex;align-items:center;gap:14px;padding:12px 16px;border-bottom:1px solid #f1f2f6;
   color:var(--ink)}
 .mrow:hover{background:#f6f8ff;box-shadow:inset 3px 0 0 var(--brand)}
 .mrow:last-child{border-bottom:none}
 .mrow-from{flex:0 0 180px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
   font-size:.9rem;font-weight:600}
 .mrow-body{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:.9rem}
 .mrow-subj{font-weight:600;color:var(--ink)}
 .mrow-snip{color:var(--muted)}
 .mrow-date{flex:0 0 auto;color:var(--muted);font-size:.78rem;white-space:nowrap;min-width:52px;text-align:end}
 .mlist-empty{padding:34px 16px;color:var(--muted);text-align:center}
 /* مبدّل الصناديق */
 .dash-card{transition:transform .12s, box-shadow .12s}
 .dash-card:hover{transform:translateY(-2px);box-shadow:0 8px 22px rgba(20,40,80,.13);
   border-color:var(--brand)}
 .mbox-switch{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:16px}
 .mbox-switch .lbl{font-size:.8rem;color:var(--muted);font-weight:700}
 .mbox-switch .chip{display:inline-flex;align-items:center;gap:6px;padding:.35rem .7rem;
   border-radius:999px;background:var(--surface);border:1px solid var(--border-strong);
   color:#475069;font-size:.82rem;font-weight:600}
 .mbox-switch .chip:hover{border-color:var(--brand);color:var(--brand)}
 .mbox-switch .chip.on{background:var(--brand);border-color:var(--brand);color:#fff}
 @media(max-width:640px){.mrow-from{flex-basis:100px}.mrow-date{display:none}}
 /* ===== واجهة البريد (أوتلوك) ===== */
 .ol{display:flex;gap:14px;align-items:flex-start}
 .ol-folders{flex:0 0 236px;background:var(--surface);border:1px solid var(--border);
   border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;position:sticky;top:14px}
 .ol-mbox{padding:12px 14px;border-bottom:1px solid var(--border);background:#fafbfd}
 .ol-mbox .nm{font-weight:700;font-size:.92rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 .ol-mbox .em{font-size:.75rem;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 .ol-flist{padding:8px}
 .ol-flist a{display:flex;align-items:center;gap:9px;padding:.5rem .6rem;border-radius:9px;
   color:#3d4457;font-size:.87rem;font-weight:600}
 .ol-flist a:hover{background:var(--brand-soft);color:var(--brand-d)}
 .ol-flist a.on{background:var(--brand);color:#fff}
 .ol-flist .cnt{margin-inline-start:auto;font-size:.71rem;background:#eef0f6;color:#4b5468;
   padding:.05rem .42rem;border-radius:999px;font-weight:700}
 .ol-flist a.on .cnt{background:rgba(255,255,255,.25);color:#fff}
 .ol-main{flex:1;min-width:0;background:var(--surface);border:1px solid var(--border);
   border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
 .ol-bar{display:flex;align-items:center;gap:7px;flex-wrap:wrap;padding:9px 12px;
   border-bottom:1px solid var(--border);background:#fafbfd}
 .ol-row{display:flex;align-items:center;gap:10px;padding:9px 12px;border-bottom:1px solid #f1f2f6}
 .ol-row:last-child{border-bottom:none}
 .ol-row:hover{background:#f6f8ff}
 .ol-row .bar{width:3px;height:32px;border-radius:2px;background:transparent;flex:0 0 3px}
 .ol-row.unseen .bar{background:var(--brand)}
 .ol-row.unseen .sub,.ol-row.unseen .who{font-weight:800}
 .ol-row .who{flex:0 0 168px;font-size:.87rem;color:#454d60;white-space:nowrap;
   overflow:hidden;text-overflow:ellipsis}
 .ol-row .mid{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:.87rem}
 .ol-row .dt{flex:0 0 auto;font-size:.76rem;color:var(--muted);white-space:nowrap}
 .ol-msg{padding:18px 20px}
 .ol-msg-head h4{font-size:1.14rem;font-weight:700;margin:0 0 10px}
 .ol-frame{width:100%;height:70vh;border:1px solid var(--border);border-radius:10px;background:#fff}
 .ol-att{display:inline-flex;align-items:center;gap:8px;padding:.42rem .7rem;
   border:1px solid var(--border-strong);border-radius:10px;font-size:.83rem;color:#3d4457;
   background:#fafbfd;margin:0 0 6px 6px}
 .ol-att:hover{border-color:var(--brand);color:var(--brand)}
 /* شريط أدوات أوتلوك المجمّع (Ribbon) */
 .rbn-tabs{display:flex;align-items:flex-end;gap:2px;padding:0 6px;margin-bottom:0;
   border-bottom:1px solid #d3d9e4;overflow-x:auto}
 .rbn-tab{padding:6px 14px;font-size:.86rem;color:#3b3a39;cursor:pointer;white-space:nowrap;
   border:1px solid transparent;border-bottom:none;border-radius:6px 6px 0 0;margin-bottom:-1px}
 .rbn-tab:hover{background:#eef3fa}
 .rbn-tab.active{color:#0f6cbd;font-weight:700;background:#f5f6f8;border-color:#d3d9e4;
   border-bottom:1px solid #f5f6f8}
 .rbn-tab-file{background:#2b579a;color:#fff;border-radius:4px;margin-inline-end:8px;font-weight:600}
 .rbn-tab-file:hover{background:#1e4278;color:#fff}
 .rbn-tell{margin-inline-start:auto;color:#8a8886;font-size:.82rem;padding:6px 12px;white-space:nowrap}
 .rbn-tell i{color:#c8a415}
 .rbn{display:flex;align-items:stretch;gap:0;background:#f5f6f8;border:1px solid #cbd2df;
   border-radius:0 0 10px 10px;padding:6px 2px;margin-bottom:14px;box-shadow:0 2px 8px rgba(20,40,80,.06);
   overflow-x:auto}
 .rbn-grp{display:flex;flex-direction:column;padding:2px 12px;border-inline-end:2px solid #d3d9e4;
   flex:0 0 auto}
 .rbn-grp:last-child{border-inline-end:none}
 .rbn-top{display:flex;align-items:stretch;gap:3px;flex:1;padding-bottom:5px}
 .rbn-lbl{text-align:center;font-size:.68rem;color:#6b6a68;font-weight:600;
   border-top:1px solid #d3d9e4;padding-top:4px;margin-top:2px}
 .rbn-big{display:inline-flex;flex-direction:column;align-items:center;justify-content:center;
   gap:4px;min-width:56px;max-width:70px;padding:6px 8px;border-radius:6px;color:#3b3a39;
   font-size:.72rem;font-weight:600;text-align:center;line-height:1.2;cursor:pointer;text-decoration:none}
 .rbn-big i{font-size:1.45rem;color:#0f6cbd}
 .rbn-big:hover{background:#e9f2fb;color:#0f6cbd}
 .rbn-big.dropdown-toggle::after{margin:0 auto}
 .rbn-col{display:flex;flex-direction:column;gap:2px;justify-content:center}
 .rbn-grid{display:grid;grid-template-columns:1fr 1fr;grid-auto-rows:min-content;gap:1px 6px}
 .rbn-s{display:inline-flex;align-items:center;gap:6px;border:none;background:transparent;
   color:#3b3a39;font-size:.78rem;font-weight:600;padding:.22rem .5rem;border-radius:5px;
   cursor:pointer;white-space:nowrap;text-align:right}
 .rbn-s i{font-size:.95rem;width:16px}
 .rbn-s:hover{background:#e9f2fb}
 .rbn-s .dropdown-toggle::after{margin-inline-start:4px}
 /* ===== واجهة أوتلوك 3 أجزاء ===== */
 .olx{display:flex;gap:0;align-items:stretch;height:calc(100vh - 150px);min-height:520px;
   border:2px solid #b7c0d0;border-radius:12px;overflow:hidden;background:#fff;
   box-shadow:0 6px 24px rgba(20,40,80,.12)}
 .olx-fold{flex:0 0 220px;background:#faf9f8;border-inline-end:2px solid #c4ccda;overflow-y:auto}
 .olx-fold .mbx{padding:12px 14px;font-weight:700;font-size:.9rem;color:#201f1e;
   border-bottom:1px solid #eaebec;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 .olx-fold a{display:flex;align-items:center;gap:11px;padding:.6rem .85rem;color:#242424;
   font-size:.9rem;font-weight:600;border-inline-start:3px solid transparent}
 .olx-fold a i{font-size:1.2rem;color:#0f6cbd}
 .olx-fold a.on i{color:#0f6cbd}
 .olx-fold a:hover{background:#f3f2f1}
 .olx-fold a.on{background:#eaf2fb;border-inline-start-color:#0f6cbd;color:#0f6cbd}
 .olx-fold .cnt{margin-inline-start:auto;font-size:.72rem;color:#0f6cbd;font-weight:700}
 .olx-list{flex:0 0 380px;border-inline-end:2px solid #c4ccda;display:flex;flex-direction:column;overflow:hidden}
 .olx-ltop{padding:10px 12px;border-bottom:2px solid #eceef2;background:#fff;display:flex;
   flex-direction:column;gap:8px}
 .olx-ltop .form-control{border:1px solid #d5dbe6;border-radius:9px;box-shadow:none}
 .olx-ltop .form-control:focus{border-color:#0f6cbd;box-shadow:0 0 0 3px rgba(15,108,189,.12)}
 .olx-ltop .input-group-text{border:1px solid #d5dbe6;background:#f6f8fb;border-radius:9px}
 .olx-ltitle{font-weight:700;color:#201f1e;font-size:1rem}
 .olx-scroll{overflow-y:auto;flex:1}
 .olx-grp{padding:6px 14px;font-size:.76rem;font-weight:700;color:#605e5c;background:#f7f7f8;
   position:sticky;top:0}
 .olx-item{display:block;padding:10px 12px 10px 14px;border-bottom:1px solid #f2f2f3;cursor:pointer;
   border-inline-start:3px solid transparent;color:inherit}
 .olx-item:hover{background:#f3f9fd}
 .olx-item.sel{background:#eaf2fb;border-inline-start-color:#0f6cbd}
 .olx-item .r1{display:flex;align-items:center;gap:6px}
 .olx-item .who{font-size:.9rem;color:#201f1e;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 .olx-item .dt{font-size:.75rem;color:#605e5c;white-space:nowrap}
 .olx-item .olx-quick{display:none;align-items:center;gap:10px;margin-inline-start:2px}
 .olx-item:hover .dt,.olx-item.sel .dt{display:none}
 .olx-item:hover .olx-quick,.olx-item.sel .olx-quick{display:inline-flex}
 .olx-quick i{cursor:pointer;color:#5b6472;font-size:1rem;line-height:1}
 .olx-quick i:hover{color:#0f6cbd}
 .olx-quick i.xdel:hover{color:#c0392b}
 .olx-item .sub{font-size:.85rem;color:#201f1e;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:1px}
 .olx-item .pre{font-size:.8rem;color:#605e5c;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:1px}
 .olx-item.unseen{border-inline-start-color:#0f6cbd}
 .olx-item.unseen .who,.olx-item.unseen .sub{font-weight:700}
 .olx-item.unseen .sub{color:#0f6cbd}
 .olx-read{flex:1;min-width:0;overflow-y:auto;background:#fff}
 .olx-status{display:flex;align-items:center;gap:14px;background:#0f6cbd;color:#fff;
   font-size:.78rem;padding:0 14px;height:30px;border-radius:0 0 12px 12px;overflow:hidden}
 .olx-status .sep{opacity:.4}
 .olx-nav{display:flex;align-items:center;gap:14px}
 .olx-nav a,.olx-nav span{color:#fff;font-size:1rem;line-height:1;cursor:pointer;opacity:.92}
 .olx-nav a:hover,.olx-nav span:hover{opacity:1}
 .olx-stat-info{display:flex;align-items:center;gap:10px;white-space:nowrap}
 .olx-stat-right{display:flex;align-items:center;gap:12px;margin-inline-start:auto;white-space:nowrap}
 .olx-stat-right i{margin-inline-end:4px}
 .olx-viewicons{display:flex;gap:10px;font-size:.95rem}
 .olx-viewicons i{cursor:pointer;opacity:.9}
 .olx-zoom{display:flex;align-items:center;gap:9px;font-size:.95rem}
 .olx-zoom i{cursor:pointer;opacity:.9;width:16px;text-align:center}
 .olx-zoom i:hover{opacity:1}
 .olx-zoom #zoomVal{font-size:.76rem;min-width:34px;text-align:center}
 .olx-empty{display:flex;align-items:center;justify-content:center;height:100%;color:#a19f9d;
   font-size:.95rem;flex-direction:column;gap:10px}
 .rdx{padding:22px 26px}
 .rdx .subj{font-size:1.5rem;font-weight:600;color:#1a1a1a;margin-bottom:14px}
 .rdx .hd{display:flex;align-items:flex-start;gap:12px;padding-bottom:14px;border-bottom:1px solid #edeef0}
 .rdx .av{width:44px;height:44px;border-radius:50%;background:#0f6cbd;color:#fff;flex:0 0 auto;
   display:flex;align-items:center;justify-content:center;font-weight:600}
 .rdx .frm{font-weight:600;color:#201f1e}
 .rdx .tos{font-size:.83rem;color:#605e5c}
 .rdx .dtt{margin-inline-start:auto;font-size:.8rem;color:#605e5c;white-space:nowrap}
 .rdx .bd{padding-top:18px;line-height:1.7;color:#242424}
 .rdx .bd img{max-width:100%}
 .rdx .acts{display:flex;gap:8px;padding:10px 26px;border-bottom:1px solid #edeef0;background:#faf9f8}
 @media(max-width:1100px){.olx{height:auto;flex-direction:column}
  .olx-fold,.olx-list{flex:none;width:100%;border-inline-end:none;border-bottom:1px solid #e6e8eb}
  .olx-list{max-height:340px}}
 @media(max-width:900px){.ol{flex-direction:column}
  .ol-folders{width:100%;flex:none;position:static}
  .ol-flist{display:flex;flex-wrap:wrap;gap:4px}
  .ol-row .who{flex-basis:110px}}
</style>
</head>
<body>
{% set ep = request.endpoint %}
{% set is_emp = user and user.role != 'admin' %}
{% set bare = request.args.get('bare') == '1' %}
{% set clean = is_emp or bare %}
{% if not clean %}
<aside class="sidebar" id="sb">
 <div class="sidebar-brand"><i class="bi bi-envelope-paper-heart"></i> Email Manager</div>
 <nav class="sidebar-nav">
  {% if user and user.role == 'admin' %}
   <a class="{{ 'active' if ep=='index' }}" href="{{ url_for('index') }}"><i class="bi bi-grid-1x2-fill"></i> لوحة التحكم</a>
   <div class="grp">الإرسال</div>
   <a class="{{ 'active' if ep=='accounts' }}" href="{{ url_for('accounts') }}"><i class="bi bi-send-fill"></i> الحسابات المرسِلة</a>
   <a class="{{ 'active' if ep=='employees' }}" href="{{ url_for('employees') }}"><i class="bi bi-people-fill"></i> الموظفون</a>
   <a class="{{ 'active' if ep=='templates_page' }}" href="{{ url_for('templates_page') }}"><i class="bi bi-pen-fill"></i> توقيع الموظفين</a>
   <a class="{{ 'active' if ep=='distribution' }}" href="{{ url_for('distribution') }}"><i class="bi bi-diagram-3-fill"></i> توزيع الموظفين</a>
   <a class="nav-hl {{ 'active' if ep=='quick_send' }}" href="{{ url_for('quick_send') }}"><i class="bi bi-lightning-charge-fill"></i> إرسال سريع</a>
   <a class="{{ 'active' if ep in ('campaigns','campaign_detail') }}" href="{{ url_for('campaigns') }}"><i class="bi bi-megaphone-fill"></i> الحملات</a>
   <a class="{{ 'active' if ep=='schedule_page' }}" href="{{ url_for('schedule_page') }}"><i class="bi bi-shield-fill-check"></i> الجدولة والحماية</a>
   <div class="grp">الرسائل والردود</div>
   <a class="nav-hl {{ 'active' if ep in ('message_templates_page','reverse_page') }}" href="{{ url_for('message_templates_page') }}"><i class="bi bi-file-earmark-text-fill"></i> القوالب والردود التلقائية</a>
   <div class="grp">البريد</div>
   <a class="{{ 'active' if ep in ('mail_home','mail_view','mail_message_view','mail_compose') }}" href="{{ url_for('mail_home') }}"><i class="bi bi-envelope-open"></i> البريد (سيرفر خارجي)</a>
   <div class="grp">النظام</div>
   <a class="{{ 'active' if ep=='domains_page' }}" href="{{ url_for('domains_page') }}"><i class="bi bi-globe2"></i> الدومينات والصناديق</a>
   <a class="{{ 'active' if ep=='users_page' }}" href="{{ url_for('users_page') }}"><i class="bi bi-shield-lock-fill"></i> المستخدمون</a>
   <a class="{{ 'active' if ep in ('backups_page',) }}" href="{{ url_for('backups_page') }}"><i class="bi bi-hdd-stack-fill"></i> النسخ الاحتياطي</a>
   <a class="{{ 'active' if ep=='server_page' }}" href="{{ url_for('server_page') }}"><i class="bi bi-hdd-network-fill"></i> السيرفر والنشر</a>
  {% elif user %}
   <a class="{{ 'active' if ep in ('me','mail_view','mail_message_view','mail_compose') }}" href="{{ url_for('me') }}"><i class="bi bi-inbox-fill"></i> بريدي</a>
   <a class="{{ 'active' if ep=='me_settings' }}" href="{{ url_for('me_settings') }}"><i class="bi bi-gear-fill"></i> إعداداتي</a>
  {% endif %}
 </nav>
 {% if user %}
 <div class="sidebar-foot">
  <div class="who"><i class="bi bi-person-circle"></i> {{ user.full_name or user.username }}
   · {{ 'مدير' if user.role=='admin' else 'موظف' }}</div>
  <a href="{{ url_for('logout') }}" class="btn btn-sm btn-light w-100">
   <i class="bi bi-box-arrow-right"></i> تسجيل الخروج</a>
 </div>
 {% endif %}
</aside>
<div class="app-backdrop" id="bd" onclick="sbToggle()"></div>
{% endif %}
<div class="app-shell{{ ' full' if clean }}">
 {% if bare and not is_emp %}
 <div class="emp-topbar">
  <strong dir="ltr"><i class="bi bi-envelope-fill"></i>
   {{ meta.email if meta is defined else 'صندوق البريد' }}</strong>
  {% if folder_label is defined and folder_label %}
  <span class="emp-folder"><i class="bi bi-folder2-open"></i> {{ folder_label }}</span>
  {% endif %}
  {% if meta is defined %}
  <form class="emp-search" method="GET" action="{{ url_for('mail_view', kind=meta.kind, oid=meta.id, bare=1) }}">
   <i class="bi bi-search"></i>
   <input name="q" value="{{ request.args.get('q','') }}" autocomplete="off"
          placeholder="ابحث في كل الرسائل (المرسِل / الموضوع / النص)…">
   <input type="hidden" name="f" value="{{ folder if folder is defined else 'INBOX' }}">
  </form>
  {% endif %}
  <span class="ms-auto"></span>
  <a href="{{ url_for('employees') }}" class="btn btn-sm btn-light">
   <i class="bi bi-arrow-right"></i> رجوع للموظفين</a>
 </div>
 {% elif is_emp %}
 <div class="emp-topbar">
  <strong dir="ltr"><i class="bi bi-envelope-fill"></i> {{ user.username }}</strong>
  {% if folder_label is defined and folder_label %}
  <span class="emp-folder"><i class="bi bi-folder2-open"></i> {{ folder_label }}</span>
  {% endif %}
  <form class="emp-search" method="GET" action="{{ url_for('me') }}">
   <i class="bi bi-search"></i>
   <input name="q" value="{{ request.args.get('q','') }}" autocomplete="off"
          placeholder="ابحث في كل الرسائل (المرسِل / الموضوع / النص)…">
  </form>
  <div class="emp-actions">
   <span class="who"><i class="bi bi-person-circle"></i> {{ user.full_name or user.username }}</span>
   <button type="button" class="btn btn-sm btn-light" data-bs-toggle="modal" data-bs-target="#empSettings"
           title="الإعدادات"><i class="bi bi-gear-fill"></i></button>
   <a href="{{ url_for('logout') }}" class="btn btn-sm btn-light">
    <i class="bi bi-box-arrow-right"></i> خروج</a>
  </div>
 </div>
 <div class="modal fade" id="empSettings" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
  <div class="modal-header"><h5 class="modal-title"><i class="bi bi-gear"></i> الإعدادات</h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
   <div class="mb-2 small text-muted">الحساب: <strong dir="ltr">{{ user.username }}</strong></div>
   <hr>
   <h6><i class="bi bi-key"></i> تغيير كلمة المرور</h6>
   <p class="small text-muted">التغيير بيطبّق على الدخول <strong>وعلى صندوق البريد على السيرفر</strong> معاً.</p>
   <form method="POST" action="{{ url_for('me_password') }}">
    <div class="mb-2"><label class="small">كلمة المرور الحالية</label>
     <input name="old" type="password" class="form-control" required autocomplete="current-password"></div>
    <div class="mb-2"><label class="small">كلمة المرور الجديدة</label>
     <input name="new" type="password" class="form-control" required autocomplete="new-password" minlength="4"></div>
    <button class="btn btn-primary w-100">حفظ كلمة المرور الجديدة</button>
   </form>
  </div>
 </div></div></div>
 {% else %}
 <div class="topbar">
  <button class="btn btn-sm btn-outline-secondary" onclick="sbToggle()"><i class="bi bi-list fs-5"></i></button>
  <strong><i class="bi bi-envelope-paper-heart"></i> Email Manager</strong>
 </div>
 {% endif %}
 <div class="app-main">
  {% if not crypto_ok %}
  <div class="alert alert-warning"><i class="bi bi-shield-exclamation"></i>
   مكتبة <code>cryptography</code> غير مثبّتة — كلمات المرور تُخزَّن كنص صريح.</div>
  {% endif %}
  {% with msgs = get_flashed_messages(with_categories=true) %}
   {% for cat, m in msgs %}
    <div class="alert alert-{{ 'danger' if cat=='error' else cat or 'info' }} alert-dismissible d-flex">
     <div class="flex-grow-1">{{ m }}</div>
     <button class="btn-close" data-bs-dismiss="alert"></button></div>
   {% endfor %}
  {% endwith %}
  {% block content %}{% endblock %}
 </div>
</div>
<div class="app-version" title="إصدار البرنامج">v{{ app_version }}</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
function sbToggle(){document.getElementById('sb').classList.toggle('open');
 document.getElementById('bd').classList.toggle('show');}
</script>
</body>
</html>
"""

INDEX_TPL = """
{% extends "base.html" %}{% block content %}
<div class="page-head"><div><h1>لوحة التحكم</h1>
 <div class="sub">نظرة عامة على النظام</div></div></div>
<div class="d-flex gap-2 flex-wrap mb-3">
 <a class="btn btn-primary" href="{{ url_for('quick_send') }}">
  <i class="bi bi-lightning-charge-fill"></i> إرسال سريع</a>
 <a class="btn btn-outline-primary" href="{{ url_for('campaigns') }}">
  <i class="bi bi-megaphone-fill"></i> الحملات</a>
 <a class="btn btn-outline-success" href="{{ url_for('employees') }}">
  <i class="bi bi-person-plus-fill"></i> الموظفون</a>
 <form method="post" action="{{ url_for('backup_now') }}" class="d-inline">
  <button class="btn btn-outline-secondary"><i class="bi bi-hdd-stack-fill"></i> نسخة احتياطية الآن</button></form>
</div>
<div class="d-flex align-items-center gap-2 mb-2">
 <span class="small text-muted"><i class="bi bi-arrow-repeat"></i> تحديث تلقائي كل ٥ ثوانٍ</span>
 <span class="small text-success" id="dashLiveFlag"></span>
</div>
<div id="dashLive">
<div class="row g-3 mb-2">
 {% for c in cards %}
 <div class="col-6 col-md-4 col-xl-2">
  <a href="{{ c.href or '#' }}" class="card h-100 text-decoration-none dash-card">
   <div class="card-body d-flex align-items-center gap-3 p-3">
   <span style="width:42px;height:42px;border-radius:12px;display:grid;place-items:center;
     background:{{ c.color }}1f;color:{{ c.color }};font-size:1.25rem;flex:0 0 42px">
    <i class="bi {{ c.icon }}"></i></span>
   <div class="min-w-0"><div class="text-muted small text-truncate">{{ c.label }}</div>
    <div style="font-size:1.55rem;font-weight:700;line-height:1.1;color:#1a1a2e">{{ c.value }}</div></div>
   </div></a>
 </div>
 {% endfor %}
</div>
{% if db_info %}
<div class="card mb-2" style="max-width:640px"><div class="card-body py-2 d-flex align-items-center gap-3 flex-wrap">
 <span style="width:38px;height:38px;border-radius:10px;display:grid;place-items:center;
   background:#0f6cbd1f;color:#0f6cbd;font-size:1.15rem"><i class="bi bi-database-fill-check"></i></span>
 <div><div class="text-muted small">قاعدة البيانات</div>
  <div class="fw-bold" style="color:#0f6cbd">{{ db_info.engine }}</div></div>
 <div class="ms-3"><div class="text-muted small">الرسائل المخزّنة</div>
  <div class="fw-bold">{{ db_info.messages }}</div></div>
 <div><div class="text-muted small">الردود</div><div class="fw-bold">{{ db_info.replies }}</div></div>
 {% if db_info.size %}<div><div class="text-muted small">الحجم</div>
  <div class="fw-bold">{{ db_info.size }}</div></div>{% endif %}
 <div><div class="text-muted small">آخر نسخة احتياطية</div>
  <div class="fw-bold">
   {% if db_info.last_backup %}<a href="{{ url_for('backups_page') }}"
     class="text-decoration-none">{{ db_info.last_backup }}</a>
   {% else %}<a href="{{ url_for('backups_page') }}" class="text-danger text-decoration-none">
     لا توجد</a>{% endif %}</div></div>
</div></div>
{% endif %}
{% if health %}
<div class="card mb-2" style="max-width:640px"><div class="card-body py-2">
 <div class="d-flex align-items-center gap-2 mb-2">
  <span style="width:34px;height:34px;border-radius:9px;display:grid;place-items:center;
    background:#16a34a1f;color:#16a34a;font-size:1.05rem"><i class="bi bi-heart-pulse-fill"></i></span>
  <div class="fw-bold">صحة النظام
   <span class="text-muted small fw-normal">· آخر فحص {{ health.last_check or '—' }}</span></div>
 </div>
 <div class="d-flex gap-4 flex-wrap small">
  {% for k, lbl in [('db','قاعدة البيانات'), ('smtp','سيرفر الإرسال'), ('imap','سيرفر الاستقبال')] %}
  <div><span class="status-dot {{ 'on' if health[k].ok else 'off' }}">
   {{ lbl }}: {{ 'سليم' if health[k].ok else 'مشكلة' }}</span></div>
  {% endfor %}
 </div>
 {% if health.fixes %}
 <div class="mt-2 small"><span class="text-muted">آخر إصلاحات ذاتية:</span>
  {% for fx in health.fixes %}
   <div class="text-success"><i class="bi bi-wrench-adjustable"></i> {{ fx.ts }} — {{ fx.action }}</div>
  {% endfor %}
 </div>
 {% else %}
 <div class="mt-1 text-muted small"><i class="bi bi-check-circle"></i> كل الخدمات تعمل — لا مشاكل.</div>
 {% endif %}
</div></div>
{% endif %}
{% if emp_alerts is defined %}
<div class="card mb-2" style="max-width:640px;border-color:{{ '#f56565' if emp_alerts else '#e3e7ee' }}">
 <div class="card-body py-2">
 <div class="d-flex align-items-center gap-2 mb-1">
  <span style="width:34px;height:34px;border-radius:9px;display:grid;place-items:center;
    background:{{ '#f565651f' if emp_alerts else '#16a34a1f' }};
    color:{{ '#f56565' if emp_alerts else '#16a34a' }};font-size:1.05rem">
   <i class="bi {{ 'bi-exclamation-triangle-fill' if emp_alerts else 'bi-people-fill' }}"></i></span>
  <div class="fw-bold">تنبيهات الموظفين
   {% if emp_alerts %}<span class="badge bg-danger">{{ emp_alerts|length }}</span>{% endif %}</div>
 </div>
 {% if emp_alerts %}
  <div class="small text-muted mb-1">موظفون يبدو إنهم متوقفون — راجعهم:</div>
  <div style="max-height:180px;overflow:auto">
  {% for a in emp_alerts %}
   <div class="d-flex justify-content-between align-items-center border-bottom py-1 small">
    <span><b>{{ a.name }}</b> <span class="text-muted" dir="ltr">{{ a.email }}</span></span>
    <span><span class="badge bg-danger-subtle text-danger">{{ a.reason }}</span>
     <a class="btn btn-sm btn-outline-primary py-0 px-2" href="{{ url_for('employees') }}">معالجة</a></span>
   </div>
  {% endfor %}
  </div>
 {% else %}
  <div class="text-success small"><i class="bi bi-check-circle"></i> كل الموظفين شغّالين — لا تنبيهات.</div>
 {% endif %}
 </div></div>
{% endif %}
<div class="card"><div class="card-body">
 <h5 class="mb-3">آخر 10 عمليات إرسال</h5>
 <div class="table-wrap">
 <table class="table">
  <thead><tr><th>الوقت</th><th>إلى</th><th>الموضوع</th><th>الحالة</th></tr></thead>
  <tbody>
  {% for s in recent %}
   <tr><td class="small">{{ s.sent_at }}</td><td>{{ s.to_email }}</td><td>{{ s.subject }}</td>
   <td>{% if s.status=='sent' %}<span class="badge bg-success">تم</span>
       {% else %}<span class="badge bg-danger" title="{{ s.error }}">فشل</span>{% endif %}</td></tr>
  {% else %}<tr><td colspan="4" class="text-muted">لا يوجد</td></tr>{% endfor %}
  </tbody>
 </table>
 </div>
</div></div>
</div>
<script>
// تحديث لحظي للوحة التحكم (البطاقات + صحة النظام + آخر الإرسالات) بدون إعادة تحميل
(function(){
 var wrap=document.getElementById('dashLive');
 if(!wrap) return;
 function tick(){
  fetch(location.pathname, {headers:{'X-Requested-With':'fetch'}})
   .then(function(r){return r.text()})
   .then(function(html){
     var doc=new DOMParser().parseFromString(html,'text/html');
     var fresh=doc.getElementById('dashLive');
     if(fresh && fresh.innerHTML!==wrap.innerHTML){
       wrap.innerHTML=fresh.innerHTML;
       var fl=document.getElementById('dashLiveFlag');
       if(fl){ fl.textContent='✓ تم التحديث'; setTimeout(function(){fl.textContent='';},1500); }
     }
   }).catch(function(){});
 }
 setInterval(tick, 5000);
})();
</script>
{% endblock %}
"""

ACCOUNTS_TPL = """
{% extends "base.html" %}{% block content %}
<div class="page-head">
 <div><h1>الإيميلات المرسِلة <span class="badge bg-secondary">{{ rows|length }}</span></h1>
  <div class="sub">الحسابات النشطة تتناوب على الإرسال بالتساوي · الحدود من
   <a href="{{ url_for('schedule_page') }}">الجدولة والحماية</a></div></div>
 <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#add">
  <i class="bi bi-plus-lg"></i> إضافة إيميل مرسِل</button>
</div>
<div class="d-flex align-items-center gap-2 mb-1">
 <span class="small text-muted"><i class="bi bi-arrow-repeat"></i> تحديث تلقائي كل ٥ ثوانٍ</span>
 <span class="small text-success" id="accLiveFlag"></span>
</div>
<div id="accLive">
<div class="table-wrap">
<table class="table align-middle">
 <thead><tr><th>البريد</th><th>الاسم الظاهر</th><th>الاتصال</th><th>SMTP</th><th>IMAP</th>
   <th>التشفير</th><th>أُرسل (ساعة/يوم)</th><th>الموظفين</th>
   <th>مُرسَلة</th><th>مُستقبَلة</th><th>نشط</th><th>إجراءات</th></tr></thead>
 <tbody>
 {% for a in rows %}
 <tr>
  <td class="fw-semibold">{{ a.email }}</td>
  <td>{{ a.display_name or '—' }}</td>
  <td><span class="status-dot {{ 'on' if a.verify_ok else 'off' }}">
      {{ 'متصل' if a.verify_ok else 'غير متصل' }}</span></td>
  <td class="small text-muted">{{ a.smtp_server }}:{{ a.smtp_port }}</td>
  <td class="small text-muted">{{ a.imap_server }}:{{ a.imap_port }}</td>
  <td><span class="badge bg-secondary">{{ a.security }}</span></td>
  <td><span class="badge bg-info">{{ a.used_hour }}</span> /
      <span class="badge bg-secondary">{{ a.used_day }}</span></td>
  <td>
   <button type="button" class="btn btn-sm btn-outline-primary" data-bs-toggle="modal"
     data-bs-target="#empof{{ a.id }}">{{ a.employees|length }} موظف</button>
  </td>
  <td><span class="badge bg-success" title="رسائل أرسلها الحساب">{{ a.sent_ct }}</span></td>
  <td><span class="badge bg-info text-dark" title="ردود/رسائل وصلت للحساب">{{ a.recv_ct }}</span></td>
  <td>{% if a.active %}<i class="bi bi-check-circle-fill" style="color:var(--ok)"></i>
      {% else %}<i class="bi bi-slash-circle" style="color:#c4c9d2"></i>{% endif %}</td>
  <td class="text-nowrap">
   <a class="btn btn-sm btn-primary" href="{{ url_for('mail_view', kind='account', oid=a.id) }}">
    <i class="bi bi-envelope-open"></i> فتح البريد</a>
   <button type="button" class="btn btn-sm btn-outline-primary" data-bs-toggle="modal"
     data-bs-target="#edacc{{ a.id }}">تعديل</button>
   <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('test_account_route', aid=a.id) }}">اختبار</a>
   <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('sync_account', aid=a.id) }}">تحديث</a>
   <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('toggle_account', aid=a.id) }}">
    {{ 'إيقاف' if a.active else 'تفعيل' }}</a>
   <a class="btn btn-sm btn-danger" href="{{ url_for('delete_account', aid=a.id) }}"
      onclick="return confirm('حذف الحساب؟')"><i class="bi bi-trash"></i></a>
  </td>
 </tr>
 {% else %}<tr><td colspan="12" class="mlist-empty">لا توجد حسابات — أضف حساباتك الخمسة</td></tr>{% endfor %}
 </tbody>
</table>
</div>
</div>
<script>
// تحديث لحظي لجدول الحسابات (مُرسَلة/مُستقبَلة والعدّادات) بدون إعادة تحميل
(function(){
 var wrap=document.getElementById('accLive'); if(!wrap) return;
 function tick(){
  // ما نحدّثش والمستخدم فاتح نافذة (modal)
  if(document.querySelector('.modal.show')) return;
  fetch(location.pathname,{headers:{'X-Requested-With':'fetch'}})
   .then(function(r){return r.text()})
   .then(function(html){
     var doc=new DOMParser().parseFromString(html,'text/html');
     var fresh=doc.getElementById('accLive');
     if(fresh && fresh.innerHTML!==wrap.innerHTML){
       wrap.innerHTML=fresh.innerHTML;
       var fl=document.getElementById('accLiveFlag');
       if(fl){ fl.textContent='✓ تم التحديث'; setTimeout(function(){fl.textContent='';},1500); }
     }
   }).catch(function(){});
 }
 setInterval(tick,5000);
})();
</script>

{% for a in rows %}
<div class="modal fade" id="edacc{{ a.id }}" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
 <form method="POST" action="{{ url_for('edit_account', aid=a.id) }}">
  <div class="modal-header"><h5 class="modal-title">تعديل: {{ a.email }}</h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
   <div class="mb-2"><label>الاسم الظاهر للمُرسِل</label>
    <input name="display_name" class="form-control" value="{{ a.display_name }}"></div>
  </div>
  <div class="modal-footer"><button class="btn btn-primary">حفظ</button></div>
 </form>
</div></div></div>
<div class="modal fade" id="empof{{ a.id }}" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content">
 <div class="modal-header"><h5 class="modal-title">موظفو {{ a.display_name or a.email }}</h5>
  <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
 <div class="modal-body">
  <div class="card card-body bg-light mb-3">
   <div class="fw-bold mb-2"><i class="bi bi-people-fill text-primary"></i> تعيين موظفين لهذا الحساب</div>
   <form method="POST" action="{{ url_for('account_assign_employees', aid=a.id) }}"
         class="row g-2 align-items-end mb-2">
    <input type="hidden" name="mode" value="group">
    <div class="col-sm-8"><label class="small text-muted mb-1">بالمجموعة (قسم / منصب)</label>
     <select name="group_value" class="form-select form-select-sm"
        onchange="this.form.group_type.value=this.options[this.selectedIndex].dataset.type||''">
      <option value="">— اختر مجموعة —</option>
      {% for g in groups %}<option value="{{ g.value }}" data-type="{{ g.type }}">{{ g.label }}</option>{% endfor %}
     </select>
     <input type="hidden" name="group_type" value=""></div>
    <div class="col-sm-4"><button class="btn btn-sm btn-primary w-100">
     <i class="bi bi-check2-all"></i> عيّن كل المجموعة</button></div>
   </form>
   <form method="POST" action="{{ url_for('account_assign_employees', aid=a.id) }}"
         class="row g-2 align-items-end">
    <input type="hidden" name="mode" value="random">
    <div class="col-sm-5"><label class="small text-muted mb-1">عدد عشوائي</label>
     <input name="count" type="number" min="1" class="form-control form-control-sm" placeholder="50"></div>
    <div class="col-sm-4 pb-1"><label class="small d-block">
      <input type="checkbox" name="from_all" value="1"> من كل الموظفين</label>
     <span class="small text-muted">غير المعيّنين: {{ unassigned }}/{{ total_active }}</span></div>
    <div class="col-sm-3"><button class="btn btn-sm btn-outline-primary w-100">
     <i class="bi bi-shuffle"></i> عيّن عشوائي</button></div>
   </form>
  </div>
  {% if a.employees %}
  <table class="table table-sm">
   <thead><tr><th>الاسم</th><th>البريد</th><th>الاتصال</th><th>نشط</th></tr></thead>
   <tbody>
   {% for e in a.employees %}
   <tr>
    <td>{{ e.name }}</td><td>{{ e.email }}</td>
    <td><span class="status-dot {{ 'on' if e.emp_connected else 'off' }}">
        {{ 'متصل' if e.emp_connected else 'غير متصل' }}</span></td>
    <td>{{ '✔' if e.active else '✖' }}</td>
   </tr>
   {% endfor %}
   </tbody>
  </table>
  {% else %}
  <p class="text-muted mb-0">مفيش موظفين متعيّنين على الحساب ده لسه —
   <a href="{{ url_for('distribution') }}">وزّعهم من هنا</a>.</p>
  {% endif %}
 </div>
</div></div></div>
{% endfor %}

<div class="modal fade" id="add" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
 <form method="POST" action="{{ url_for('add_account') }}">
  <div class="modal-header"><h5 class="modal-title">إضافة إيميل مرسِل</h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
   <div class="mb-2"><label>البريد الإلكتروني</label>
    <input name="email" type="email" class="form-control" required></div>
   <div class="mb-2"><label>الاسم الظاهر للمُرسِل (اختياري)</label>
    <input name="display_name" class="form-control" placeholder="مثلاً: إدارة الموارد البشرية"></div>
   <div class="mb-2"><label>كلمة المرور / App Password</label>
    <input name="password" type="password" class="form-control" required></div>
   <div class="alert alert-success py-2 small mb-2">
    <i class="bi bi-magic"></i> إعدادات SMTP/IMAP تُكتشف تلقائياً من البريد.
    افتح «إعدادات متقدمة» فقط لو سيرفرك مختلف.</div>
   <details>
    <summary class="mb-2" style="cursor:pointer">إعدادات متقدمة (اختياري)</summary>
    <div class="row">
     <div class="col-8 mb-2"><label>SMTP Server</label><input name="smtp_server" class="form-control" placeholder="تلقائي"></div>
     <div class="col-4 mb-2"><label>Port</label><input name="smtp_port" type="number" class="form-control" placeholder="587"></div>
    </div>
    <div class="mb-2"><label>نوع التشفير (SMTP)</label>
     <select name="security" class="form-select">
      <option value="">تلقائي</option>
      <option value="starttls">STARTTLS (587)</option>
      <option value="ssl">SSL/TLS (465)</option>
      <option value="none">بدون</option>
     </select></div>
    <div class="row">
     <div class="col-8 mb-2"><label>IMAP Server</label><input name="imap_server" class="form-control" placeholder="تلقائي"></div>
     <div class="col-4 mb-2"><label>Port</label><input name="imap_port" type="number" class="form-control" placeholder="993"></div>
    </div>
   </details>
   <p class="small text-muted mb-0 mt-2">لـ Gmail: فعّل التحقق بخطوتين ثم أنشئ
    «App Password» واستخدمه هنا بدل كلمة المرور العادية.</p>
  </div>
  <div class="modal-footer"><button class="btn btn-primary">حفظ</button></div>
 </form>
</div></div></div>

<script>
(function(){
 var P={
  "gmail.com":["smtp.gmail.com",587,"starttls","imap.gmail.com",993],
  "googlemail.com":["smtp.gmail.com",587,"starttls","imap.gmail.com",993],
  "outlook.com":["smtp-mail.outlook.com",587,"starttls","outlook.office365.com",993],
  "hotmail.com":["smtp-mail.outlook.com",587,"starttls","outlook.office365.com",993],
  "live.com":["smtp-mail.outlook.com",587,"starttls","outlook.office365.com",993],
  "yahoo.com":["smtp.mail.yahoo.com",587,"starttls","imap.mail.yahoo.com",993],
  "icloud.com":["smtp.mail.me.com",587,"starttls","imap.mail.me.com",993],
  "zoho.com":["smtp.zoho.com",587,"starttls","imap.zoho.com",993]
 };
 var form=document.querySelector('#add form'); if(!form) return;
 var em=form.email;
 em.addEventListener('input',function(){
  var d=(em.value.split('@')[1]||'').toLowerCase().trim(); if(!d) return;
  var g=P[d]||["mail."+d,587,"starttls","mail."+d,993];
  if(!form.smtp_server.value) form.smtp_server.placeholder=g[0];
  if(!form.smtp_port.value)   form.smtp_port.placeholder=g[1];
  if(!form.imap_server.value) form.imap_server.placeholder=g[3];
  if(!form.imap_port.value)   form.imap_port.placeholder=g[4];
 });
})();
</script>
{% endblock %}
"""

EMPLOYEES_TPL = """
{% extends "base.html" %}{% block content %}
<h2>الموظفون <span class="badge bg-secondary">{{ rows|length }}</span></h2>
<div class="d-flex gap-2 mb-3 flex-wrap align-items-center">
 <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#add">
  <i class="bi bi-plus-circle"></i> إضافة موظف</button>
 <a class="btn btn-outline-primary btn-sm" href="{{ url_for('employees_import_template') }}">
  <i class="bi bi-file-earmark-arrow-down"></i> تحميل نموذج الاستيراد</a>
 <form method="POST" action="{{ url_for('import_employees') }}" enctype="multipart/form-data"
       class="d-flex gap-2">
  <input type="file" name="file" accept=".xlsx,.xlsm,.csv" required class="form-control form-control-sm" style="width:auto">
  <button class="btn btn-success btn-sm"><i class="bi bi-upload"></i> استيراد</button>
 </form>
 <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('export_employees') }}">
  <i class="bi bi-download"></i> تصدير CSV</a>
 <a class="btn btn-success btn-sm" href="{{ url_for('connect_all_employees') }}">
  <i class="bi bi-plug"></i> اتصال بصناديق الكل + تحميل الوارد/المُرسَل</a>
</div>
<p class="text-muted small">اضغط <b>«تحميل نموذج الاستيراد»</b> لتنزيل ملف Excel بالأعمدة الجاهزة
 (<code>اسم المشترك · رقم الهوية · المهنة · Email</code>) — كل عمود منفصل، املأ الداتا
 وامسح صف المثال ثم ارفعه بـ «استيراد». يقبل Excel (.xlsx) أو CSV، ويفهم أسماء الأعمدة
 عربي أو إنجليزي. أي موظف جديد ياخد كلمة مرور افتراضية (022001) وتوقيعه بالتصميم الاحترافي تلقائياً.</p>
<div class="mb-3" style="max-width:420px">
 <div class="input-group">
  <span class="input-group-text"><i class="bi bi-search"></i></span>
  <input id="empSearch" class="form-control" placeholder="بحث بالاسم أو البريد أو الإقامة أو الرقم الوظيفي…"
         onkeyup="empFilter()" autocomplete="off">
 </div>
 <div class="form-text" id="empCount"></div>
</div>

<div class="card card-body py-2 mb-2" id="bulkBar" style="display:none">
 <div class="d-flex align-items-center gap-2 flex-wrap">
  <span class="badge bg-primary" id="bulkCount">0 محدد</span>
  <span class="small text-muted">— إجراء جماعي للكل:</span>
  <button class="btn btn-sm btn-outline-success" onclick="bulkDo('connect')">
   <i class="bi bi-plug"></i> اتصال/تحديث الصناديق</button>
  <button class="btn btn-sm btn-outline-primary" onclick="bulkDo('activate')">
   <i class="bi bi-check-circle"></i> تفعيل</button>
  <button class="btn btn-sm btn-outline-secondary" onclick="bulkDo('deactivate')">
   <i class="bi bi-pause-circle"></i> إيقاف</button>
  <button class="btn btn-sm btn-outline-info" onclick="bulkDo('login')">
   <i class="bi bi-key"></i> لوج إن</button>
  <span class="text-muted">|</span>
  <select id="bulkAccount" class="form-select form-select-sm" style="width:auto">
   <option value="">— بدون حساب (إلغاء تعيين) —</option>
   {% for a in accs %}<option value="{{ a.id }}">{{ a.display_name or a.email }}</option>{% endfor %}
  </select>
  <button class="btn btn-sm btn-outline-dark" onclick="bulkDo('move')">
   <i class="bi bi-arrow-left-right"></i> نقل للحساب</button>
  <span class="text-muted">|</span>
  <button class="btn btn-sm btn-danger" onclick="bulkDo('delete')">
   <i class="bi bi-trash"></i> حذف</button>
  <button class="btn btn-sm btn-light border" onclick="empClearSel()">إلغاء التحديد</button>
 </div>
</div>
<form id="bulkForm" method="POST" action="{{ url_for('employees_bulk') }}" class="d-none">
 <input type="hidden" name="bulk_action" id="bulkActionField">
 <input type="hidden" name="target_account" id="bulkAccountField">
 <span id="bulkIds"></span>
</form>

<div class="table-responsive">
<table class="table table-striped align-middle" id="empTable">
 <thead><tr>
   <th style="width:34px"><input type="checkbox" id="empAll" onclick="empToggleAll(this)"
       title="تحديد الكل"></th>
   <th>الاسم</th><th>البريد</th><th>الإقامة</th><th>الرقم الوظيفي</th><th>المنصب</th><th>القسم</th><th>الهاتف</th>
   <th>الحساب المسؤول</th><th>توقيع</th><th>الاتصال</th>
   <th>مُرسَلة</th><th>مُستقبَلة</th><th>نشط</th><th>إجراءات</th></tr></thead>
 <tbody>
 {% for e in rows %}
 <tr data-s="{{ (e.name ~ ' ' ~ e.email ~ ' ' ~ e.department ~ ' ' ~ e.title ~ ' ' ~ (e.iqama or '') ~ ' ' ~ (e.emp_number or ''))|lower }}">
  <td><input type="checkbox" class="emp-chk" value="{{ e.id }}" onclick="empSync()"></td>
  <td>{{ e.name }}</td><td dir="ltr" class="text-nowrap">{{ e.email }}</td>
  <td dir="ltr">{{ e.iqama or '—' }}</td><td dir="ltr">{{ e.emp_number or '—' }}</td><td>{{ e.title }}</td>
  <td>{{ e.department }}</td><td>{{ e.phone }}</td>
  <td class="small">{% if e.owner_email %}<span class="badge bg-info text-dark">{{ e.owner_name or e.owner_email }}</span>
      {% else %}<a class="text-muted" href="{{ url_for('distribution') }}">— تعيين —</a>{% endif %}</td>
  <td><button type="button" class="btn btn-sm btn-outline-secondary"
       onclick="showSig({{ e.id }}, '{{ e.name|replace("'", " ") }}')"
       title="عرض التوقيع الفعلي"><i class="bi bi-eye"></i> عرض</button></td>
  <td><span class="status-dot {{ 'on' if e.emp_connected else 'off' }}">
      {{ 'متصل' if e.emp_connected else 'غير متصل' }}</span></td>
  <td><span class="badge bg-success" title="رسائل أرسلها">{{ (counts.get(e.email|lower) or {}).get('sent', 0) }}</span></td>
  <td><span class="badge bg-info text-dark" title="رسائل وصلته">{{ (counts.get(e.email|lower) or {}).get('inbox', 0) }}</span></td>
  <td>{{ '✔' if e.active else '✖' }}</td>
  <td class="text-nowrap">
   <a class="btn btn-sm btn-primary" href="{{ url_for('mail_view', kind='employee', oid=e.id, bare=1) }}"
      target="_blank">
    <i class="bi bi-envelope-open"></i> فتح البريد</a>
   <button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal"
     data-bs-target="#ed{{ e.id }}">تعديل</button>
   {% if e.password %}
   <a class="btn btn-sm btn-outline-success" href="{{ url_for('connect_employee', eid=e.id) }}">
    {{ 'تحديث الصندوق' if e.emp_connected else 'اتصال' }}</a>
   {% endif %}
   <a class="btn btn-sm btn-outline-info" href="{{ url_for('employee_make_login', eid=e.id) }}">لوج إن</a>
   <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('toggle_employee', eid=e.id) }}">
    {{ 'إيقاف' if e.active else 'تفعيل' }}</a>
   <a class="btn btn-sm btn-danger" href="{{ url_for('delete_employee', eid=e.id) }}"
      onclick="return confirm('حذف الموظف؟')"><i class="bi bi-trash"></i></a>
  </td>
 </tr>
 {% else %}<tr><td colspan="15" class="text-muted">لا يوجد موظفون</td></tr>{% endfor %}
 </tbody>
</table>
</div>

{% for e in rows %}
<div class="modal fade" id="ed{{ e.id }}" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
 <form method="POST" action="{{ url_for('edit_employee', eid=e.id) }}">
  <div class="modal-header"><h5 class="modal-title">تعديل: {{ e.name }}</h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
   <div class="mb-2"><label>الاسم</label><input name="name" class="form-control" value="{{ e.name }}" required></div>
   <div class="mb-2"><label>البريد</label><input name="email" type="email" class="form-control" value="{{ e.email }}" required></div>
   <div class="row">
    <div class="col-6 mb-2"><label>رقم الإقامة</label><input name="iqama" class="form-control" dir="ltr" value="{{ e.iqama or '' }}"></div>
    <div class="col-6 mb-2"><label>الرقم الوظيفي</label><input name="emp_number" class="form-control" dir="ltr" value="{{ e.emp_number or '' }}"></div>
   </div>
   <div class="row">
    <div class="col-6 mb-2"><label>المنصب</label><input name="title" class="form-control" value="{{ e.title }}"></div>
    <div class="col-6 mb-2"><label>القسم</label><input name="department" class="form-control" value="{{ e.department }}"></div>
   </div>
   <div class="mb-2"><label>الهاتف</label><input name="phone" class="form-control" value="{{ e.phone }}"></div>
   <div class="mb-2"><label>كلمة مرور صندوق الموظف (للرد العكسي)</label>
    <input name="password" type="password" class="form-control" autocomplete="new-password"
     placeholder="{{ 'محفوظة — اتركها فارغة للإبقاء عليها' if e.password else 'غير محفوظة' }}"></div>
   <div class="mb-2"><label>التوقيع (اختياري — فاضي = توقيع الحساب الرئيسي)</label>
    <textarea name="signature" class="form-control" rows="3"
      placeholder="سيبه فاضي = ياخد توقيع الحساب الرئيسي تلقائياً">{{ e.signature }}</textarea>
    <div class="form-text">لو حطيت توقيع هنا هيتغلّب على توقيع الحساب الرئيسي لهذا الموظف فقط.</div></div>
  </div>
  <div class="modal-footer"><button class="btn btn-primary">حفظ</button></div>
 </form>
</div></div></div>
{% endfor %}

<div class="modal fade" id="add" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
 <form method="POST" action="{{ url_for('add_employee') }}">
  <div class="modal-header"><h5 class="modal-title">إضافة موظف</h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
   <div class="mb-2"><label>الاسم</label><input name="name" class="form-control" required></div>
   <div class="mb-2"><label>البريد الإلكتروني</label><input name="email" type="email" class="form-control" required></div>
   <div class="row">
    <div class="col-6 mb-2"><label>رقم الإقامة</label><input name="iqama" class="form-control" dir="ltr"></div>
    <div class="col-6 mb-2"><label>الرقم الوظيفي</label><input name="emp_number" class="form-control" dir="ltr"></div>
   </div>
   <div class="row">
    <div class="col-6 mb-2"><label>المنصب</label><input name="title" class="form-control"></div>
    <div class="col-6 mb-2"><label>القسم</label><input name="department" class="form-control"></div>
   </div>
   <div class="mb-2"><label>الهاتف</label><input name="phone" class="form-control"></div>
   <div class="mb-2"><label>كلمة مرور صندوق الموظف (اختياري — الافتراضي 022001)</label>
    <input name="password" type="password" class="form-control" autocomplete="new-password"></div>
   <div class="mb-2"><label>التوقيع (اختياري)</label>
    <textarea name="signature" class="form-control" rows="3"
      placeholder="سيبه فاضي = ياخد توقيع الحساب الرئيسي تلقائياً"></textarea>
    <div class="form-text">لو سِبته فاضي، الموظف بياخد <b>توقيع الحساب الرئيسي</b> تلقائياً. تقدر تحط توقيع خاص باستخدام {name} {title} {department} {phone} {email}.</div></div>
  </div>
  <div class="modal-footer"><button class="btn btn-primary">حفظ</button></div>
 </form>
</div></div></div>
<script>
function empFilter(){
 var q=(document.getElementById('empSearch').value||'').trim().toLowerCase();
 var rows=document.querySelectorAll('#empTable tbody tr'), shown=0;
 rows.forEach(function(r){
  var hit = !q || (r.dataset.s||'').indexOf(q) !== -1;
  r.style.display = hit ? '' : 'none';
  if(hit) shown++;
 });
 document.getElementById('empCount').textContent = q ? ('ظهر '+shown+' موظف') : '';
}
function empChecked(){
 return Array.prototype.slice.call(document.querySelectorAll('.emp-chk:checked'));
}
function empSync(){
 var n = empChecked().length;
 var bar = document.getElementById('bulkBar');
 bar.style.display = n ? '' : 'none';
 document.getElementById('bulkCount').textContent = n + ' محدد';
 var all = document.getElementById('empAll');
 var total = document.querySelectorAll('.emp-chk').length;
 all.checked = n>0 && n===total;
 all.indeterminate = n>0 && n<total;
}
function empToggleAll(cb){
 document.querySelectorAll('#empTable tbody tr').forEach(function(r){
  if(r.style.display==='none') return;      // الصفوف الظاهرة فقط (يحترم البحث)
  var c=r.querySelector('.emp-chk'); if(c) c.checked=cb.checked;
 });
 empSync();
}
function empClearSel(){
 document.querySelectorAll('.emp-chk').forEach(function(c){c.checked=false;});
 empSync();
}
function bulkDo(act){
 var ids = empChecked().map(function(c){return c.value;});
 if(!ids.length){ alert('حدّد موظف واحد على الأقل (أو علّم «تحديد الكل» فوق)'); return; }
 var labels={activate:'تفعيل',deactivate:'إيقاف',move:'نقل',delete:'حذف',
   connect:'اتصال/تحديث صناديق',login:'إنشاء لوج إن لـ'};
 var warn = (act==='delete')
   ? ('⚠️ حذف '+ids.length+' موظف نهائياً؟ لا يمكن التراجع.')
   : ('تأكيد '+labels[act]+' '+ids.length+' موظف؟');
 if(!confirm(warn)) return;
 document.getElementById('bulkActionField').value = act;
 document.getElementById('bulkAccountField').value =
   (act==='move') ? document.getElementById('bulkAccount').value : '';
 var box=document.getElementById('bulkIds'); box.innerHTML='';
 ids.forEach(function(id){
  var i=document.createElement('input'); i.type='hidden'; i.name='ids'; i.value=id;
  box.appendChild(i);
 });
 document.getElementById('bulkForm').submit();
}
function showSig(eid, name){
 var m=document.getElementById('sigModal');
 document.getElementById('sigModalName').textContent = name||'';
 document.getElementById('sigModalBody').innerHTML =
   '<div class="text-center text-muted py-4">… جارِ التحميل</div>';
 var bs=bootstrap.Modal.getOrCreateInstance(m); bs.show();
 fetch('/employees/'+eid+'/signature-preview')
  .then(function(r){return r.text()})
  .then(function(html){ document.getElementById('sigModalBody').innerHTML=html; })
  .catch(function(){ document.getElementById('sigModalBody').innerHTML=
    '<div class="text-danger py-3">تعذّر تحميل التوقيع</div>'; });
}
</script>

<div class="modal fade" id="sigModal" tabindex="-1"><div class="modal-dialog modal-lg">
 <div class="modal-content">
  <div class="modal-header"><h5 class="modal-title">توقيع: <span id="sigModalName"></span></h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body" id="sigModalBody" style="background:#eceff1"></div>
 </div></div></div>
{% endblock %}
"""

TEMPLATES_TPL = """
{% extends "base.html" %}{% block content %}
<style>
 .sig-wrap{max-width:860px;margin:0 auto}
 .sig-head{display:flex;align-items:center;gap:10px;margin-bottom:4px}
 .sig-head i{font-size:1.4rem;color:#0f6cbd}
 .sig-head h2{font-size:1.35rem;margin:0;font-weight:700;color:#1f2937}
 .sig-sub{color:#6b7280;font-size:.86rem;margin-bottom:18px}
 .sig-card{background:#fff;border:1px solid #e2e6ee;border-radius:12px;
   box-shadow:0 1px 3px rgba(20,40,80,.05);margin-bottom:16px;overflow:hidden}
 .sig-card-h{display:flex;align-items:center;gap:8px;padding:12px 16px;
   background:#f7f9fc;border-bottom:1px solid #e8ebf2;font-weight:700;font-size:.95rem;color:#243043}
 .sig-card-h i{color:#0f6cbd}
 .sig-card-b{padding:16px}
 .sig-hint{color:#6b7280;font-size:.8rem;margin-bottom:10px;line-height:1.7}
 .sig-hint code{background:#eef2f9;color:#0f6cbd;padding:1px 6px;border-radius:5px;font-size:.78rem}
 .sig-ta{width:100%;border:1px solid #d5dae4;border-radius:8px;padding:10px 12px;
   font-family:'Consolas','Courier New',monospace;font-size:.85rem;color:#243043;
   line-height:1.7;resize:vertical;outline:none;background:#fcfdff}
 .sig-ta:focus{border-color:#0f6cbd;box-shadow:0 0 0 3px rgba(15,108,189,.12)}
 .sig-acc{border:1.5px solid #c7d0e0;border-inline-start:4px solid #0f6cbd;border-radius:10px;
   padding:16px;margin-bottom:22px;background:#fbfcfe;box-shadow:0 2px 8px rgba(20,40,80,.06)}
 .sig-acc:last-child{margin-bottom:0}
 .sig-acc + .sig-acc{position:relative}
 .sig-acc-top{display:flex;align-items:center;gap:8px;margin-bottom:12px;padding-bottom:11px;
   border-bottom:2px solid #e2e6ee}
 .sig-acc-top .em{font-weight:700;color:#0f6cbd;font-size:.92rem}
 .sig-acc-top .nm{color:#6b7280;font-size:.82rem}
 .sig-btn{background:#0f6cbd;border:none;color:#fff;padding:7px 16px;border-radius:7px;
   font-size:.85rem;font-weight:600;cursor:pointer;transition:.15s}
 .sig-btn:hover{background:#115ea3}
 .sig-file{font-size:.82rem}
 .sig-logo{max-height:34px;border-radius:5px;border:1px solid #e2e6ee;padding:2px;background:#fff}
 .sig-prev-lbl{font-size:.78rem;font-weight:700;color:#0f6cbd;margin-bottom:5px}
 .sig-prev-lbl i{margin-inline-end:4px}
 .sig-prev{border:1px dashed #cbd5e6;border-radius:8px;background:#fff;padding:12px 14px;
   min-height:110px;font-family:'Segoe UI',Tahoma,Arial,sans-serif;font-size:.86rem;
   color:#242424;line-height:1.7;white-space:pre-wrap;overflow-wrap:anywhere}
 .sig-prev-logo{max-height:80px;margin-top:8px;border-radius:6px}
</style>
<div class="sig-wrap">
 <div class="sig-head"><i class="bi bi-pen-fill"></i><h2>توقيع الموظفين</h2></div>
 <div class="sig-sub">التوقيع اللي بيتحط تلقائياً في إيميلات الموظفين. (قوالب الرسائل المرسلة صفحة منفصلة في القائمة.)</div>

 <div class="sig-card">
  <div class="sig-card-h"><i class="bi bi-building-fill-check"></i> بيانات ثابتة لكل التواقيع</div>
  <div class="sig-card-b">
   <div class="sig-hint">الهاتف والموقع واللوجو دول <b>موحّدين</b> على كل التواقيع (الجديدة والقديمة):
    <code>{phone}</code> بيطلع الهاتف، <code>{website}</code> بيطلع الموقع، واللوجو بيظهر
    <b>على شمال التوقيع</b>. ارفع صورة واحدة وتتطبّق على الكل.</div>
   <form method="POST" action="{{ url_for('save_company_info') }}" enctype="multipart/form-data">
    <div class="row g-3">
     <div class="col-md-4">
      <label class="small text-muted mb-1">الهاتف الموحّد</label>
      <input name="company_phone" class="form-control" dir="ltr" value="{{ company_phone }}"></div>
     <div class="col-md-4">
      <label class="small text-muted mb-1">الموقع الموحّد</label>
      <input name="company_website" class="form-control" dir="ltr" value="{{ company_website }}"></div>
     <div class="col-md-4">
      <label class="small text-muted mb-1">لوجو موحّد لكل التواقيع (أقصى 3 ميجا · PNG/JPG/SVG)</label>
      <input name="logo" type="file" accept="image/*" class="form-control form-control-sm sig-file"></div>
    </div>
    <div class="mt-3">
     <label class="small text-muted mb-1 d-block">شكل التوقيع المعتمد</label>
     <label class="me-3 small"><input type="radio" name="signature_style" value="rich"
        {{ 'checked' if signature_style != 'text' }}> التصميم الاحترافي (زي الصورة)</label>
     <label class="small"><input type="radio" name="signature_style" value="text"
        {{ 'checked' if signature_style == 'text' }}> نصّي بسيط</label>
    </div>
    <div class="d-flex align-items-center gap-3 mt-3 flex-wrap">
     <button class="sig-btn"><i class="bi bi-check-lg"></i> حفظ البيانات الثابتة</button>
     {% if global_logo %}
      <span class="small text-muted">اللوجو الحالي:</span>
      <img src="{{ global_logo }}" class="sig-logo" alt="logo">
      <label class="small"><input type="checkbox" name="remove_logo"> حذف اللوجو الموحّد</label>
     {% else %}<span class="small text-muted">لا يوجد لوجو موحّد بعد.</span>{% endif %}
    </div>
   </form>
  </div>
 </div>

 <div class="sig-card">
  <div class="sig-card-h"><i class="bi bi-stars"></i> التصميم المعتمد للتوقيع (يُملأ من بيانات كل موظف)</div>
  <div class="sig-card-b">
   <div class="sig-hint">ده شكل التوقيع اللي بيتبعت فعلاً — الاسم/الوظيفة/الإيميل/القسم بتتعبّى
    من بيانات كل موظف، والهاتف/الموقع/اللوجو موحّدين من فوق. (الوظيفة = خانة «المنصب»،
    مكان 📍 = خانة «القسم».)</div>
   {% if not global_logo %}
   <div class="alert alert-warning py-2 small mb-2"><i class="bi bi-exclamation-triangle-fill"></i>
    لسه مرفعتش <b>لوجو موحّد</b> — ارفع صورة من كارت «بيانات ثابتة» فوق عشان تظهر على شمال التوقيع.</div>
   {% endif %}
   <div style="background:#eceff1;border-radius:10px;padding:24px;overflow:auto">
    {{ rich_preview|safe }}
   </div>
  </div>
 </div>

 <div class="sig-card">
  <div class="sig-card-h"><i class="bi bi-globe2"></i> قالب التوقيع العام (للوضع النصّي البسيط فقط)</div>
  <div class="sig-card-b">
   <div class="sig-hint">يُطبَّق على أي موظف مالوش توقيع خاص ولا حسابه الرئيسي له توقيع. المتغيرات:
    <code>{name}</code> <code>{title}</code> <code>{department}</code> <code>{email}</code>
    <code>{phone}</code> <code>{website}</code> —
    (<code>{phone}</code> و<code>{website}</code> قيمتهما ثابتة من «البيانات الثابتة» فوق)
    والسطر اللي متغيّره فاضي بيتشال تلقائياً.</div>
   <form method="POST" action="{{ url_for('save_signature_template') }}">
    <textarea name="signature_template" class="sig-ta" rows="5">{{ signature_template }}</textarea>
    <div class="mt-2"><button class="sig-btn"><i class="bi bi-check-lg"></i> حفظ قالب التوقيع</button></div>
   </form>
  </div>
 </div>

 <div class="sig-card">
  <div class="sig-card-h"><i class="bi bi-person-badge"></i> توقيع الحسابات الرئيسية</div>
  <div class="sig-card-b">
   {% if signature_style != 'text' %}
   <div class="alert alert-success py-2 small mb-3"><i class="bi bi-check-circle-fill"></i>
    التصميم الاحترافي مفعّل على <b>كل الحسابات</b> — بيتولّد تلقائياً من بيانات كل حساب
    + اللوجو الموحّد. مش محتاج تكتب حاجة.</div>
   {% for m in mains %}
   <div class="sig-acc">
    <div class="sig-acc-top">
     <span class="em" dir="ltr">{{ m.email }}</span>
     <span class="nm">{{ m.display_name }}</span>
    </div>
    <div dir="ltr" style="background:#eceff1;border-radius:8px;padding:16px;overflow:auto">
     {{ main_rich[m.id]|safe }}</div>
   </div>
   {% else %}
   <p class="text-muted mb-0 small">مفيش حسابات رئيسية لسه.</p>
   {% endfor %}
   {% else %}
   <div class="sig-hint">التوقيع اللي تحطه لحساب رئيسي بيتطبّق عليه <b>وعلى كل موظفيه</b> تلقائياً.
    الأولوية: توقيع الموظف الخاص ← توقيع حسابه الرئيسي ← قالب التوقيع العام.</div>
   {% for m in mains %}
   <div class="sig-acc">
    <div class="sig-acc-top">
     <span class="em" dir="ltr">{{ m.email }}</span>
     <span class="nm">{{ m.display_name }}</span>
     {% if m.logo %}<img src="{{ m.logo }}" class="sig-logo ms-auto" alt="logo">{% endif %}
    </div>
    <form method="POST" action="{{ url_for('save_account_signature', aid=m.id) }}" enctype="multipart/form-data">
     <div class="row g-3">
      <div class="col-md-6">
       <textarea name="signature" class="sig-ta" id="sigin{{ m.id }}" rows="6"
         data-email="{{ m.email }}" oninput="sigPrev({{ m.id }})"
         placeholder="Thanks &amp; Best Regards,&#10;{name}&#10;{title} | {department}&#10;Email: {email}&#10;Phone: {phone}">{{ m.signature }}</textarea>
      </div>
      <div class="col-md-6">
       <div class="sig-prev-lbl"><i class="bi bi-eye"></i> معاينة التوقيع</div>
       {% set shown_logo = global_logo or m.logo %}
       <div dir="ltr" style="display:flex;gap:12px;align-items:flex-start">
        {% if shown_logo %}<img src="{{ shown_logo }}"
           style="max-height:80px;border-radius:6px;flex:0 0 auto" alt="logo">{% endif %}
        <div class="sig-prev" id="sigprev{{ m.id }}" style="flex:1"></div>
       </div>
      </div>
     </div>
     <div class="row g-2 align-items-center mt-1">
      <div class="col-md-7"><label class="small text-muted mb-1">لوجو / صورة (أقصى 3 ميجا)</label>
       <input name="logo" type="file" accept="image/*" class="form-control form-control-sm sig-file"></div>
      <div class="col-md-5 text-md-end pt-2">
       {% if m.logo %}<label class="small me-2"><input type="checkbox" name="remove_logo"> حذف اللوجو</label>{% endif %}
       <button class="sig-btn"><i class="bi bi-check-lg"></i> حفظ توقيع الحساب</button></div>
     </div>
    </form>
   </div>
   {% else %}
   <p class="text-muted mb-0 small">مفيش حسابات رئيسية لسه — أنشئها من صفحة الدومينات أو الحسابات المرسِلة.</p>
   {% endfor %}
   {% endif %}
  </div>
 </div>

 <div class="sig-card" id="emps">
  <div class="sig-card-h"><i class="bi bi-people-fill"></i> توقيع كل الموظفين (مطبّق على الكل)</div>
  <div class="sig-card-b">
   {% if signature_style != 'text' %}
   <div class="alert alert-success py-2 small mb-3"><i class="bi bi-check-circle-fill"></i>
    التصميم الاحترافي مطبّق على <b>كل الموظفين الحاليين والجدد</b> — بيتولّد لحظة الإرسال من
    بيانات كل موظف (الاسم/المنصب/القسم/الإيميل) + الهاتف/الموقع/اللوجو الموحّدين.</div>
   <input id="empSigSearch" class="sig-ta mb-3" style="font-family:inherit"
          placeholder="بحث بالاسم أو البريد أو الإقامة أو الرقم الوظيفي…"
          onkeyup="empSigFilter()" autocomplete="off">
   {% for e in emps %}
   <div class="sig-acc emp-sig-row"
        data-s="{{ (e.name ~ ' ' ~ e.email ~ ' ' ~ (e.iqama or '') ~ ' ' ~ (e.emp_number or ''))|lower }}">
    <div class="sig-acc-top">
     <span class="em" dir="ltr">{{ e.email }}</span>
     <span class="nm">{{ e.name }}</span>
     <span class="nm">· حسابه: <b>{{ e.owner_name or e.owner_email or 'غير مربوط' }}</b></span>
    </div>
    <div dir="ltr" style="background:#eceff1;border-radius:8px;padding:16px;overflow:auto">
     {{ emp_rich[e.id]|safe }}</div>
   </div>
   {% else %}
   <p class="text-muted mb-0 small">مفيش موظفين لسه.</p>
   {% endfor %}
   {% else %}
   <div class="sig-hint">كل موظف يرث توقيع حسابه الرئيسي تلقائياً. اكتب توقيع خاص هنا واحفظ عشان يتغلّب عليه —
    سيبه فاضي واحفظ عشان يرجع يرث توقيع الحساب الرئيسي.</div>
   <input id="empSigSearch" class="sig-ta mb-3" style="font-family:inherit"
          placeholder="بحث بالاسم أو البريد أو الإقامة أو الرقم الوظيفي…"
          onkeyup="empSigFilter()" autocomplete="off">
   {% for e in emps %}
   <div class="sig-acc emp-sig-row"
        data-s="{{ (e.name ~ ' ' ~ e.email ~ ' ' ~ (e.iqama or '') ~ ' ' ~ (e.emp_number or ''))|lower }}">
    <div class="sig-acc-top">
     <span class="em" dir="ltr">{{ e.email }}</span>
     <span class="nm">{{ e.name }}</span>
     <span class="nm">· حسابه: <b>{{ e.owner_name or e.owner_email or 'غير مربوط' }}</b></span>
     {% if e.signature %}<span class="badge bg-info text-dark ms-auto">توقيع خاص</span>
     {% else %}<span class="badge bg-secondary ms-auto">يرث الرئيسي</span>{% endif %}
    </div>
    <form method="POST" action="{{ url_for('save_employee_signature', eid=e.id) }}">
     <textarea name="signature" class="sig-ta mb-2" rows="3"
       placeholder="فاضي = يرث توقيع الحساب الرئيسي{{ ' (' ~ e.owner_email ~ ')' if e.owner_email }}">{{ e.signature }}</textarea>
     <div class="text-md-end"><button class="sig-btn"><i class="bi bi-check-lg"></i> حفظ توقيع الموظف</button></div>
    </form>
   </div>
   {% else %}
   <p class="text-muted mb-0 small">مفيش موظفين لسه.</p>
   {% endfor %}
   {% endif %}
  </div>
 </div>
</div>
<script>
window.COMPANY_PHONE = {{ company_phone|tojson }};
window.COMPANY_SITE  = {{ company_website|tojson }};
function empSigFilter(){
 var q=(document.getElementById('empSigSearch').value||'').trim().toLowerCase();
 document.querySelectorAll('.emp-sig-row').forEach(function(r){
  r.style.display = (!q || (r.dataset.s||'').indexOf(q)!==-1) ? '' : 'none';
 });
}
function _esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function sigPrev(id){
 var ta=document.getElementById('sigin'+id), box=document.getElementById('sigprev'+id);
 if(!ta||!box) return;
 var txt=ta.value||ta.getAttribute('placeholder')||'';
 var sample={'{name}':'محمد أحمد','{first_name}':'محمد','{title}':'محاسب أول',
   '{department}':'المالية',
   '{phone}':(window.COMPANY_PHONE||'920035640'),
   '{company_phone}':(window.COMPANY_PHONE||'920035640'),
   '{website}':(window.COMPANY_SITE||'www.solutionstech.sa'),
   '{site}':(window.COMPANY_SITE||'www.solutionstech.sa'),
   '{email}':(ta.dataset.email||'name@domain.sa')};
 txt=_esc(txt);
 for(var k in sample){ txt=txt.split(k).join('<b>'+_esc(sample[k])+'</b>'); }
 // احذف الأسطر الفاضية زي ما البرنامج بيعمل
 txt=txt.split('\\n').filter(function(l){return l.trim()!=='';}).join('<br>');
 box.innerHTML=txt||'<span style="color:#9aa4b2">— التوقيع فاضي —</span>';
}
document.addEventListener('DOMContentLoaded',function(){
 document.querySelectorAll('textarea[id^=sigin]').forEach(function(ta){
  sigPrev(ta.id.replace('sigin',''));
 });
});
</script>
{% endblock %}
"""

MSG_TEMPLATES_TPL = """
{% extends "base.html" %}{% block content %}
<style>
 .mt-wrap{max-width:none;margin:0;padding:0 6px}
 .mt-head{display:flex;align-items:center;gap:8px;margin-bottom:2px}
 .mt-head i{font-size:1.25rem;color:#0f6cbd}
 .mt-head h2{font-size:1.2rem;margin:0;font-weight:700;color:#1f2937}
 .mt-sub{color:#6b7280;font-size:.8rem;margin-bottom:8px}
 .mt-add{background:#0f6cbd;border:none;color:#fff;padding:6px 14px;border-radius:7px;
   font-size:.84rem;font-weight:600;cursor:pointer;margin-bottom:10px}
 .mt-add:hover{background:#115ea3}
 .mt-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:10px}
 .mt-card{background:#fff;border:1.5px solid #c7d0e0;border-inline-start:4px solid #0f6cbd;
   border-radius:10px;padding:10px 12px;box-shadow:0 1px 6px rgba(20,40,80,.06)}
 .mt-card-t{display:flex;align-items:center;gap:6px;margin-bottom:6px;padding-bottom:6px;
   border-bottom:2px solid #eef1f6}
 .mt-card-t .nm{font-weight:700;color:#0f6cbd;font-size:.9rem}
 .mt-lbl{font-size:.72rem;color:#6b7280;font-weight:600;margin:6px 0 2px}
 .mt-inp{width:100%;border:1px solid #d5dae4;border-radius:6px;padding:5px 8px;font-size:.82rem;
   color:#243043;outline:none;background:#fcfdff}
 .mt-inp:focus{border-color:#0f6cbd;box-shadow:0 0 0 3px rgba(15,108,189,.1)}
 textarea.mt-inp{font-family:'Consolas','Courier New',monospace;line-height:1.5;resize:vertical}
 .mt-actions{display:flex;gap:6px;margin-top:8px}
 .mt-save{background:#0f6cbd;border:none;color:#fff;padding:6px 16px;border-radius:7px;
   font-size:.83rem;font-weight:600;cursor:pointer}
 .mt-save:hover{background:#115ea3}
 .mt-del{background:#fff;border:1px solid #e0b3b6;color:#c0392b;padding:6px 14px;border-radius:7px;
   font-size:.83rem;font-weight:600;text-decoration:none}
 .mt-del:hover{background:#fde7e9}
 .mt-vars{color:#6b7280;font-size:.8rem;margin-top:16px;line-height:1.8}
 .mt-vars code{background:#eef2f9;color:#0f6cbd;padding:1px 6px;border-radius:5px;font-size:.78rem}
 .mt-card-t .nm-btn{background:none;border:none;padding:0;cursor:pointer;text-align:start}
 .mt-card-t .nm-btn:hover{text-decoration:underline}
 .mt-cfg{margin-inline-start:auto;background:#eef6ff;border:1px solid #bcd9f5;color:#0f6cbd;
   font-size:.7rem;font-weight:700;padding:3px 8px;border-radius:20px;cursor:pointer;white-space:nowrap}
 .mt-cfg:hover{background:#dbeafe}
 .mt-senders{font-size:.7rem;color:#0a7d33;margin-top:4px;min-height:1em}
 .mt-senders i{font-size:.72rem}
 .cfg-sec{border:1px solid #e3e8f0;border-radius:10px;padding:10px 12px;margin-bottom:12px;background:#fbfcfe}
 .cfg-h{font-weight:700;color:#1f2937;font-size:.92rem;margin-bottom:3px}
 .cfg-h i{color:#0f6cbd;margin-inline-end:4px}
 .cfg-note{color:#6b7280;font-size:.76rem;margin-bottom:8px;line-height:1.6}
 .cfg-accs{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:6px}
 .cfg-acc{display:flex;align-items:center;gap:6px;border:1px solid #d9e0ec;border-radius:7px;
   padding:5px 8px;cursor:pointer;background:#fff;font-size:.8rem}
 .cfg-acc:hover{border-color:#0f6cbd;background:#f4f9ff}
 .cfg-acc input{margin:0}
 .cfg-acc span{display:flex;flex-direction:column;line-height:1.25}
 .cfg-acc small{color:#8a93a5;font-size:.68rem}
 .cfg-vars{color:#6b7280;font-size:.74rem;margin-top:6px}
 .cfg-vars code{background:#eef2f9;color:#0f6cbd;padding:1px 5px;border-radius:4px}
</style>
<div class="mt-wrap">
 <div class="mt-head"><i class="bi bi-megaphone"></i><h2>قوالب الرسائل المرسلة</h2></div>
 <div class="mt-sub">نصوص الرسائل اللي بتختار منها لما تعمل <b>حملة</b> إرسال جماعي — مش لها علاقة بالتوقيع.</div>
 <button class="mt-add" data-bs-toggle="modal" data-bs-target="#add">
  <i class="bi bi-plus-circle"></i> قالب رسالة جديد</button>
 <div class="mt-grid">
 {% for t in rows %}
  {% set sel = (t.send_accounts or '').split(',') %}
  <div class="mt-card">
   <div class="mt-card-t">
    <i class="bi bi-envelope-paper text-primary"></i>
    <button type="button" class="nm nm-btn" data-bs-toggle="modal" data-bs-target="#cfg{{ t.id }}"
            title="إعداد الإرسال والاستقبال">{{ t.name }}</button>
    <button type="button" class="mt-cfg" data-bs-toggle="modal" data-bs-target="#cfg{{ t.id }}">
     <i class="bi bi-arrow-left-right"></i> إرسال/استقبال</button>
   </div>
   <div class="mt-senders">
    {% set snames = [] %}
    {% for a in accs %}{% if a.id|string in sel %}{% set _ = snames.append(a.display_name or a.email) %}{% endif %}{% endfor %}
    {% if snames %}<i class="bi bi-send-check"></i> المرسِلون: {{ snames|join(' · ') }}{% endif %}
    {% if (t.reply_body or '').strip() %}<span style="color:#b26a00;margin-inline-start:6px"><i class="bi bi-robot"></i> له رد خاص</span>{% endif %}
   </div>
   <form method="POST" action="{{ url_for('edit_template', tid=t.id) }}">
    <div class="mt-lbl">اسم القالب</div>
    <input name="name" class="mt-inp" value="{{ t.name }}">
    <div class="mt-lbl">نص الرسالة</div>
    <textarea name="body" class="mt-inp" rows="5">{{ t.body }}</textarea>
    <div class="mt-actions">
     <button class="mt-save"><i class="bi bi-check-lg"></i> حفظ</button>
     <a class="mt-del" href="{{ url_for('delete_template', tid=t.id) }}"
        onclick="return confirm('حذف القالب؟')"><i class="bi bi-trash"></i> حذف</a>
    </div>
   </form>
  </div>
 {% else %}<p class="text-muted">لا توجد قوالب رسائل — اضغط «قالب رسالة جديد».</p>{% endfor %}
 </div>

 {# نافذة الإعداد لكل قالب: مين يبعت + رد الموظفين التلقائي عليه #}
 {% for t in rows %}
  {% set sel = (t.send_accounts or '').split(',') %}
  <div class="modal fade" id="cfg{{ t.id }}" tabindex="-1"><div class="modal-dialog modal-lg">
   <div class="modal-content">
    <form method="POST" action="{{ url_for('template_config', tid=t.id) }}">
     <div class="modal-header">
      <h5 class="modal-title"><i class="bi bi-arrow-left-right text-primary"></i>
       الإرسال والاستقبال — {{ t.name }}</h5>
      <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
     <div class="modal-body">
      <div class="cfg-sec">
       <div class="cfg-h"><i class="bi bi-send"></i> مين اللي يبعت القالب ده؟</div>
       <div class="cfg-note">اختَر الحسابات الرئيسية المخصّصة لإرسال هذا القالب — بتتسجّل وتظهر على الكارت كمرجع لمين بيبعت القالب ده.</div>
       <div class="cfg-accs">
        {% for a in accs %}
         <label class="cfg-acc">
          <input type="checkbox" name="send_accounts" value="{{ a.id }}"
                 {{ 'checked' if a.id|string in sel else '' }}>
          <span>{{ a.display_name or a.email }}<small>{{ a.email }}</small></span>
         </label>
        {% else %}<div class="text-muted small">لا توجد حسابات رئيسية.</div>{% endfor %}
       </div>
      </div>
      <div class="cfg-sec">
       <div class="cfg-h"><i class="bi bi-robot"></i> رد الموظفين التلقائي على القالب ده (الاستقبال)</div>
       <div class="cfg-note">لما الموظف يستلم رسالة من هذا القالب، صندوقه يرد تلقائياً بالنص ده.
        لو سِبته فاضي، يُستخدم رد الحساب المرسِل أو القسم أو الرد الافتراضي.</div>
       <textarea name="reply_body" class="form-control" rows="6"
        placeholder="شكراً على رسالتكم، تم الاطلاع وسيتم الرد قريباً.">{{ t.reply_body }}</textarea>
       <div class="cfg-vars">المتغيرات: <code>{name}</code> <code>{first_name}</code>
        <code>{title}</code> <code>{department}</code> <code>{phone}</code> <code>{email}</code></div>
      </div>
     </div>
     <div class="modal-footer">
      <button class="btn btn-primary"><i class="bi bi-check-lg"></i> حفظ الإعدادات</button></div>
    </form>
   </div></div></div>
 {% endfor %}
 <div class="mt-vars">المتغيرات داخل نص الرسالة: <code>{name}</code> <code>{first_name}</code>
  <code>{title}</code> <code>{department}</code> <code>{phone}</code> <code>{email}</code> —
  التوقيع يُضاف تلقائياً حسب الحساب المرسِل، وموضوع الإيميل = اسم القالب.</div>
</div>

<div class="modal fade" id="add" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
 <form method="POST" action="{{ url_for('add_template') }}">
  <div class="modal-header"><h5 class="modal-title">قالب رسالة جديد</h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
   <div class="mb-2"><label>اسم القالب</label><input name="name" class="form-control" required></div>
   <div class="mb-2"><label>نص الرسالة</label><textarea name="body" class="form-control" rows="6" required></textarea></div>
   <div class="form-text">موضوع الإيميل = اسم القالب، والتوقيع يُضاف تلقائياً حسب الحساب المرسِل.</div>
  </div>
  <div class="modal-footer"><button class="btn btn-primary">حفظ</button></div>
 </form>
</div></div></div>

<hr class="my-4" id="reverse">
{% include "reverse.html" %}
{% endblock %}
"""

CAMPAIGNS_TPL = """
{% extends "base.html" %}{% block content %}
<div class="page-head"><div><h1>الحملات</h1>
 <div class="sub">أرسل لكل الموظفين على دفعات — وقالب مختلف لكل قسم إن أردت</div></div></div>
{% if not templates %}
 <div class="alert alert-warning">أضف <b>قالب رسالة</b> واحد على الأقل قبل إنشاء حملة — من صفحة <a href="{{ url_for('message_templates_page') }}">قوالب الرسائل المرسلة</a>.</div>
{% else %}
<form method="POST" action="{{ url_for('add_campaign') }}" class="card card-body mb-4">
 <div class="row">
  <div class="col-md-4 mb-2"><label>اسم الحملة</label><input name="name" class="form-control" required></div>
  <div class="col-md-4 mb-2"><label>القالب الافتراضي</label>
   <select name="template_id" class="form-select">
    {% for t in templates %}<option value="{{ t.id }}">{{ t.name }}</option>{% endfor %}
   </select></div>
  <div class="col-md-4 mb-2"><label>فلترة المستلمين (اختياري)</label>
   <input name="filter" class="form-control" placeholder="اسم أو بريد أو قسم"></div>
 </div>
 <div class="row">
  <div class="col-md-6 mb-2">
   <label>مجموعة أي حساب؟</label>
   <select name="scope_account" class="form-select">
    <option value="">كل الموظفين (كل الحسابات)</option>
    {% for a in accs %}<option value="{{ a.id }}" {{ 'selected' if scope==a.id|string }}>
     {{ a.display_name or a.email }} — {{ a.n_emp }} موظف</option>{% endfor %}
   </select>
   <div class="form-text">اختر حساباً ليشمل مستلمو الحملة مجموعته فقط
    (التوزيع من صفحة «توزيع الموظفين»).</div>
  </div>
  <div class="col-md-3 mb-2"><label><i class="bi bi-calendar-event text-danger"></i> تاريخ الإرسال <span class="text-danger">*</span></label>
   <input name="send_date" type="date" class="form-control" required></div>
  <div class="col-md-3 mb-2"><label><i class="bi bi-clock"></i> ساعة الإرسال <span class="text-danger">*</span></label>
   <input name="send_time" type="time" class="form-control" value="12:00" required></div>
  <div class="col-md-3 mb-2"><label><i class="bi bi-reply-fill text-success"></i> تاريخ التسليم (الرد) <span class="text-danger">*</span></label>
   <input name="reply_date" type="date" class="form-control" required></div>
  <div class="col-md-3 mb-2"><label><i class="bi bi-clock-history"></i> ساعة التسليم <span class="text-danger">*</span></label>
   <input name="reply_time" type="time" class="form-control" value="12:00" required></div>
 </div>
 <div class="alert alert-info py-2 small mb-0">
  <i class="bi bi-info-circle"></i> <b>التواريخ دي هي المعتمدة</b>: الرسائل تتبعت بتاريخ الإرسال،
  والردود التلقائية توصل بتاريخ التسليم — من داخل الحملة دي فقط.</div>
 {% if departments %}
 <div class="mt-2">
  <label class="mb-1">قالب مختلف لكل قسم (اختياري — الفارغ يستخدم الافتراضي)</label>
  <div class="row g-2">
   {% for d in departments %}
   <div class="col-md-4"><div class="input-group input-group-sm">
    <span class="input-group-text" style="min-width:110px">{{ d or '(بدون قسم)' }}</span>
    <select name="dept_tpl::{{ d }}" class="form-select">
     <option value="">— الافتراضي —</option>
     {% for t in templates %}<option value="{{ t.id }}">{{ t.name }}</option>{% endfor %}
    </select>
   </div></div>
   {% endfor %}
  </div>
 </div>
 {% endif %}
 <div class="mt-3"><button class="btn btn-primary">
  <i class="bi bi-rocket-takeoff"></i> إنشاء الحملة وإضافة كل الموظفين</button></div>
 <p class="small text-muted mt-2 mb-0">كل الموظفين يدخلوا قائمة الانتظار، والجدولة تبعتهم على دفعات.
  فعّل الجدولة من <a href="{{ url_for('schedule_page') }}">الجدولة والحماية</a>.</p>
</form>
{% endif %}

<div class="d-flex align-items-center gap-2 mb-2 flex-wrap">
 <div class="input-group input-group-sm" style="width:auto">
  <span class="input-group-text"><i class="bi bi-search"></i></span>
  <input id="campSearch" class="form-control" placeholder="بحث باسم الحملة أو القالب…"
         onkeyup="campFilter()" autocomplete="off" style="min-width:220px"></div>
 <select id="campStatus" class="form-select form-select-sm" style="width:auto" onchange="campFilter()">
  <option value="">كل الحالات</option>
  <option value="active">نشطة</option>
  <option value="paused">متوقفة</option>
  <option value="completed">مكتملة</option>
 </select>
 <span class="small text-muted" id="campCount"></span>
</div>
<div class="d-flex align-items-center gap-2 mb-1">
 <span class="small text-muted"><i class="bi bi-arrow-repeat"></i> تحديث تلقائي كل ٥ ثوانٍ</span>
 <span class="small text-success" id="campLive"></span>
</div>
<div class="table-wrap" id="campTableWrap">
<table class="table align-middle">
 <thead><tr><th>#</th><th>الاسم</th><th>القالب</th><th>الحالة</th>
   <th>التقدّم</th><th>تاريخ الإرسال</th><th>تاريخ الاستقبال (الرد)</th><th>إجراءات</th></tr></thead>
 <tbody>
 {% for c in rows %}
 <tr data-s="{{ (c.name ~ ' ' ~ c.template_name)|lower }}" data-status="{{ c.status }}">
  <td>{{ c.id }}</td><td class="fw-semibold">{{ c.name }}</td>
  <td>{{ c.template_name }}{% if c.dept_count %}
      <span class="badge bg-info">+{{ c.dept_count }} قسم</span>{% endif %}</td>
  <td><span class="badge bg-{{ {'active':'primary','paused':'secondary','completed':'success'}[c.status] }}">
      {{ {'active':'نشطة','paused':'متوقفة','completed':'مكتملة'}[c.status] }}</span></td>
  <td style="min-width:210px">
   <div class="d-flex align-items-center gap-2 mb-1">
    <small style="min-width:46px" class="text-muted">إرسال</small>
    <div class="progress flex-grow-1" style="height:14px;border-radius:8px">
     <div class="progress-bar bg-success" style="width:{{ c.pct_sent }}%"></div>
     <div class="progress-bar bg-danger" style="width:{{ c.pct_failed }}%"></div>
    </div>
    {% if c.send_done %}<span class="badge bg-success"><i class="bi bi-check-lg"></i> اكتمل</span>
    {% elif c.sent or c.failed %}<span class="badge bg-primary">{{ c.pct_done }}%</span>
    {% else %}<span class="badge bg-secondary">بانتظار</span>{% endif %}
   </div>
   <div class="d-flex align-items-center gap-2">
    <small style="min-width:46px" class="text-muted">استقبال</small>
    <div class="progress flex-grow-1" style="height:14px;border-radius:8px">
     <div class="progress-bar bg-info" style="width:{{ c.pct_reply }}%"></div>
    </div>
    {% if c.reply_done %}<span class="badge bg-success"><i class="bi bi-check-lg"></i> اكتمل</span>
    {% elif c.replied %}<span class="badge bg-info text-dark">{{ c.pct_reply }}%</span>
    {% else %}<span class="badge bg-secondary">—</span>{% endif %}
   </div>
   <small class="text-muted">إرسال {{ c.done }}/{{ c.total }} · ردود {{ c.replied }}/{{ c.total }}</small>
  </td>
  <td class="small text-nowrap">
   {% if c.send_date %}<i class="bi bi-calendar-event text-primary"></i> {{ c.send_date }} {{ c.send_time }}
   {% elif c.last_sent %}<i class="bi bi-clock text-muted"></i> {{ c.last_sent }}
   {% else %}<span class="text-muted">—</span>{% endif %}</td>
  <td class="small text-nowrap">
   {% if c.reply_date %}<i class="bi bi-reply-fill text-success"></i> {{ c.reply_date }} {{ c.reply_time }}
    {% if c.last_reply %}<span class="badge bg-success ms-1" title="وصل فعلاً">✓</span>{% endif %}
   {% elif c.last_reply %}<i class="bi bi-reply-fill text-success"></i> {{ c.last_reply }}
   {% else %}<span class="text-muted">—</span>{% endif %}</td>
  <td class="text-nowrap">
   <a class="btn btn-sm btn-outline-primary" href="{{ url_for('campaign_detail', cid=c.id) }}">تفاصيل</a>
   <a class="btn btn-sm btn-outline-info" href="{{ url_for('campaign_duplicate', cid=c.id) }}"
      title="إنشاء نسخة جاهزة من الحملة"><i class="bi bi-files"></i> تكرار</a>
   <button class="btn btn-sm btn-outline-success" data-bs-toggle="modal"
     data-bs-target="#dt{{ c.id }}"><i class="bi bi-calendar2-week"></i> تعديل التواريخ</button>
   {% if c.status=='active' %}
    <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('campaign_action', cid=c.id, act='pause') }}">إيقاف</a>
   {% elif c.status=='paused' %}
    <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('campaign_action', cid=c.id, act='resume') }}">استئناف</a>
   {% endif %}
   <a class="btn btn-sm btn-danger" href="{{ url_for('campaign_action', cid=c.id, act='delete') }}"
      onclick="return confirm('حذف الحملة؟')">حذف</a>
  </td>
 </tr>
 {% else %}<tr><td colspan="8" class="mlist-empty">لا توجد حملات</td></tr>{% endfor %}
 </tbody>
</table>
</div>

{% for c in rows %}
<div class="modal fade" id="dt{{ c.id }}" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
 <form method="POST" action="{{ url_for('campaign_edit_dates', cid=c.id) }}">
  <div class="modal-header"><h5 class="modal-title">تعديل تواريخ: {{ c.name }}</h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
   <div class="row">
    <div class="col-6 mb-2"><label><i class="bi bi-calendar-event text-danger"></i> تاريخ الإرسال</label>
     <input name="send_date" type="date" class="form-control" value="{{ c.send_date }}" required></div>
    <div class="col-6 mb-2"><label>ساعة الإرسال</label>
     <input name="send_time" type="time" class="form-control" value="{{ c.send_time or '12:00' }}" required></div>
    <div class="col-6 mb-2"><label><i class="bi bi-reply-fill text-success"></i> تاريخ التسليم (الرد)</label>
     <input name="reply_date" type="date" class="form-control" value="{{ c.reply_date }}" required></div>
    <div class="col-6 mb-2"><label>ساعة التسليم</label>
     <input name="reply_time" type="time" class="form-control" value="{{ c.reply_time or '12:00' }}" required></div>
   </div>
   <div class="alert alert-info py-2 small mb-0"><i class="bi bi-info-circle"></i>
    التعديل بيأثّر على المستلمين اللي لسه ماتبعتلهمش والردود اللي لسه ماجتش.</div>
  </div>
  <div class="modal-footer"><button class="btn btn-primary"><i class="bi bi-save"></i> حفظ التواريخ</button></div>
 </form>
</div></div></div>
{% endfor %}
<script>
// بحث/فلترة قائمة الحملات (بالاسم/القالب + الحالة)
function campFilter(){
 var q=(document.getElementById('campSearch').value||'').trim().toLowerCase();
 var st=document.getElementById('campStatus').value;
 var rows=document.querySelectorAll('#campTableWrap tbody tr'), shown=0;
 rows.forEach(function(r){
  if(!r.dataset.s && !r.dataset.status) return;   // صف «لا توجد حملات»
  var hitQ = !q || (r.dataset.s||'').indexOf(q)!==-1;
  var hitS = !st || r.dataset.status===st;
  var hit = hitQ && hitS;
  r.style.display = hit ? '' : 'none';
  if(hit) shown++;
 });
 var el=document.getElementById('campCount');
 if(el) el.textContent=(q||st)?('ظهر '+shown+' حملة'):'';
}
// تحديث لحظي لجدول الحملات (التقدّم + التواريخ) بدون إعادة تحميل الصفحة
(function(){
 var wrap=document.getElementById('campTableWrap');
 if(!wrap) return;
 function tick(){
  fetch(location.pathname, {headers:{'X-Requested-With':'fetch'}})
   .then(function(r){return r.text()})
   .then(function(html){
     var doc=new DOMParser().parseFromString(html,'text/html');
     var fresh=doc.getElementById('campTableWrap');
     if(fresh && fresh.innerHTML!==wrap.innerHTML){
       wrap.innerHTML=fresh.innerHTML;
       campFilter();   // أعِد تطبيق الفلتر بعد التحديث اللحظي
       var live=document.getElementById('campLive');
       if(live){ live.textContent='✓ تم التحديث'; setTimeout(function(){live.textContent='';},1500); }
     }
   }).catch(function(){});
 }
 setInterval(tick, 5000);
})();
</script>
{% endblock %}
"""

QUICKSEND_TPL = """
{% extends "base.html" %}{% block content %}
<div class="d-flex align-items-center gap-2 mb-1">
 <h1 class="mb-0"><i class="bi bi-lightning-charge-fill text-warning"></i> إرسال سريع</h1></div>
<div class="text-muted small mb-3">اختَر القالب والحساب والتواريخ — والحملة تتعمل فوراً بكل موظفي الحساب.</div>

{% if not templates %}
 <div class="alert alert-warning">أضف <b>قالب رسالة</b> أولاً من
  <a href="{{ url_for('message_templates_page') }}">قوالب الرسائل المرسلة</a>.</div>
{% else %}
<form method="POST" action="{{ url_for('add_campaign') }}" class="card card-body"
      style="max-width:720px">
 <div class="row">
  <div class="col-md-6 mb-3"><label class="fw-semibold mb-1">
    <i class="bi bi-file-earmark-text text-primary"></i> القالب</label>
   <select name="template_id" class="form-select" required>
    {% for t in templates %}<option value="{{ t.id }}">{{ t.name }}</option>{% endfor %}
   </select></div>
  <div class="col-md-6 mb-3"><label class="fw-semibold mb-1">
    <i class="bi bi-person-badge text-success"></i> الحساب المُرسِل (مجموعته)</label>
   <select name="scope_account" class="form-select">
    <option value="">كل الموظفين ({{ total_emp }})</option>
    {% for a in accs %}<option value="{{ a.id }}">
     {{ a.display_name or a.email }} — {{ a.n_emp }} موظف</option>{% endfor %}
   </select></div>
 </div>
 <div class="row">
  <div class="col-6 col-md-3 mb-2"><label class="small">
    <i class="bi bi-calendar-event text-danger"></i> تاريخ الإرسال</label>
   <input name="send_date" type="date" class="form-control" value="{{ today }}" required></div>
  <div class="col-6 col-md-3 mb-2"><label class="small">
    <i class="bi bi-clock"></i> ساعة الإرسال</label>
   <input name="send_time" id="qsSendTime" type="time" class="form-control" value="12:00" required></div>
  <div class="col-6 col-md-3 mb-2"><label class="small">
    <i class="bi bi-reply-fill text-success"></i> تاريخ الرد</label>
   <input name="reply_date" type="date" class="form-control" value="{{ today }}" required></div>
  <div class="col-6 col-md-3 mb-2"><label class="small">
    <i class="bi bi-clock-history"></i> ساعة الرد</label>
   <input name="reply_time" id="qsReplyTime" type="time" class="form-control" value="12:00" required></div>
 </div>
 <div class="alert alert-light border py-2 small mb-3"><i class="bi bi-info-circle text-primary"></i>
  الوقت مضبوط على <b>الآن</b> فالحملة تتبعت فورًا وتتوزّع خلال دقيقة. الاسم بيتحط تلقائيًا،
  وتقدر تتابع الإرسال <b>لحظيًا</b> في صفحة <a href="{{ url_for('campaigns') }}">الحملات</a>.</div>
 <div class="d-flex gap-2">
  <button class="btn btn-primary btn-lg"><i class="bi bi-rocket-takeoff"></i> أنشئ وأرسل</button>
  <a class="btn btn-outline-secondary" href="{{ url_for('campaigns') }}">الحملات المتقدّمة</a>
 </div>
</form>
<script>
// اضبط وقت الإرسال/الرد على الآن (توقيت المتصفح) عشان الإرسال يبدأ فورًا
(function(){
 try{
  var now=new Date(new Date().toLocaleString('en-US',{timeZone:'Asia/Riyadh'}));
  var hh=('0'+now.getHours()).slice(-2), mm=('0'+now.getMinutes()).slice(-2);
  var s=document.getElementById('qsSendTime'), r=document.getElementById('qsReplyTime');
  if(s) s.value=hh+':'+mm; if(r) r.value=hh+':'+mm;
 }catch(e){}
})();
</script>
{% endif %}
{% endblock %}
"""

CAMPAIGN_DETAIL_TPL = """
{% extends "base.html" %}{% block content %}
<div class="page-head"><div><h1>حملة: {{ c.name }}</h1></div></div>
<p>
 <span class="badge bg-info">القالب الافتراضي: {{ c.template_name }}</span>
 <span class="badge bg-success">تم: {{ counts.sent }}</span>
 <span class="badge bg-warning">معلّق: {{ counts.pending }}</span>
 <span class="badge bg-danger">فشل: {{ counts.failed }}</span>
</p>
{% if dept_tpls %}
<div class="card"><div class="card-body py-2">
 <strong class="small">قوالب الأقسام:</strong>
 {% for d in dept_tpls %}<span class="badge bg-secondary">{{ d.department or '(بدون قسم)' }} → {{ d.name }}</span> {% endfor %}
</div></div>
{% endif %}
<div class="mb-3 d-flex gap-2 flex-wrap">
 <a class="btn btn-warning" href="{{ url_for('campaign_action', cid=c.id, act='send_now') }}">
  <i class="bi bi-send"></i> إرسال دفعة الآن</a>
 {% if counts.failed %}
 <a class="btn btn-outline-danger" href="{{ url_for('campaign_action', cid=c.id, act='retry_failed') }}">
  إعادة محاولة الفاشل ({{ counts.failed }})</a>
 {% endif %}
 <a class="btn btn-outline-success" href="{{ url_for('campaign_export', cid=c.id) }}">
  <i class="bi bi-download"></i> تصدير CSV</a>
 <a class="btn btn-outline-secondary" href="{{ url_for('campaigns') }}">رجوع</a>
</div>
{% if counts.pending %}
 {% if scheduler_on %}
 <div class="alert alert-success">الجدولة مفعّلة — المتبقّي ({{ counts.pending }}) هيترسل
  تلقائياً على دفعات. مش محتاج تعمل حاجة.</div>
 {% else %}
 <div class="alert alert-warning">الجدولة <strong>غير مفعّلة</strong> — فعّلها من
  <a href="{{ url_for('schedule_page') }}">الجدولة والحماية</a> عشان الباقي يترسل تلقائياً،
  أو اضغط «إرسال دفعة الآن» يدوياً في كل مرة.</div>
 {% endif %}
{% endif %}
<table class="table table-sm table-striped">
 <thead><tr><th>الموظف</th><th>البريد</th><th>الحالة</th><th>محاولات</th><th>الخطأ</th><th>وقت الإرسال</th></tr></thead>
 <tbody>
 {% for r in recipients %}
 <tr>
  <td>{{ r.name }}</td><td>{{ r.email }}</td>
  <td><span class="badge bg-{{ {'sent':'success','pending':'warning','failed':'danger'}[r.status] }}
     {{ 'text-dark' if r.status=='pending' }}">{{ r.status }}</span></td>
  <td>{{ r.attempts }}</td><td class="small text-danger">{{ r.error or '' }}</td>
  <td class="small">{{ r.sent_at or '' }}</td>
 </tr>
 {% endfor %}
 </tbody>
</table>
{% endblock %}
"""

SCHEDULE_TPL = """
{% extends "base.html" %}{% block content %}
<style>
 .sc-wrap{max-width:760px;margin:0 auto}
 .sc-head{display:flex;align-items:center;gap:10px;margin-bottom:14px}
 .sc-head i{font-size:1.4rem;color:#0f6cbd}
 .sc-head h2{font-size:1.35rem;margin:0;font-weight:700;color:#1f2937}
 .sc-card{background:#fff;border:1px solid #e2e6ee;border-radius:12px;margin-bottom:16px;
   box-shadow:0 1px 4px rgba(20,40,80,.05);overflow:hidden}
 .sc-card-h{display:flex;align-items:center;gap:8px;padding:11px 16px;background:#f7f9fc;
   border-bottom:1px solid #e8ebf2;font-weight:700;font-size:.98rem;color:#243043}
 .sc-card-h i{color:#0f6cbd}
 .sc-card-b{padding:16px}
 .sc-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
 @media(max-width:576px){.sc-grid{grid-template-columns:1fr}}
 .sc-fld label{display:block;font-size:.85rem;font-weight:600;color:#243043;margin-bottom:5px}
 .sc-ig{display:flex;align-items:stretch;border:1px solid #d5dae4;border-radius:8px;overflow:hidden;background:#fcfdff}
 .sc-ig input{border:none;outline:none;padding:9px 11px;font-size:.9rem;width:100%;background:transparent}
 .sc-ig input:focus{box-shadow:none}
 .sc-ig .unit{display:flex;align-items:center;padding:0 12px;background:#eef2f9;color:#0f6cbd;
   font-size:.8rem;font-weight:700;white-space:nowrap;border-inline-start:1px solid #d5dae4}
 .sc-ig:focus-within{border-color:#0f6cbd;box-shadow:0 0 0 3px rgba(15,108,189,.12)}
 .sc-hint{font-size:.75rem;color:#8a94a6;margin-top:4px}
 .sc-check{display:flex;align-items:flex-start;gap:9px;padding:10px 12px;border:1px solid #e6e9f0;
   border-radius:8px;margin-top:10px;background:#fbfcfe;cursor:pointer}
 .sc-check input{width:18px;height:18px;accent-color:#0f6cbd;margin-top:1px}
 .sc-check .t{font-size:.88rem;color:#243043;font-weight:600}
 .sc-check .d{font-size:.75rem;color:#8a94a6;margin-top:2px}
 .sc-btn{background:#0f6cbd;border:none;color:#fff;padding:10px 20px;border-radius:8px;
   font-size:.92rem;font-weight:600;cursor:pointer}
 .sc-btn:hover{background:#115ea3}
 .sc-btn-2{background:#fff;border:1px solid #e0a336;color:#b3730a;padding:9px 18px;border-radius:8px;
   font-size:.9rem;font-weight:600;text-decoration:none;display:inline-flex;align-items:center;gap:6px}
 .sc-btn-2:hover{background:#fff7ea}
 .sc-note{background:#eff6fc;border:1px solid #b3d3f0;border-radius:10px;padding:12px 14px;
   font-size:.82rem;color:#2c4a63;line-height:1.8}
</style>
<div class="sc-wrap">
 <div class="sc-head"><i class="bi bi-shield-fill-check"></i><h2>الجدولة والحماية من البلوك</h2></div>
 <form method="POST">

  <div class="sc-card">
   <div class="sc-card-h"><i class="bi bi-stack"></i> الدفعات</div>
   <div class="sc-card-b">
    <div class="sc-grid">
     <div class="sc-fld"><label>عدد الرسائل في كل دفعة</label>
      <div class="sc-ig"><input name="batch_size" type="number" min="1" value="{{ s.batch_size }}" required>
       <span class="unit">رسالة</span></div></div>
     <div class="sc-fld"><label>الفترة بين كل دفعة والتانية</label>
      <div class="sc-ig"><input name="interval_minutes" type="number" min="1" value="{{ s.interval_minutes }}" required>
       <span class="unit">دقيقة</span></div>
      <div class="sc-hint">مثلاً 5 = كل 5 دقائق تتبعت دفعة جديدة</div></div>
    </div>
    <label class="sc-check">
     <input type="checkbox" name="enabled" {{ 'checked' if s.enabled }}>
     <span><span class="t">تفعيل الإرسال المجدول التلقائي</span>
      <span class="d">لما يتفعّل، البرنامج يبعت الحملات على دفعات لوحده حسب الإعدادات دي.</span></span></label>
   </div>
  </div>

  <div class="sc-card">
   <div class="sc-card-h"><i class="bi bi-shield-lock"></i> الحماية من البلوك</div>
   <div class="sc-card-b">
    <div class="sc-grid">
     <div class="sc-fld"><label>أقل تأخير بين رسالتين</label>
      <div class="sc-ig"><input name="send_min_delay" type="number" min="0" value="{{ cfg.send_min_delay }}">
       <span class="unit">ثانية</span></div></div>
     <div class="sc-fld"><label>أكبر تأخير بين رسالتين</label>
      <div class="sc-ig"><input name="send_max_delay" type="number" min="0" value="{{ cfg.send_max_delay }}">
       <span class="unit">ثانية</span></div>
      <div class="sc-hint">البرنامج يستنى مدة عشوائية بين الرقمين قبل كل رسالة</div></div>
     <div class="sc-fld"><label>حد ساعي لكل حساب</label>
      <div class="sc-ig"><input name="per_account_hourly_limit" type="number" min="0" value="{{ cfg.per_account_hourly_limit }}">
       <span class="unit">/ ساعة</span></div>
      <div class="sc-hint">0 = بلا حد</div></div>
     <div class="sc-fld"><label>حد يومي لكل حساب</label>
      <div class="sc-ig"><input name="per_account_daily_limit" type="number" min="0" value="{{ cfg.per_account_daily_limit }}">
       <span class="unit">/ يوم</span></div>
      <div class="sc-hint">0 = بلا حد</div></div>
     <div class="sc-fld"><label>توزيع الحملة الداخلية على</label>
      <div class="sc-ig"><input name="campaign_spread_seconds" type="number" min="0" value="{{ cfg.campaign_spread_seconds or '60' }}">
       <span class="unit">ثانية</span></div>
      <div class="sc-hint">الحملة الداخلية تتبعت كلها موزّعة على المدة دي (افتراضي 60 ثانية · 0 = لحظي). مرة واحدة ثم تخلص.</div></div>
    </div>
    <label class="sc-check">
     <input type="checkbox" name="randomize_send" {{ 'checked' if cfg.randomize_send == '1' }}>
     <span><span class="t">ترتيب عشوائي</span>
      <span class="d">ترتيب المستلمين + اختيار الحساب المرسِل بشكل عشوائي (أأمن ضد البلوك).</span></span></label>
    <label class="sc-check">
     <input type="checkbox" name="save_to_sent" {{ 'checked' if cfg.save_to_sent == '1' }}>
     <span><span class="t">حفظ نسخة في مجلد Sent</span>
      <span class="d">تُحفظ نسخة من كل رسالة مُرسَلة في مجلد المُرسَل.</span></span></label>
   </div>
  </div>

  <div class="sc-card">
   <div class="sc-card-h"><i class="bi bi-calendar-event"></i> موعد الإرسال المجدول (اختياري)</div>
   <div class="sc-card-b">
    <div class="sc-grid">
     <div class="sc-fld"><label>تاريخ الإرسال</label>
      <div class="sc-ig"><input name="campaign_send_date" type="date" value="{{ cfg.campaign_send_date }}"></div></div>
     <div class="sc-fld"><label>وقت الإرسال</label>
      <div class="sc-ig"><input name="campaign_send_time" type="time" value="{{ cfg.campaign_send_time or '12:00' }}"></div></div>
    </div>
    <div class="sc-note mt-2">
     <b>إزاي يشتغل؟</b><br>
     • لو حطيت <b>موعد في المستقبل</b> → البرنامج يستنّى للموعد ده وبعدين يبعت الحملة تلقائياً.<br>
     • لو حطيت <b>موعد/تاريخ قديم</b> → الرسائل تتبعت خلال <b>دقيقة</b> وتتسجّل بنفس التاريخ القديم، والردود التلقائية تيجي بعدها.<br>
     • سيبهم فاضيين → الإرسال يشتغل على طول بالوقت الحالي.
    </div>
   </div>
  </div>

  <div class="d-flex align-items-center gap-2 flex-wrap">
   <button class="sc-btn"><i class="bi bi-save"></i> حفظ كل الإعدادات</button>
   <a class="sc-btn-2" href="{{ url_for('send_now') }}"><i class="bi bi-send"></i> إرسال دفعة الآن يدوياً</a>
   <span class="text-muted small ms-auto">آخر تشغيل دفعة: {{ s.last_run or 'لم يبدأ بعد' }}</span>
  </div>
 </form>

 <div class="sc-note mt-3">
  <b>مثال:</b> 250 موظف، دفعة = 20 رسالة، الفترة = 5 دقائق، تأخير 8–25 ثانية، 5 حسابات →
  كل حساب يرسل ~4 رسائل كل دفعة بفواصل، وتخلص الحملة خلال ~1–1.5 ساعة.
 </div>
</div>
{% endblock %}
"""

AUTOREPLY_TPL = """
{% extends "base.html" %}{% block content %}
<h2>الرد التلقائي</h2>
<form method="POST" class="card card-body" style="max-width:640px">
 <div class="form-check mb-3">
  <input class="form-check-input" type="checkbox" name="auto_reply_enabled" id="ar"
   {{ 'checked' if settings.auto_reply_enabled == '1' }}>
  <label class="form-check-label" for="ar">تفعيل الرد التلقائي على رسائل الوارد الجديدة</label></div>
 <div class="mb-2"><label>موضوع الرد</label>
  <input name="auto_reply_subject" class="form-control" value="{{ settings.auto_reply_subject }}"></div>
 <div class="mb-2"><label>نص الرد</label>
  <textarea name="auto_reply_body" class="form-control" rows="5">{{ settings.auto_reply_body }}</textarea></div>
 <div class="form-check mb-3">
  <input class="form-check-input" type="checkbox" name="mark_seen_on_fetch" id="ms"
   {{ 'checked' if settings.mark_seen_on_fetch == '1' }}>
  <label class="form-check-label" for="ms">وضع علامة "مقروء" على الرسائل عند جلبها من الخادم</label></div>
 <div><button class="btn btn-primary">حفظ</button></div>
</form>
{% endblock %}
"""

REVERSE_TPL = """
<style>
 .rv-wrap{max-width:1100px;margin:0 auto}
 .rv-head{display:flex;align-items:center;gap:10px;margin-bottom:2px}
 .rv-head i{font-size:1.4rem;color:#0f6cbd}
 .rv-head h2{font-size:1.35rem;margin:0;font-weight:700;color:#1f2937}
 .rv-sub{color:#6b7280;font-size:.82rem;margin-bottom:14px;line-height:1.8}
 .rv-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
 @media(max-width:640px){.rv-stats{grid-template-columns:repeat(2,1fr)}}
 .rv-stat{border-radius:12px;padding:14px 16px;color:#fff;box-shadow:0 2px 8px rgba(20,40,80,.1)}
 .rv-stat h6{font-size:.8rem;opacity:.95;margin:0 0 6px;font-weight:600}
 .rv-stat .n{font-size:1.7rem;font-weight:800;line-height:1}
 .rv-card{background:#fff;border:1px solid #e2e6ee;border-radius:12px;margin-bottom:16px;
   box-shadow:0 1px 4px rgba(20,40,80,.05);overflow:hidden}
 .rv-card-h{display:flex;align-items:center;gap:8px;padding:11px 16px;background:#f7f9fc;
   border-bottom:1px solid #e8ebf2;font-weight:700;font-size:.96rem;color:#243043}
 .rv-card-h i{color:#0f6cbd}
 .rv-card-b{padding:16px}
 .rv-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
 @media(max-width:576px){.rv-grid{grid-template-columns:1fr}}
 .rv-fld label{display:block;font-size:.83rem;font-weight:600;color:#243043;margin-bottom:5px}
 .rv-inp{width:100%;border:1px solid #d5dae4;border-radius:7px;padding:8px 10px;font-size:.86rem;
   background:#fcfdff;outline:none}
 .rv-inp:focus{border-color:#0f6cbd;box-shadow:0 0 0 3px rgba(15,108,189,.1)}
 textarea.rv-inp{resize:vertical;line-height:1.7}
 .rv-hint{font-size:.74rem;color:#8a94a6;margin-top:4px}
 .rv-check{display:flex;align-items:flex-start;gap:9px;padding:10px 12px;border:1px solid #e6e9f0;
   border-radius:8px;background:#fbfcfe;cursor:pointer}
 .rv-check input{width:18px;height:18px;accent-color:#0f6cbd;margin-top:1px}
 .rv-btn{background:#0f6cbd;border:none;color:#fff;padding:9px 18px;border-radius:8px;
   font-size:.9rem;font-weight:600;cursor:pointer}
 .rv-btn:hover{background:#115ea3}
 .rv-btn-o{background:#fff;border:1px solid #e0a336;color:#b3730a;padding:8px 15px;border-radius:8px;
   font-size:.86rem;font-weight:600;text-decoration:none;display:inline-flex;align-items:center;gap:6px}
 .rv-btn-o:hover{background:#fff7ea}
 .rv-acc{border:1.5px solid #c7d0e0;border-inline-start:4px solid #0f6cbd;border-radius:10px;
   padding:12px;margin-bottom:12px;background:#fbfcfe}
 .rv-acc-top{display:flex;align-items:center;gap:8px;margin-bottom:8px}
 .rv-acc-top .nm{font-weight:700;color:#243043}
 .rv-acc-top .em{font-size:.78rem;color:#0f6cbd;direction:ltr}
 .rv-search{border:1px solid #d5dae4;border-radius:8px;padding:9px 12px;font-size:.88rem;
   background:#fff;outline:none;width:100%;margin-bottom:12px}
 .rv-search:focus{border-color:#0f6cbd;box-shadow:0 0 0 3px rgba(15,108,189,.1)}
 .rv-emp-grp{border:1px solid #e2e6ee;border-radius:10px;margin-bottom:10px;overflow:hidden}
 .rv-emp-h{display:flex;align-items:center;gap:8px;padding:10px 14px;background:#f2f6fc;cursor:pointer;
   font-weight:700;font-size:.9rem;color:#243043}
 .rv-emp-h .chev{transition:transform .18s;color:#0f6cbd}
 .rv-emp-h.open .chev{transform:rotate(-90deg)}
 .rv-emp-h .cnt{margin-inline-start:auto;background:#0f6cbd;color:#fff;font-size:.7rem;font-weight:700;
   padding:2px 9px;border-radius:20px}
 .rv-emp-list{display:none}
 .rv-emp-list.open{display:block}
 .rv-emp-row{display:flex;align-items:center;gap:10px;padding:8px 14px;border-top:1px solid #eef1f6;font-size:.85rem}
 .rv-emp-row .e-em{color:#0f6cbd;direction:ltr}
 .rv-emp-row .e-dep{color:#8a94a6;font-size:.78rem}
 .rv-badge{font-size:.68rem;font-weight:700;padding:2px 8px;border-radius:20px}
 .rv-badge.on{background:#e6f4ea;color:#1e7e34}.rv-badge.off{background:#f1f3f5;color:#868e96}
 .rv-badge.rep{background:#eef2f9;color:#0f6cbd}
 .rv-table{width:100%;border-collapse:collapse;font-size:.84rem}
 .rv-table th{position:sticky;top:0;background:#eef2f9;color:#334;font-size:.75rem;font-weight:700;padding:8px 10px;text-align:start}
 .rv-table td{padding:7px 10px;border-bottom:1px solid #eef1f6}
</style>
<div class="rv-wrap">
 <div class="rv-head"><i class="bi bi-robot"></i><h2>الردود التلقائية</h2></div>
 <div class="rv-sub">لما الموظف يستلم رسالة من حسابه الرئيسي، صندوقه يردّ عليه <b>تلقائياً</b> بعد وقت تحدّده،
  بنص القالب (حسب الحساب أو القسم أو قالب عام)، ويتملّى ببيانات الموظف وتوقيعه.</div>

 <div class="rv-stats">
  <div class="rv-stat" style="background:linear-gradient(135deg,#0f6cbd,#2b88d8)">
   <h6>موظفون ببيانات دخول</h6><div class="n">{{ stats.with_creds }} / {{ stats.total }}</div></div>
  <div class="rv-stat" style="background:linear-gradient(135deg,#e0a800,#e6b52c)">
   <h6>بانتظار موعد الرد</h6><div class="n">{{ stats.waiting }}</div></div>
  <div class="rv-stat" style="background:linear-gradient(135deg,#1e9e54,#28a745)">
   <h6>ردود أُرسلت</h6><div class="n">{{ stats.sent }}</div></div>
  <div class="rv-stat" style="background:linear-gradient(135deg,#c0392b,#dc3545)">
   <h6>ردود فشلت</h6><div class="n">{{ stats.failed }}</div></div>
 </div>

 <form method="POST" action="{{ url_for('reverse_page') }}">
  <div class="rv-card">
   <div class="rv-card-h"><i class="bi bi-clock-history"></i> التوقيت والتشغيل</div>
   <div class="rv-card-b">
    <label class="rv-check mb-3">
     <input type="checkbox" name="reverse_enabled" {{ 'checked' if s.reverse_enabled=='1' }}>
     <span><span class="t fw-bold">تفعيل الرد العكسي التلقائي</span></span></label>
    <div class="rv-grid">
     <div class="rv-fld"><label>الرد بعد كم <b>ثانية</b> من وصول الرسالة</label>
      <input class="rv-inp" name="reverse_delay_seconds" type="number" min="0"
             value="{{ s.reverse_delay_seconds or '20' }}">
      <div class="rv-hint">الافتراضي 20 ثانية — الموظف ما يردّش إلا بعد مرور المدة دي من استلامه.</div></div>
     <div class="rv-fld"><label>فحص صناديق الموظفين كل (دقيقة)</label>
      <input class="rv-inp" name="reverse_scan_minutes" type="number" min="1"
             value="{{ s.reverse_scan_minutes or scan_default }}"></div>
     <div class="rv-fld"><label>صناديق تُفحص كل دورة</label>
      <input class="rv-inp" name="reverse_batch_size" type="number" min="1" value="{{ s.reverse_batch_size }}">
      <div class="rv-hint">اجعله بعدد الموظفين ({{ stats.with_creds }}) حتى يلتزم الجميع بالموعد.</div></div>
     <div class="rv-fld"><label>مدى التأخير العشوائي بين الردود (ثانية)</label>
      <div class="d-flex gap-2">
       <input class="rv-inp" name="reverse_min_delay" type="number" min="0" value="{{ s.reverse_min_delay }}" placeholder="أقل">
       <input class="rv-inp" name="reverse_max_delay" type="number" min="0" value="{{ s.reverse_max_delay }}" placeholder="أكبر"></div></div>
    </div>
   </div>
  </div>

  <div class="rv-card">
   <div class="rv-card-h"><i class="bi bi-hdd-network"></i> سيرفر بريد موحّد للموظفين (اختياري)</div>
   <div class="rv-card-b">
    <div class="rv-hint mb-2"><i class="bi bi-magic"></i> سيرفر كل موظف يُكتشف تلقائياً من نطاق بريده —
     املأ التالي فقط لو كل الموظفين على سيرفر واحد مخصّص.</div>
    <div class="rv-grid">
     <div class="rv-fld"><label>IMAP Server</label>
      <input class="rv-inp" name="emp_imap_server" placeholder="تلقائي" value="{{ s.emp_imap_server }}"></div>
     <div class="rv-fld"><label>IMAP Port</label>
      <input class="rv-inp" name="emp_imap_port" type="number" placeholder="993" value="{{ s.emp_imap_port }}"></div>
     <div class="rv-fld"><label>SMTP Server</label>
      <input class="rv-inp" name="emp_smtp_server" placeholder="تلقائي" value="{{ s.emp_smtp_server }}"></div>
     <div class="rv-fld"><label>SMTP Port</label>
      <input class="rv-inp" name="emp_smtp_port" type="number" placeholder="587" value="{{ s.emp_smtp_port }}"></div>
     <div class="rv-fld"><label>نوع تشفير SMTP</label>
      <select class="rv-inp" name="emp_security">
       <option value="">تلقائي</option>
       {% for v,l in [('starttls','STARTTLS (587)'),('ssl','SSL/TLS (465)'),('none','بدون')] %}
        <option value="{{ v }}" {{ 'selected' if s.emp_security==v }}>{{ l }}</option>{% endfor %}
      </select></div>
    </div>
   </div>
  </div>

  <div class="rv-card">
   <div class="rv-card-h"><i class="bi bi-chat-left-text"></i> نصوص الردود</div>
   <div class="rv-card-b">
    <div class="rv-fld mb-3"><label>نص الرد الافتراضي (يُستخدم لو مفيش نص للحساب أو القسم)</label>
     <textarea class="rv-inp" name="reverse_default_reply" rows="3">{{ s.reverse_default_reply }}</textarea></div>
    <div class="rv-card-h" style="background:none;border:none;padding:6px 0;font-size:.9rem">
     <i class="bi bi-1-circle"></i> نص الرد لكل حساب رئيسي (الأولوية الأعلى)</div>
    {% for a in accs %}
     <div class="rv-acc">
      <div class="rv-acc-top">
       <span class="nm">{{ a.display_name or a.email }}</span><span class="em">{{ a.email }}</span>
       <span class="ms-auto rv-hint">تأخير خاص (دقيقة):</span>
       <input class="rv-inp" style="width:90px" name="accdelay::{{ a.id }}" type="number" min="0"
              value="{{ acc_replies.get(a.id, {}).get('delay_minutes', 0) or '' }}" placeholder="عام">
      </div>
      <textarea class="rv-inp" name="accrep::{{ a.id }}" rows="2"
        placeholder="الرد الذي سيرسله موظفو هذا الحساب له">{{ acc_replies.get(a.id, {}).get('body', '') }}</textarea>
     </div>
    {% else %}<p class="text-muted small">أضف حسابات مرسِلة أولاً.</p>{% endfor %}
    <div class="rv-card-h" style="background:none;border:none;padding:10px 0 6px;font-size:.9rem">
     <i class="bi bi-2-circle"></i> نص الرد حسب القسم (لو نص الحساب فاضي)</div>
    <div class="rv-grid">
    {% for d in departments %}
     <div class="rv-fld"><label>{{ d or '(بدون قسم)' }}</label>
      <textarea class="rv-inp" name="dept::{{ d }}" rows="2">{{ dept_map.get(d, '') }}</textarea></div>
    {% else %}<p class="text-muted small">لا توجد أقسام بعد.</p>{% endfor %}
    </div>
    <p class="rv-hint mt-2">المتغيرات: <code>{name}</code> <code>{title}</code>
     <code>{department}</code> <code>{phone}</code> <code>{email}</code></p>
   </div>
  </div>

  <div class="d-flex align-items-center gap-2 flex-wrap mb-3">
   <button class="rv-btn"><i class="bi bi-save"></i> حفظ كل الإعدادات</button>
   <a class="rv-btn-o" href="{{ url_for('reverse_run') }}"><i class="bi bi-play-circle"></i> افحص الصناديق الآن</a>
   <a class="rv-btn-o" href="{{ url_for('reverse_flush') }}"><i class="bi bi-send-check"></i> أرسل ما حان موعده</a>
  </div>
 </form>

 <div class="rv-card">
  <div class="rv-card-h"><i class="bi bi-people-fill"></i> موظفو كل حساب رئيسي</div>
  <div class="rv-card-b">
   <input class="rv-search" id="rvEmpSearch" placeholder="بحث بالاسم أو البريد أو القسم…"
          onkeyup="rvEmpFilter()" autocomplete="off">
   {% for a in accs %}
   {% set grp = emps|selectattr('owner_account_id','equalto',a.id)|list %}
   <div class="rv-emp-grp" data-acc="{{ (a.display_name ~ ' ' ~ a.email)|lower }}">
    <div class="rv-emp-h" onclick="this.classList.toggle('open');this.nextElementSibling.classList.toggle('open')">
     <i class="bi bi-chevron-left chev"></i>
     <i class="bi bi-send-fill"></i> {{ a.display_name or a.email }}
     <span class="em" style="font-size:.76rem;color:#0f6cbd;direction:ltr">{{ a.email }}</span>
     <span class="cnt">{{ grp|length }} موظف</span>
    </div>
    <div class="rv-emp-list">
     {% for e in grp %}
     <div class="rv-emp-row" data-s="{{ (e.name ~ ' ' ~ e.email ~ ' ' ~ (e.department or ''))|lower }}">
      <span class="fw-semibold">{{ e.name }}</span>
      <span class="e-em">{{ e.email }}</span>
      {% if e.department %}<span class="e-dep">· {{ e.department }}</span>{% endif %}
      <span class="ms-auto d-flex gap-1">
       <span class="rv-badge {{ 'on' if e.emp_connected else 'off' }}">{{ 'متصل' if e.emp_connected else 'غير متصل' }}</span>
       {% if e.n_replies %}<span class="rv-badge rep">{{ e.n_replies }} رد</span>{% endif %}
      </span>
     </div>
     {% else %}<div class="rv-emp-row text-muted">لا يوجد موظفون تحت هذا الحساب</div>{% endfor %}
    </div>
   </div>
   {% else %}<p class="text-muted small mb-0">أضف حسابات رئيسية وموظفين أولاً.</p>{% endfor %}
  </div>
 </div>

 {% if queue %}
 <div class="rv-card">
  <div class="rv-card-h"><i class="bi bi-hourglass-split"></i> ردود بانتظار موعدها ({{ stats.waiting }})</div>
  <div class="rv-card-b">
   <div style="max-height:360px;overflow:auto;border:1px solid #e8ebf2;border-radius:9px">
   <table class="rv-table">
    <thead><tr><th>الموظف</th><th>سيرد على</th><th>الموضوع</th><th>وصلت</th><th>موعد الرد</th></tr></thead>
    <tbody>
    {% for q in queue %}
     <tr><td class="fw-semibold">{{ q.name }}<div class="small text-muted" dir="ltr">{{ q.emp_email }}</div></td>
      <td class="small" dir="ltr">{{ q.account_email }}</td>
      <td class="small">{{ q.subject }}</td>
      <td class="small text-muted">{{ q.received_at }}</td>
      <td class="small"><span class="rv-badge" style="background:#fff3cd;color:#8a5a00">{{ q.due_at }}</span></td></tr>
    {% endfor %}
    </tbody>
   </table>
   </div>
  </div>
 </div>
 {% endif %}
</div>
<script>
function rvEmpFilter(){
 var q=(document.getElementById('rvEmpSearch').value||'').trim().toLowerCase();
 document.querySelectorAll('.rv-emp-grp').forEach(function(grp){
  var rows=grp.querySelectorAll('.rv-emp-row[data-s]'), any=false;
  rows.forEach(function(r){
   var hit=!q||(r.dataset.s||'').indexOf(q)!==-1||(grp.dataset.acc||'').indexOf(q)!==-1;
   r.style.display=hit?'':'none'; if(hit) any=true;
  });
  grp.style.display=(any||!q)?'':'none';
  if(q){ grp.querySelector('.rv-emp-h').classList.add('open');
         grp.querySelector('.rv-emp-list').classList.add('open'); }
 });
}
</script>
"""

VISION2030_SVG = r'''<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 112 76"><g fill="#fff" clip-path="url(#logo_svg__a)"><path d="M15.115 16.317h-1.33V4.568h1.33zm10.877-3.185c0 2.016-1.684 3.327-4.021 3.327a6.9 6.9 0 0 1-4.818-1.88l.826-.975a5.61 5.61 0 0 0 4.044 1.694c1.579 0 2.624-.84 2.624-2 0-1.095-.587-1.717-3.067-2.249-2.706-.592-3.954-1.498-3.954-3.394 0-1.85 1.631-3.207 3.871-3.207a6.15 6.15 0 0 1 4.142 1.446l-.752 1.02A5.2 5.2 0 0 0 21.49 5.64c-1.504 0-2.511.839-2.511 1.895 0 1.102.609 1.724 3.202 2.248s3.834 1.499 3.834 3.327zM37.84 4.373a5.99 5.99 0 0 0-4.293 1.769 5.95 5.95 0 0 0-1.72 4.3v.038a5.98 5.98 0 0 0 1.774 4.233 6.01 6.01 0 0 0 4.257 1.742 6.03 6.03 0 0 0 4.247-1.769 6 6 0 0 0 1.748-4.244 5.88 5.88 0 0 0-1.715-4.297 5.92 5.92 0 0 0-4.298-1.742zm4.615 6.137a4.6 4.6 0 0 1-1.28 3.387 4.64 4.64 0 0 1-3.335 1.43 4.7 4.7 0 0 1-3.353-1.448 4.67 4.67 0 0 1-1.293-3.407 4.6 4.6 0 0 1 1.277-3.39 4.63 4.63 0 0 1 3.339-1.427 4.7 4.7 0 0 1 3.352 1.443 4.67 4.67 0 0 1 1.293 3.404zM28.172 4.598h1.33v11.719h-1.315zM5.727 16.4.661 4.569h1.503l.752 1.752 3.465 8.37.33.801-.127-1.288 3.939-9.636h1.428L6.907 16.4zm48.95-11.83h1.3v11.748h-1.06L46.603 5.752l.752 1.716v8.849h-1.346V4.568h1.248l7.968 10.108-.549-1.439zM91.945 17.56h1.263v1.243H91.96zm2.496 0h1.248v1.243H94.44zM68.74 3.322h-1.248V2.095h1.248zm30.518 8.7a5 5 0 0 0 1.646.749 8 8 0 0 0 1.977.24h.331l.421-.877v1.229a1.62 1.62 0 0 1-.564 1.4 2.6 2.6 0 0 1-1.578.42 4.7 4.7 0 0 1-1.03-.105 7 7 0 0 1-1.06-.374l-.383 1.198q.622.236 1.27.39.548.135 1.112.135a3.55 3.55 0 0 0 2.654-.862c.572-.635.869-1.47.827-2.322V4.582h-2a6.5 6.5 0 0 0-2.105.33 5 5 0 0 0-1.63.891 3.92 3.92 0 0 0-1.429 3.057c-.016.654.126 1.301.414 1.889.268.512.654.953 1.127 1.288zm0-4.391c.182-.368.438-.694.752-.96a3.722 3.722 0 0 1 2.307-.832h2.015l-.707.353v5.59h-1.262a4.4 4.4 0 0 1-1.323-.195 3.5 3.5 0 0 1-1.083-.57 2.6 2.6 0 0 1-.751-.914 2.8 2.8 0 0 1-.271-1.244c-.005-.427.096-.849.293-1.228zM71.207 3.338h-1.248V2.095h1.248zm36.832 13.105c-.344 0-.685-.048-1.015-.142l.331-1.192q.166.05.338.075h.301c.2.009.399-.024.586-.097a.75.75 0 0 0 .353-.33c.101-.183.164-.384.188-.592q.065-.443.06-.891V4.582h1.241v8.707q.006.661-.113 1.31a2.7 2.7 0 0 1-.399.997 1.8 1.8 0 0 1-.751.63 2.7 2.7 0 0 1-1.128.217zm-3.165-13.105h-2.736V2.32a1.6 1.6 0 0 1 .383-1.191 1.5 1.5 0 0 1 1.098-.375h.864v.907h-.857a.52.52 0 0 0-.383.105.56.56 0 0 0-.098.367v.277h1.714zM67.839 16.271h2.586v-.93c0 .046.052.09.082.128.188.275.448.492.752.63.357.157.745.231 1.135.217h23.302V4.582h-1.248v10.49H72.424c-.2.008-.4-.025-.586-.098a.8.8 0 0 1-.36-.33 1.6 1.6 0 0 1-.181-.591 6 6 0 0 1-.06-.892V4.582h-3.368a5.77 5.77 0 0 0-4.14 1.7 5.73 5.73 0 0 0-1.663 4.144 5.66 5.66 0 0 0 1.646 4.13 5.7 5.7 0 0 0 4.127 1.685zm-4.442-5.905a4.43 4.43 0 0 1 1.229-3.263 4.46 4.46 0 0 1 3.213-1.375h2.916l-.751.383v7.02a7 7 0 0 0 .12 1.311q.064.322.196.622h-2.436a4.52 4.52 0 0 1-3.252-1.377 4.5 4.5 0 0 1-1.258-3.29zM5.283 75.147H4.36L2.585 72.81l-.88.899v1.438H.94v-4.975h.766v2.675l2.541-2.675h.917L3.103 72.3zM7.072 70.172h-.767v4.975h.767zM12.937 70.172v4.975h-.654L9.35 71.378v3.77h-.752v-4.976h.737l2.849 3.664v-3.664zM18.852 72.428v2.045a3.2 3.2 0 0 1-2.075.75 2.48 2.48 0 0 1-1.863-.712 2.47 2.47 0 0 1-.73-1.85 2.54 2.54 0 0 1 .746-1.83 2.56 2.56 0 0 1 1.832-.748 2.68 2.68 0 0 1 1.88.637l-.482.569a2.1 2.1 0 0 0-1.428-.517c-.474.03-.918.246-1.236.599a1.8 1.8 0 0 0-.463 1.29 1.76 1.76 0 0 0 1.09 1.76c.229.095.475.14.722.135.46.006.911-.136 1.285-.405v-1.056h-1.323v-.645zM22.076 70.172h-1.842v4.975h1.842a2.51 2.51 0 0 0 2.487-1.489 2.49 2.49 0 0 0-.593-2.83 2.5 2.5 0 0 0-1.894-.656m0 4.293h-1.075v-3.612h1.075c.48 0 .941.19 1.28.53a1.803 1.803 0 0 1 0 2.553c-.339.339-.8.529-1.28.529M28.337 70.082a2.55 2.55 0 0 0-1.861.73 2.53 2.53 0 0 0-.755 1.848 2.6 2.6 0 0 0 1.605 2.42 2.62 2.62 0 0 0 2.855-.556 2.604 2.604 0 0 0-1.844-4.457zm1.804 2.578a1.79 1.79 0 0 1-1.096 1.73 1.8 1.8 0 0 1-.708.143 1.84 1.84 0 0 1-1.691-1.175 1.8 1.8 0 0 1-.12-.713 1.79 1.79 0 0 1 1.087-1.741c.224-.097.465-.147.71-.147a1.85 1.85 0 0 1 1.695 1.174c.088.228.13.47.123.714zM37.11 70.172v4.975h-.768v-3.821l-1.698 2.533-1.692-2.518v3.806h-.751v-4.975h.857l1.6 2.473 1.594-2.473zM43.514 70.082a2.56 2.56 0 0 0-1.864.73 2.54 2.54 0 0 0-.76 1.848 2.6 2.6 0 0 0 1.603 2.419 2.62 2.62 0 0 0 2.855-.553 2.605 2.605 0 0 0 .578-2.84 2.622 2.622 0 0 0-2.413-1.618zm1.796 2.578a1.79 1.79 0 0 1-1.09 1.727 1.8 1.8 0 0 1-.706.146 1.84 1.84 0 0 1-1.304-.565 1.83 1.83 0 0 1-.508-1.323 1.79 1.79 0 0 1 1.087-1.741c.224-.097.466-.147.71-.147a1.84 1.84 0 0 1 1.691 1.175c.088.227.128.47.12.713zM48.144 70.854v1.528h2.586v.682h-2.586v2.083h-.767v-4.975h3.683v.682zM58.367 73.761c0 .884-.692 1.499-1.767 1.499a3.1 3.1 0 0 1-2.037-.75l.451-.54c.44.403 1.013.63 1.61.638.593 0 .976-.278.976-.75s-.278-.636-1.21-.846c-1.067-.263-1.654-.57-1.654-1.499a1.495 1.495 0 0 1 1.073-1.365c.198-.058.406-.076.611-.05a2.77 2.77 0 0 1 1.767.584l-.406.576a2.33 2.33 0 0 0-1.376-.502c-.534 0-.902.278-.902.69s.27.63 1.27.869c1.15.277 1.594.682 1.594 1.446M61.99 70.135h-.751l-2.203 5.012h.752l.526-1.236h2.518l.519 1.236h.804zm-1.368 3.117.985-2.248.985 2.248zM69.154 70.172v2.833a1.98 1.98 0 0 1-1.26 2.123 2 2 0 0 1-.874.124 1.966 1.966 0 0 1-2.031-1.323 1.95 1.95 0 0 1-.09-.857v-2.877h.753v2.84c0 .966.496 1.498 1.368 1.498s1.353-.547 1.353-1.498v-2.878zM72.446 70.173h-1.841v4.975h1.841a2.51 2.51 0 0 0 2.487-1.489 2.49 2.49 0 0 0-.593-2.83 2.5 2.5 0 0 0-1.894-.656m0 4.293h-1.082v-3.612h1.082c.48 0 .941.19 1.281.53a1.803 1.803 0 0 1-1.28 3.082M77.152 70.172h-.767v4.975h.767zM83.887 70.135h-.752l-2.202 5.012h.752l.526-1.236h2.518l.519 1.236h.804zm-1.368 3.117.985-2.248.984 2.248zM89.9 73.244h.09a1.5 1.5 0 0 0 1.18-1.498 1.5 1.5 0 0 0-.405-1.072 2 2 0 0 0-1.436-.487h-2.255v4.975h.752v-1.798h1.218l1.24 1.754h.902zm-2.022-.54v-1.85h1.376c.752 0 1.135.33 1.135.914s-.443.937-1.127.937zM95.11 70.135h-.752l-2.202 5.012h.751l.527-1.236h2.518l.518 1.236h.805zm-1.376 3.117.985-2.248.992 2.248zM101.475 72.623l-.157-.053.142-.074a1.13 1.13 0 0 0 .699-1.08 1.11 1.11 0 0 0-.323-.817 1.82 1.82 0 0 0-1.293-.426h-2.255v4.975h2.308c1.15 0 1.834-.502 1.834-1.334a1.188 1.188 0 0 0-.97-1.191zm-2.435-1.79h1.368c.609 0 .97.269.97.749 0 .479-.376.749-1.038.749h-1.3zm1.564 3.656H99.04V72.99h1.503c.978 0 1.12.472 1.12.75 0 .509-.383.749-1.059.749M104.49 70.172h-.767v4.975h.767zM108.46 70.135h-.752l-2.195 5.012h.752l.526-1.236h2.518l.519 1.236h.804zm-1.368 3.117.984-2.248.993 2.248zM80.008 58.972h-.752v.749h.752zm-9.02 6.428h.752v-6.428h-.752zm-62.72-4.862h-.752v4.143H4.66v-4.143H3.555a3.9 3.9 0 0 0-1.218.18c-.34.11-.656.282-.932.509-.25.205-.455.46-.601.75a2.24 2.24 0 0 0-.21.966c-.009.378.074.753.24 1.094.157.294.378.55.646.749.285.204.607.351.947.434.368.1.747.15 1.128.15h4.713zM3.976 64.68h-.707a2.5 2.5 0 0 1-.751-.112 2.1 2.1 0 0 1-.624-.338 1.584 1.584 0 0 1-.564-1.289 1.5 1.5 0 0 1 .165-.704c.106-.21.255-.396.436-.547a1.9 1.9 0 0 1 .624-.344c.241-.087.496-.13.752-.128h.706zm2.3 2.3h.752v-.749h-.752zm-1.594-8.01h-.751v.75h.751zm43.876 0h-.752v.75h.752zm-41.042 8.01h.752v-.749h-.752zm42.297-8.01h-.751v.75h.751zm28.94 0H78v.75h.752zm-75.326 0h-.752v.75h.752zm48.784 8.01h.752v-.749h-.752zm4.608-6.443h-.752v4.143H53.37v-4.143h-.752v4.143H49.76v-4.143h-1.128a4 4 0 0 0-1.225.18c-.34.111-.655.284-.932.509-.249.205-.451.46-.594.75a2.24 2.24 0 0 0-.21.966c-.013.379.07.755.24 1.094.154.296.376.552.646.749.283.204.602.351.94.434.37.1.752.15 1.135.15h8.186zm-7.72 4.143h-.714a2.6 2.6 0 0 1-.752-.112 2.1 2.1 0 0 1-.616-.338 1.6 1.6 0 0 1-.421-.539 1.7 1.7 0 0 1-.15-.75 1.5 1.5 0 0 1 .165-.704 1.85 1.85 0 0 1 1.067-.891c.241-.087.496-.13.752-.128h.714zm4.367 2.3h.752v-.749h-.752zm-40.59-5.814c-.18-.2-.4-.361-.647-.472a2.1 2.1 0 0 0-.864-.157h-.526v.749h.624c.171 0 .34.038.496.112.148.068.279.167.383.292.1.12.173.261.21.412q.064.266.06.54v2.075H9.269v.75h4.089v-2.892a2.7 2.7 0 0 0-.113-.75 1.7 1.7 0 0 0-.346-.622zm55.33 3.551h-3.051l1.255-2.997a7 7 0 0 0-.609-.472 5 5 0 0 0-.669-.382q-.331-.167-.691-.262a2.8 2.8 0 0 0-.692-.097 2.8 2.8 0 0 0-.699.097 4 4 0 0 0-.661.247q-.354.163-.67.39a6 6 0 0 0-.593.472l1.263 2.997h-2.706v-4.173h-.752v5.012q.015.258 0 .517a1 1 0 0 1-.113.337.5.5 0 0 1-.203.188.9.9 0 0 1-.338.06h-.173l-.195-.045-.188.689q.288.076.586.075c.222.008.443-.033.647-.12.176-.095.324-.234.428-.405.112-.173.189-.366.226-.57q.07-.37.067-.748v-.15h9.246v-6.406h-.752zm-5.088 0-1.128-2.75c.252-.217.54-.389.85-.509.291-.105.6-.158.91-.157.33 0 .656.063.961.187.295.115.57.277.812.48l-1.127 2.75zm-7.028 2.3h.751v-.749h-.751zm53.564-1.58h.752v-6.466h-.752zm-2.811-.75h-2.466c.151-.331.228-.692.226-1.056a2.7 2.7 0 0 0-.203-1.034 2.6 2.6 0 0 0-.556-.824 2.5 2.5 0 0 0-.827-.555 2.7 2.7 0 0 0-1.037-.202 2.4 2.4 0 0 0-1.008.21 2.5 2.5 0 0 0-.811.554 2.64 2.64 0 0 0-.684 2.398q.053.262.157.51H97.38a2.6 2.6 0 0 0 .226-1.057 2.8 2.8 0 0 0-.203-1.034 2.6 2.6 0 0 0-.556-.824 2.5 2.5 0 0 0-.827-.555 2.7 2.7 0 0 0-1.038-.202 2.4 2.4 0 0 0-1.007.21 2.5 2.5 0 0 0-.812.554 2.64 2.64 0 0 0-.684 2.398q.054.262.158.51h-2.255v-5.717h-.751v5.709h-2.255v-1.094q0-.4-.106-.787a1.7 1.7 0 0 0-.97-1.094 2.2 2.2 0 0 0-.886-.157h-3.18l1.353-2.577h-.752l-1.383 2.57q.027.211.113.404.08.177.21.322h3.669c.2-.003.4.033.586.105a.98.98 0 0 1 .609.69q.052.259.052.524v1.094h-6.644v-4.143H78.91a3.9 3.9 0 0 0-1.218.18c-.342.111-.66.284-.94.509a2.4 2.4 0 0 0-.594.75 2.24 2.24 0 0 0-.21.966c-.008.378.074.753.24 1.094.158.294.378.55.647.749.283.202.602.35.94.434q.557.15 1.135.15h14.281a2.56 2.56 0 0 0 1.88.81 2.7 2.7 0 0 0 1.067-.21c.327-.137.622-.341.865-.6h3.157a2.56 2.56 0 0 0 1.879.81c.369.003.734-.068 1.075-.21.324-.14.615-.343.857-.6h3.653v-6.398h-.752zm-27.549 0h-.707a2.5 2.5 0 0 1-.751-.112 2.1 2.1 0 0 1-.624-.337 1.651 1.651 0 0 1-.413-1.963 1.84 1.84 0 0 1 1.067-.892c.24-.087.495-.13.752-.127h.706zm17.469-.314a1.8 1.8 0 0 1-.406.592c-.171.17-.376.303-.601.39-.24.092-.495.138-.752.134a1.85 1.85 0 0 1-.752-.142 1.7 1.7 0 0 1-.578-.405 1.83 1.83 0 0 1-.527-1.319c-.003-.256.043-.51.136-.749.09-.22.22-.424.383-.6a1.9 1.9 0 0 1 .579-.404c.237-.101.493-.152.752-.15.257-.002.513.046.751.143.222.093.426.225.602.39.169.173.304.376.398.599.094.239.142.493.143.749 0 .257-.05.512-.15.75zm6.946-.023a1.83 1.83 0 0 1-1.008.982 2 2 0 0 1-.751.135 1.743 1.743 0 0 1-1.331-.547 1.828 1.828 0 0 1-.526-1.319 2 2 0 0 1 .135-.75q.142-.33.384-.599c.166-.17.362-.306.578-.404.238-.102.494-.153.752-.15.258-.003.513.046.752.142.222.093.426.225.601.39.169.173.304.377.398.6.194.48.194 1.017 0 1.498zm-65.878.293h-1.135c-.34.015-.679-.047-.992-.18a1.3 1.3 0 0 1-.564-.54q.064-.33.06-.667v-2.27h-.714v2.42c.018.36-.103.715-.338.99a1.27 1.27 0 0 1-1 .374 1.505 1.505 0 0 1-1.03-.367 1.4 1.4 0 0 1-.293-.397 1.2 1.2 0 0 1-.12-.487v-2.533h-.751v2.48c.006.19-.027.379-.098.555a1.06 1.06 0 0 1-.654.591 1.6 1.6 0 0 1-.459.068H28.39v-3.694h-.751v3.694H23.88l1.263-2.997a8 8 0 0 0-.616-.472 5 5 0 0 0-.662-.382q-.331-.169-.691-.262a2.53 2.53 0 0 0-1.39 0q-.361.098-.7.254a4 4 0 0 0-.661.39q-.318.214-.602.472l1.27 2.997H18.62v-4.143h-1.15a3.7 3.7 0 0 0-1.218.187 3 3 0 0 0-.932.517 2.2 2.2 0 0 0-.61.75c-.144.303-.219.636-.217.973-.01.379.073.754.24 1.094.154.297.375.554.647.75.285.2.607.346.947.426.373.094.757.142 1.142.143h.429v.202a.95.95 0 0 1-.323.81c-.27.174-.589.258-.91.24q-.301.002-.594-.068a3.7 3.7 0 0 1-.609-.21l-.218.69q.405.145.752.224.316.076.64.075a2.04 2.04 0 0 0 1.502-.495 1.84 1.84 0 0 0 .482-1.34v-.128H29.78a1.88 1.88 0 0 0 1.586-.824c.171.281.415.512.707.666.332.17.702.252 1.075.24.377.013.753-.061 1.097-.217.3-.15.545-.392.699-.69q.095.161.218.3.144.164.338.263.235.128.496.187.257.056.519.06h2.075v-6.391h-.752zm-19.972 0h-.751a2.5 2.5 0 0 1-.752-.113 1.85 1.85 0 0 1-.624-.33 1.6 1.6 0 0 1-.42-.524 1.7 1.7 0 0 1-.151-.75 1.5 1.5 0 0 1 .165-.704 1.8 1.8 0 0 1 .444-.554c.187-.15.398-.27.624-.352.241-.085.496-.125.751-.12h.752zm3.962 0-1.12-2.75c.25-.22.537-.393.85-.51a2.64 2.64 0 0 1 1.87.03c.293.115.565.277.805.48l-1.12 2.75zm18.792.749h.751v-6.421h-.751zM96.5 22.64c-8.81 0-15.207 6.623-15.207 14.708v.082c0 8.085 6.322 14.626 15.124 14.626s15.199-6.623 15.199-14.708v-.082c0-8.085-6.314-14.626-15.117-14.626m8.553 14.79c0 4.87-3.502 8.857-8.554 8.857-5.05 0-8.644-4.061-8.644-8.94v-.081c0-4.878 3.51-8.857 8.562-8.857s8.636 4.061 8.636 8.939zm-94.222 8.737h10.876v5.402H.593v-4.953l9.501-7.762c3.54-2.93 4.931-4.496 4.931-6.826s-1.594-3.701-3.834-3.701-3.713 1.221-5.825 3.821L.96 28.634c2.811-3.821 5.54-5.89 10.636-5.89 5.909 0 9.825 3.455 9.825 8.775v.082c0 4.75-2.443 7.11-7.517 11.007l-6.216 4.758-1.21.929zm68.846-3.5v.083c0 5.365-3.916 9.306-10.276 9.306-5.134 0-8.681-2.03-11.124-4.915l4.322-4.106c1.954 2.195 3.991 3.417 6.885 3.417 2.368 0 4.037-1.342 4.037-3.455v-.082c0-2.315-2.083-3.619-5.585-3.619h-2.609l-.977-3.979 9.156-9.178-3.669 2.353h-9.892v-5.365h19.28v4.713l-7.215 6.863c3.908.674 7.667 2.682 7.667 7.965"></path></g><defs><clipPath id="logo_svg__a"><path fill="#fff" d="M0 .162h112v75.676H0z"></path></clipPath></defs></svg>'''


LOGIN_TPL = """
<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>تسجيل الدخول · Solutions Tech</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
 *{box-sizing:border-box}
 :root{--st-navy:#14176C;--st-gold:#FCB938}
 body{margin:0;min-height:100vh;font-family:'Cairo','Segoe UI',Tahoma,Arial,sans-serif;
   background:linear-gradient(135deg,#f5f7fc 0%,#eef1f8 100%)}
 /* تخطيط نصفين: لوحة تعريفية + كارت الدخول */
 .lg-wrap{display:flex;min-height:100vh}
 .lg-brand{flex:1.08;position:relative;overflow:hidden;color:#fff;
   background:linear-gradient(135deg,#14176C 0%,#20237f 55%,#0d0f46 100%);
   display:flex;flex-direction:column;justify-content:center;padding:56px 64px;z-index:0}
 .lg-brand::before{content:"";position:absolute;inset:0;z-index:-1;
   background:url('https://solutionstech.sa/storage/7711-850x480.jpg') center/cover no-repeat;
   opacity:.14}
 .lg-brand::after{content:"";position:absolute;z-index:-1;width:520px;height:520px;border-radius:50%;
   right:-180px;top:-160px;background:radial-gradient(circle,rgba(252,185,56,.30),transparent 68%)}
 .lg-chip{display:inline-flex;background:#fff;border-radius:14px;padding:16px 22px;
   box-shadow:0 12px 30px rgba(0,0,0,.22);align-self:flex-start;margin-bottom:34px}
 .lg-chip img{height:54px;width:auto;display:block}
 .lg-title{font-size:2.15rem;font-weight:800;line-height:1.3;margin:0 0 10px}
 .lg-sub{font-size:1rem;color:#d6d8f5;margin:0 0 30px;max-width:460px;line-height:1.9}
 .lg-feats{list-style:none;padding:0;margin:0 0 34px;display:grid;gap:13px;max-width:470px}
 .lg-feats li{display:flex;align-items:center;gap:12px;font-size:1rem;color:#eef0ff}
 .lg-feats i{color:#FCB938;font-size:1.15rem;flex:0 0 auto}
 .lg-contact{display:flex;gap:22px;flex-wrap:wrap;font-size:.92rem;color:#c9ccf0;
   border-top:1px solid rgba(255,255,255,.15);padding-top:20px}
 .lg-contact span{display:inline-flex;align-items:center;gap:8px}
 .lg-contact i{color:#FCB938}
 .lg-vision{display:flex;align-items:center;gap:16px;margin:24px 0 4px;padding:16px 18px;
   border-radius:12px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.14)}
 .lg-vision svg{height:70px;width:auto;flex:0 0 auto}
 .lg-vision span{font-size:.88rem;color:#eef0ff;line-height:1.8}
 .lg-login{flex:.92;display:flex;flex-direction:column;align-items:center;justify-content:center;
   padding:26px;position:relative;overflow:hidden}
 /* خلفية مزخرفة بالهوية: تدرّج ناعم + علامة سهم ذهبي باهتة */
 .lg-login::before{content:"";position:absolute;inset:0;z-index:0;pointer-events:none;
   background:radial-gradient(520px 320px at 18% 12%, rgba(252,185,56,.13), transparent 60%),
             radial-gradient(560px 360px at 92% 104%, rgba(20,23,108,.10), transparent 60%)}
 .lg-login::after{content:"";position:absolute;z-index:0;width:340px;height:340px;left:-70px;bottom:-70px;
   pointer-events:none;opacity:.06;transform:rotate(-8deg);background:no-repeat center/contain;
   background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cpath fill='%23FCB938' d='M8 18 L72 18 L50 44 L8 44 Z'/%3E%3Cpath fill='%23FCB938' d='M8 54 L62 54 L40 80 L8 80 Z'/%3E%3C/svg%3E")}
 .lg-welcome{position:relative;z-index:1;text-align:center;margin-bottom:20px}
 .lg-welcome h2{font-size:1.5rem;font-weight:800;color:var(--st-navy);margin:0 0 3px}
 .lg-welcome p{font-size:.9rem;color:#6b7280;margin:0 0 10px}
 .lg-clock{display:inline-flex;align-items:center;gap:8px;background:#fff;border:1px solid #e3e6f0;
   border-radius:999px;padding:6px 15px;font-size:.84rem;color:var(--st-navy);font-weight:700;
   box-shadow:0 4px 12px rgba(20,23,108,.10)}
 .lg-clock i{color:var(--st-gold)}
 .lg-login .ow-card{position:relative;z-index:1}
 @media(max-width:900px){ .lg-brand{display:none} .lg-login{flex:1} }
 .ow-card{width:min(560px,94vw);min-height:560px;background:#fff;
   border:1px solid #e3e6f0;border-top:5px solid var(--st-gold);border-radius:16px;
   box-shadow:0 22px 60px rgba(20,23,108,.20);position:relative;overflow:hidden;
   padding:40px 56px 28px;display:flex;flex-direction:column}
 .ow-card::before{content:"";position:absolute;inset:0 0 auto 0;height:5px;
   background:linear-gradient(90deg,var(--st-gold),#ffd16b,var(--st-gold))}
 .ow-close{position:absolute;top:14px;left:16px;color:#d13438;font-size:1.25rem;
   width:34px;height:34px;border-radius:8px;background:none;border:none;cursor:pointer;
   line-height:1;display:flex;align-items:center;justify-content:center;transition:.15s}
 .ow-close:hover{background:#fde7e9;color:#a4262c}
 .ow-brand{display:flex;flex-direction:column;align-items:center;gap:10px;margin-top:40px;margin-bottom:42px}
 .ow-brand img{width:min(300px,72%);height:auto;display:block}
 .ow-brand .fallback{display:none;font-size:2rem;font-weight:800;color:var(--st-navy);letter-spacing:1px}
 .ow-brand .rule{width:64px;height:4px;border-radius:3px;background:var(--st-gold)}
 .ow-brand .tag{font-size:.9rem;color:#6b7280;font-weight:600}
 .ow-body{flex:1;display:flex;flex-direction:column}
 .ow-lbl{font-size:.92rem;color:#242424;margin-bottom:6px;font-weight:600}
 .ow-inp{width:100%;border:none;border-bottom:2px solid #605e5c;background:transparent;
   padding:9px 2px;font-size:1rem;color:#242424;outline:none}
 .ow-inp:focus{border-bottom-color:var(--st-navy)}
 .ow-inp::placeholder{color:#a19f9d}
 .ow-field{margin-bottom:26px}
 .ow-remember{display:flex;align-items:center;gap:8px;font-size:.9rem;color:#242424;
   margin:-8px 0 18px;cursor:pointer;user-select:none}
 .ow-remember input{width:16px;height:16px;accent-color:var(--st-navy);cursor:pointer}
 .ow-adv{text-align:center;font-weight:700;color:#242424;font-size:.95rem;margin:8px 0 4px;
   cursor:pointer;user-select:none}
 .ow-adv i{font-size:.8rem}
 .ow-alert{background:#fde7e9;border:1px solid #f3b5bb;color:#a4262c;border-radius:2px;
   padding:8px 12px;font-size:.88rem;margin-bottom:14px}
 .ow-alert.info{background:#eef0fb;border-color:#c3c7ea;color:var(--st-navy)}
 .ow-foot{margin-top:auto;padding-top:24px}
 .ow-btn{width:100%;border:none;background:var(--st-navy);color:#fff;font-family:inherit;
   padding:13px;font-size:1.05rem;font-weight:700;border-radius:10px;cursor:pointer;transition:.15s;
   box-shadow:0 6px 18px rgba(20,23,108,.28)}
 .ow-btn:hover{background:#0e1050;box-shadow:0 8px 22px rgba(20,23,108,.36)}
 .ow-btn:active{transform:translateY(1px)}
 .ow-legal{position:fixed;bottom:10px;right:14px;left:14px;display:flex;align-items:center;gap:22px;
   font-size:.82rem;color:#605e5c}
 .ow-legal a{color:#605e5c;text-decoration:none}
 .ow-legal a:hover{text-decoration:underline}
 .ow-legal .dots{font-weight:700;letter-spacing:1px}
 .ow-manual{max-height:0;overflow:hidden;transition:max-height .2s ease}
 .ow-manual.open{max-height:60px}
 .ow-manual-lbl{display:flex;align-items:center;gap:8px;font-size:.9rem;color:#242424;
   margin:10px 0 4px;cursor:pointer;user-select:none}
 .ow-manual-lbl input{width:16px;height:16px;accent-color:var(--st-navy);cursor:pointer}
 #owAdvChev{transition:transform .2s}
 #owAdvChev.up{transform:rotate(180deg)}
 /* شاشة الإعداد المتقدم */
 .ow-advscreen{display:none;position:fixed;inset:0;background:#f3f2f1;
   align-items:center;justify-content:center;z-index:50}
 .ow-advscreen.show{display:flex}
 .ow-adv-card{min-height:520px}
 .ow-adv-brand{display:flex;align-items:center;gap:9px;margin:6px 0 26px}
 .ow-logo.sm{width:30px;height:30px;border-radius:5px}
 .ow-logo.sm i{font-size:1rem}
 .ow-adv-name{font-size:1.15rem;color:var(--st-navy);font-weight:700}
 .ow-adv-title{font-size:1.5rem;font-weight:700;color:#242424;margin:0 0 26px}
 .ow-prov{display:grid;grid-template-columns:repeat(4,1fr);gap:24px 10px;flex:1;align-content:start}
 .ow-prov-tile{display:flex;flex-direction:column;align-items:center;gap:9px;cursor:pointer;
   font-size:.82rem;color:#242424;text-align:center;padding:8px 4px;border-radius:8px;transition:.15s}
 .ow-prov-tile:hover{background:#eff6fc}
 .ow-prov-tile .pi{font-size:2.1rem;line-height:1}
 .ow-goback{margin-top:18px;color:var(--st-navy);text-decoration:none;font-size:.95rem}
 .ow-goback:hover{text-decoration:underline}
</style></head><body>
<div class="lg-wrap">
 <aside class="lg-brand">
  <div class="lg-chip">
   <img src="https://solutionstech.sa/storage/logo/22-removebg-preview.png" alt="Solutions Tech"
        onerror="this.outerHTML='<span style=&quot;font-size:1.6rem;font-weight:800;color:#14176C&quot;>SOLUTIONS <span style=&quot;color:#FCB938&quot;>TECH</span></span>'">
  </div>
  <h1 class="lg-title">شريكك في<br>إدارة القوى العاملة</h1>
  <p class="lg-sub">نوفّر ونُدير الكوادر نيابةً عنك — من التوظيف والعقود إلى الرواتب
   والإقامات، بالتزام نظامي كامل ودون التأثير على نطاق منشأتك.</p>
  <ul class="lg-feats">
   <li><i class="bi bi-people-fill"></i> كوادر متخصصة لكل القطاعات: تقنية المعلومات · مصانع · صحة · تجزئة · لوجستيات · نفط وغاز</li>
   <li><i class="bi bi-globe2"></i> استقدام خارجي وتوظيف من داخل المملكة وتوفير عمالة فوري</li>
   <li><i class="bi bi-arrow-left-right"></i> تحويل الكفالة وإسناد الموارد البشرية</li>
   <li><i class="bi bi-patch-check-fill"></i> تكامل نظامي: مدد · التأمينات · مقيم · قوى · أجير</li>
  </ul>
  <div class="lg-contact">
   <span><i class="bi bi-telephone-fill"></i> 920015704</span>
   <span><i class="bi bi-globe"></i> solutionstech.sa</span>
  </div>
  <div class="lg-vision">
   {{ vision2030_svg|safe }}
   <span>نفخر بدعم رؤية المملكة 2030<br>في تمكين القوى العاملة الوطنية</span>
  </div>
 </aside>
 <main class="lg-login">
 <div class="lg-welcome">
  <h2>مرحباً بك 👋</h2>
  <p>سجّل الدخول للمتابعة إلى لوحة التحكم</p>
  <span class="lg-clock"><i class="bi bi-clock"></i> <span id="lgClock">—</span></span>
 </div>
<div class="ow-card">
 <button type="button" class="ow-close" onclick="history.length>1?history.back():null" title="إغلاق"><i class="bi bi-x-lg"></i></button>
 <div class="ow-brand">
  <img src="https://solutionstech.sa/storage/logo/22-removebg-preview.png" alt="Solutions Tech"
       onerror="this.style.display='none';document.getElementById('owFallback').style.display='block'">
  <div class="fallback" id="owFallback">SOLUTIONS <span style="color:var(--st-gold)">TECH</span></div>
  <div class="rule"></div>
 </div>
 <form method="POST" class="ow-body">
  {% with msgs = get_flashed_messages(with_categories=true) %}
   {% for cat,m in msgs %}<div class="ow-alert {{ 'info' if cat!='error' }}">{{ m }}</div>{% endfor %}
  {% endwith %}
  <div class="ow-field">
   <label class="ow-lbl">البريد الإلكتروني</label>
   <input name="username" class="ow-inp" placeholder="اكتب بريدك الإلكتروني" autofocus required>
  </div>
  <div class="ow-field">
   <label class="ow-lbl">كلمة المرور</label>
   <input name="password" type="password" class="ow-inp" placeholder="اكتب كلمة المرور" required>
  </div>
  <label class="ow-remember"><input type="checkbox" id="owRemember"> تذكّرني</label>
  <div class="ow-adv" id="owAdvToggle"><i class="bi bi-chevron-down" id="owAdvChev"></i> خيارات متقدمة</div>
  <div class="ow-manual" id="owManual">
   <label class="ow-manual-lbl"><input type="checkbox" id="owManualChk"> دعني أعدّ حسابي يدوياً</label>
  </div>
  <div class="ow-foot">
   <button class="ow-btn" type="submit">اتصال</button>
  </div>
 </form>
</div>
 </main>
</div>

<!-- شاشة الإعداد المتقدم (زي Outlook) -->
<div class="ow-advscreen" id="owAdvScreen">
 <div class="ow-card ow-adv-card">
  <button type="button" class="ow-close" id="owAdvClose" title="إغلاق"><i class="bi bi-x-lg"></i></button>
  <div class="ow-adv-brand"><img src="https://solutionstech.sa/storage/logo/22-removebg-preview.png" alt="Solutions Tech" style="height:34px;width:auto"><span class="ow-adv-name">Solutions Tech</span></div>
  <h5 class="ow-adv-title">الإعداد المتقدم</h5>
  <div class="ow-prov">
   <div class="ow-prov-tile" data-p="microsoft"><span class="pi" style="color:#d83b01"><i class="bi bi-microsoft"></i></span><span>Microsoft 365</span></div>
   <div class="ow-prov-tile" data-p="outlook"><span class="pi" style="color:#14176C"><i class="bi bi-envelope-fill"></i></span><span>Outlook.com</span></div>
   <div class="ow-prov-tile" data-p="exchange"><span class="pi" style="color:#14176C"><i class="bi bi-diagram-3-fill"></i></span><span>Exchange</span></div>
   <div class="ow-prov-tile" data-p="google"><span class="pi" style="color:#ea4335"><i class="bi bi-google"></i></span><span>Google</span></div>
   <div class="ow-prov-tile" data-p="pop"><span class="pi" style="color:#e0a336"><i class="bi bi-envelope"></i></span><span>POP</span></div>
   <div class="ow-prov-tile" data-p="imap"><span class="pi" style="color:#e0a336"><i class="bi bi-envelope-open"></i></span><span>IMAP</span></div>
   <div class="ow-prov-tile" data-p="exchange2013"><span class="pi" style="color:#14176C"><i class="bi bi-diagram-3"></i></span><span>Exchange 2013<br>أو أقدم</span></div>
  </div>
  <a href="#" class="ow-goback" id="owGoBack">رجوع</a>
 </div>
</div>
<div class="ow-legal">
 <a href="#">شروط الاستخدام</a>
 <a href="#">الخصوصية وملفات تعريف الارتباط</a>
 <a href="#" class="dots">•••</a>
</div>
<script>
// ساعة وتاريخ حيّ بتوقيت السعودية
(function(){
 var el=document.getElementById('lgClock'); if(!el) return;
 var days=['الأحد','الإثنين','الثلاثاء','الأربعاء','الخميس','الجمعة','السبت'];
 function pad(n){return (n<10?'0':'')+n;}
 function tick(){
  try{
   var now=new Date(new Date().toLocaleString('en-US',{timeZone:'Asia/Riyadh'}));
   var h=now.getHours(), m=now.getMinutes(), ampm=h<12?'ص':'م', h12=h%12||12;
   el.textContent = days[now.getDay()]+' '+pad(now.getDate())+'/'+pad(now.getMonth()+1)+'/'
     +now.getFullYear()+' · '+h12+':'+pad(m)+' '+ampm;
  }catch(e){}
 }
 tick(); setInterval(tick, 30000);
})();
(function(){
 var u=document.querySelector('input[name=username]');
 var r=document.getElementById('owRemember');
 var f=document.querySelector('form.ow-body');
 try{
  var saved=localStorage.getItem('emSavedUser');
  if(saved){ u.value=saved; r.checked=true;
   var p=document.querySelector('input[name=password]'); if(p) p.focus(); }
 }catch(e){}
 f.addEventListener('submit', function(){
  try{
   if(r.checked && u.value.trim()) localStorage.setItem('emSavedUser', u.value.trim());
   else localStorage.removeItem('emSavedUser');
  }catch(e){}
 });
 // خيارات متقدمة: فتح/غلق القسم اليدوي
 var adv=document.getElementById('owAdvToggle');
 var man=document.getElementById('owManual');
 var chev=document.getElementById('owAdvChev');
 var manChk=document.getElementById('owManualChk');
 adv.addEventListener('click', function(){
  var open=man.classList.toggle('open');
  chev.classList.toggle('up', open);
 });
 // شاشة الإعداد المتقدم
 var scr=document.getElementById('owAdvScreen');
 function showScr(){ scr.classList.add('show'); }
 function hideScr(){ scr.classList.remove('show'); }
 f.addEventListener('submit', function(e){
  // لو اختار "إعداد يدوي" اعرض شاشة الإعداد المتقدم بدل الدخول المباشر
  if(manChk && manChk.checked){ e.preventDefault(); showScr(); }
 });
 document.getElementById('owGoBack').addEventListener('click', function(e){ e.preventDefault(); hideScr(); });
 document.getElementById('owAdvClose').addEventListener('click', hideScr);
 // اختيار أي مزوّد = المتابعة بتسجيل الدخول العادي
 document.querySelectorAll('.ow-prov-tile').forEach(function(t){
  t.addEventListener('click', function(){ hideScr(); if(manChk) manChk.checked=false; f.submit(); });
 });
})();
</script>
</body></html>
"""

USERS_TPL = """
{% extends "base.html" %}{% block content %}
<h2>المستخدمون (لوج إن)</h2>
<button class="btn btn-primary mb-3" data-bs-toggle="modal" data-bs-target="#add">
 <i class="bi bi-plus-circle"></i> مستخدم جديد</button>
<table class="table table-striped align-middle">
 <thead><tr><th>اسم المستخدم</th><th>الاسم</th><th>الدور</th><th>الموظف المرتبط</th><th>نشط</th><th>إجراءات</th></tr></thead>
 <tbody>
 {% for u in rows %}
 <tr>
  <td>{{ u.username }}</td><td>{{ u.full_name }}</td>
  <td><span class="badge bg-{{ 'danger' if u.role=='admin' else 'secondary' }}">
      {{ 'مدير' if u.role=='admin' else 'موظف' }}</span></td>
  <td>{{ u.emp_email or '—' }}</td>
  <td>{{ '✔' if u.active else '✖' }}</td>
  <td class="text-nowrap">
   <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#rp{{ u.id }}">كلمة مرور</button>
   <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('user_toggle', uid=u.id) }}">{{ 'إيقاف' if u.active else 'تفعيل' }}</a>
   {% if u.id != user.id %}
   <a class="btn btn-sm btn-danger" href="{{ url_for('user_delete', uid=u.id) }}"
      onclick="return confirm('حذف المستخدم؟')"><i class="bi bi-trash"></i></a>
   {% endif %}
  </td>
 </tr>
 <div class="modal fade" id="rp{{ u.id }}" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
  <form method="POST" action="{{ url_for('user_reset', uid=u.id) }}">
   <div class="modal-header"><h5 class="modal-title">كلمة مرور جديدة لـ {{ u.username }}</h5>
    <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
   <div class="modal-body"><input name="password" type="text" class="form-control" required></div>
   <div class="modal-footer"><button class="btn btn-primary">حفظ</button></div>
  </form>
 </div></div></div>
 {% else %}<tr><td colspan="6" class="text-muted">لا يوجد</td></tr>{% endfor %}
 </tbody>
</table>

<div class="modal fade" id="add" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
 <form method="POST" action="{{ url_for('user_add') }}">
  <div class="modal-header"><h5 class="modal-title">مستخدم جديد</h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
   <div class="mb-2"><label>اسم المستخدم</label><input name="username" class="form-control" required></div>
   <div class="mb-2"><label>الاسم الكامل</label><input name="full_name" class="form-control"></div>
   <div class="mb-2"><label>كلمة المرور</label><input name="password" type="text" class="form-control" required></div>
   <div class="mb-2"><label>الدور</label>
    <select name="role" class="form-select" onchange="document.getElementById('empsel').style.display=this.value=='employee'?'block':'none'">
     <option value="admin">مدير (وصول كامل)</option>
     <option value="employee">موظف (صندوقه فقط)</option>
    </select></div>
   <div class="mb-2" id="empsel" style="display:none"><label>الموظف المرتبط</label>
    <select name="employee_id" class="form-select">
     <option value="">— بدون —</option>
     {% for e in employees %}<option value="{{ e.id }}">{{ e.name }} — {{ e.email }}</option>{% endfor %}
    </select></div>
  </div>
  <div class="modal-footer"><button class="btn btn-primary">حفظ</button></div>
 </form>
</div></div></div>
{% endblock %}
"""

MAIL_TPL = """
{% extends "base.html" %}{% block content %}
{% set bare = '1' if request.args.get('bare') == '1' else none %}
<div class="rbn-tabs">
 <span class="rbn-tab rbn-tab-file">ملف</span>
 <span class="rbn-tab active" onclick="rbTab('home',this)">الصفحة الرئيسية</span>
 <span class="rbn-tab" onclick="rbTab('sr',this)">إرسال/استلام</span>
 <span class="rbn-tab" onclick="rbTab('folder',this)">مجلد</span>
 <span class="rbn-tab" onclick="rbTab('view',this)">عرض</span>
 <span class="rbn-tab" onclick="rbTab('help',this)">تعليمات</span>
 <span class="rbn-tell"><i class="bi bi-lightbulb"></i> أخبرني بما تريد فعله…</span>
</div>
<div class="rbn" id="rbn-home">
 <!-- جديد -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big rbn-new" href="{{ url_for('mail_compose', kind=kind, oid=oid, bare=bare, f=folder) }}">
    <i class="bi bi-envelope-plus-fill" style="color:#2b579a"></i><span>بريد جديد</span></a>
   <a class="rbn-big" href="{{ url_for('mail_compose', kind=kind, oid=oid, bare=bare, f=folder) }}">
    <i class="bi bi-window-plus" style="color:#2b579a"></i><span>عناصر جديدة</span></a>
  </div>
  <div class="rbn-lbl">جديد</div>
 </div>
 <!-- حذف -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <div class="rbn-col">
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-x-octagon" style="color:#c0392b"></i> تجاهل</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-stars" style="color:#2b579a"></i> تنظيف</button>
    <button type="button" class="rbn-s" onclick="rbMove('Junk Email')"><i class="bi bi-slash-circle" style="color:#c0392b"></i> عشوائي</button>
   </div>
   <a class="rbn-big" href="#" onclick="rbAct('delete');return false"><i class="bi bi-x-lg" style="color:#c0392b"></i><span>حذف</span></a>
   <a class="rbn-big" href="#" onclick="rbMove('Archive');return false"><i class="bi bi-archive-fill" style="color:#5b8a5b"></i><span>أرشفة</span></a>
  </div>
  <div class="rbn-lbl">حذف</div>
 </div>
 <!-- استجابة -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbCompose('reply');return false"><i class="bi bi-reply-fill" style="color:#2b579a"></i><span>رد</span></a>
   <a class="rbn-big" href="#" onclick="rbCompose('replyall');return false"><i class="bi bi-reply-all-fill" style="color:#2b579a"></i><span>رد على الكل</span></a>
   <a class="rbn-big" href="#" onclick="rbCompose('forward');return false"><i class="bi bi-arrow-right-square-fill" style="color:#2b579a"></i><span>إعادة توجيه</span></a>
  </div>
  <div class="rbn-lbl">استجابة</div>
 </div>
 <!-- خطوات سريعة -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <div class="rbn-grid">
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-arrow-right-circle" style="color:#2b579a"></i> نقل إلى: ؟</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-people" style="color:#2b579a"></i> إلى المدير</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-envelope-at" style="color:#2b579a"></i> بريد الفريق</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-check2-circle" style="color:#5b8a5b"></i> تم</button>
    <button type="button" class="rbn-s" onclick="rbCompose('reply')"><i class="bi bi-reply" style="color:#2b579a"></i> رد وحذف</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-plus-square" style="color:#8a8886"></i> إنشاء جديد</button>
   </div>
  </div>
  <div class="rbn-lbl">خطوات سريعة</div>
 </div>
 <!-- نقل -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <div class="rbn-col">
    <div class="dropdown">
     <button type="button" class="rbn-s dropdown-toggle" data-bs-toggle="dropdown"><i class="bi bi-folder-symlink" style="color:#2b579a"></i> نقل</button>
     <ul class="dropdown-menu">
      {% for f in folders %}{% if f.name != folder %}
      <li><a class="dropdown-item" href="#" onclick="rbMove('{{ f.name }}');return false">{{ f.label }}</a></li>
      {% endif %}{% endfor %}
     </ul>
    </div>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-diagram-2" style="color:#2b579a"></i> قواعد</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-journal-text" style="color:#7a3b8a"></i> OneNote</button>
   </div>
  </div>
  <div class="rbn-lbl">نقل</div>
 </div>
 <!-- علامات -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbAct('unread');return false"><i class="bi bi-envelope-open" style="color:#2b579a"></i><span>مقروء/غير</span></a>
   <div class="rbn-col">
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-shield-check" style="color:#e0a800"></i> سياسة</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-tag-fill" style="color:#d63384"></i> تصنيف</button>
    <button type="button" class="rbn-s" onclick="rbAct('flag')"><i class="bi bi-flag-fill" style="color:#c0392b"></i> متابعة</button>
   </div>
  </div>
  <div class="rbn-lbl">علامات</div>
 </div>
 <!-- مجموعات -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <div class="rbn-col">
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-people-fill" style="color:#2b579a"></i> مجموعة جديدة</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-search" style="color:#2b579a"></i> استعراض المجموعات</button>
   </div>
  </div>
  <div class="rbn-lbl">مجموعات</div>
 </div>
 <!-- بحث -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <div class="rbn-col">
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-person-lines-fill" style="color:#2b579a"></i> دفتر العناوين</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-funnel" style="color:#8a8886"></i> تصفية البريد</button>
   </div>
  </div>
  <div class="rbn-lbl">بحث</div>
 </div>
 <!-- عام -->
 <div class="rbn-grp ms-auto">
  <div class="rbn-top">
   <a class="rbn-big" href="{{ url_for('mail_view', kind=kind, oid=oid, bare=bare, f=folder, q=q, unseen=unseen, refresh=1) }}">
    <i class="bi bi-arrow-clockwise" style="color:#2b579a"></i><span>تحديث</span></a>
  </div>
  <div class="rbn-lbl">عام</div>
 </div>
</div>
<!-- شريط إرسال/استلام -->
<div class="rbn" id="rbn-sr" style="display:none">
 <!-- إرسال واستلام -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big rbn-new" href="{{ url_for('mail_view', kind=kind, oid=oid, bare=bare, f=folder, q=q, unseen=unseen, refresh=1) }}">
    <i class="bi bi-arrow-repeat" style="color:#2b579a"></i><span>إرسال/استلام كل المجلدات</span></a>
   <div class="rbn-col">
    <a class="rbn-s" href="{{ url_for('mail_view', kind=kind, oid=oid, bare=bare, f=folder, q=q, unseen=unseen, refresh=1) }}"><i class="bi bi-folder-symlink" style="color:#2b579a"></i> تحديث المجلد</a>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-send" style="color:#2b579a"></i> إرسال الكل</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-envelope-paper" style="color:#2b579a"></i> مجموعات الإرسال/الاستلام</button>
   </div>
  </div>
  <div class="rbn-lbl">إرسال واستلام</div>
 </div>
 <!-- تنزيل -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-bar-chart-line" style="color:#2b579a"></i><span>إظهار التقدّم</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-x-circle" style="color:#c0392b"></i><span>إلغاء الكل</span></a>
  </div>
  <div class="rbn-lbl">تنزيل</div>
 </div>
 <!-- الخادم -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-download" style="color:#2b579a"></i><span>تنزيل العناوين</span></a>
   <div class="rbn-col">
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-check2-square" style="color:#2b579a"></i> تحديد للتنزيل</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-x-square" style="color:#c0392b"></i> إلغاء تحديد التنزيل</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-check2-circle" style="color:#5b8a5b"></i> معالجة العناوين المحددة</button>
   </div>
  </div>
  <div class="rbn-lbl">الخادم</div>
 </div>
 <!-- التفضيلات -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-gear-wide-connected" style="color:#2b579a"></i><span>تفضيلات التنزيل</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-globe" style="color:#c0392b"></i><span>العمل دون اتصال</span></a>
  </div>
  <div class="rbn-lbl">التفضيلات</div>
 </div>
</div>
<!-- شريط المجلد -->
<div class="rbn" id="rbn-folder" style="display:none">
 <!-- جديد -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-folder-plus" style="color:#2b579a"></i><span>مجلد جديد</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-folder-symlink" style="color:#2b579a"></i><span>مجلد بحث جديد</span></a>
  </div>
  <div class="rbn-lbl">جديد</div>
 </div>
 <!-- إجراءات -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <div class="rbn-col">
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-input-cursor-text" style="color:#2b579a"></i> إعادة تسمية المجلد</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-files" style="color:#2b579a"></i> نسخ المجلد</button>
   </div>
   <div class="rbn-col">
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-folder-symlink" style="color:#8a8886"></i> نقل المجلد</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-folder-x" style="color:#c0392b"></i> حذف المجلد</button>
   </div>
  </div>
  <div class="rbn-lbl">إجراءات</div>
 </div>
 <!-- تنظيف -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-envelope-open" style="color:#2b579a"></i><span>تحديد الكل كمقروء</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-play-circle" style="color:#2b579a"></i><span>تشغيل القواعد الآن</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-sort-alpha-down" style="color:#2b579a"></i><span>ترتيب المجلدات أ-ي</span></a>
   <div class="rbn-col">
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-stars" style="color:#2b579a"></i> تنظيف المجلد</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-trash" style="color:#c0392b"></i> حذف الكل</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-arrow-counterclockwise" style="color:#5b8a5b"></i> استرداد العناصر المحذوفة</button>
   </div>
  </div>
  <div class="rbn-lbl">تنظيف</div>
 </div>
 <!-- المفضلة -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-star-fill" style="color:#e0a800"></i><span>إضافة إلى المفضلة</span></a>
  </div>
  <div class="rbn-lbl">المفضلة</div>
 </div>
 <!-- عرض عبر الإنترنت -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-cloud" style="color:#2b579a"></i><span>عرض على الخادم</span></a>
  </div>
  <div class="rbn-lbl">عرض عبر الإنترنت</div>
 </div>
 <!-- خصائص -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-clock-history" style="color:#2b579a"></i><span>نهج</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-archive" style="color:#2b579a"></i><span>الأرشفة التلقائية</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-people-fill" style="color:#2b579a"></i><span>أذونات المجلد</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-card-list" style="color:#2b579a"></i><span>خصائص المجلد</span></a>
  </div>
  <div class="rbn-lbl">خصائص</div>
 </div>
</div>
<!-- شريط العرض -->
<div class="rbn" id="rbn-view" style="display:none">
 <!-- العرض الحالي -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-arrow-repeat" style="color:#2b579a"></i><span>تغيير العرض</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-gear" style="color:#2b579a"></i><span>إعدادات العرض</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-arrow-counterclockwise" style="color:#2b579a"></i><span>إعادة تعيين العرض</span></a>
  </div>
  <div class="rbn-lbl">العرض الحالي</div>
 </div>
 <!-- الرسائل -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <div class="rbn-col">
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-chat-square-text" style="color:#2b579a"></i> إظهار كمحادثات</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-sliders" style="color:#8a8886"></i> إعدادات المحادثة</button>
   </div>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-text-paragraph" style="color:#2b579a"></i><span>معاينة الرسالة</span></a>
  </div>
  <div class="rbn-lbl">الرسائل</div>
 </div>
 <!-- علبة الوارد المركّزة -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-inbox-fill" style="color:#2b579a"></i><span>إظهار الوارد المركّز</span></a>
  </div>
  <div class="rbn-lbl">علبة الوارد المركّزة</div>
 </div>
 <!-- الترتيب -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <div class="rbn-grid">
    <button type="button" class="rbn-s" onclick="olSort('date',null,'التاريخ')"><i class="bi bi-calendar3" style="color:#2b579a"></i> التاريخ</button>
    <button type="button" class="rbn-s" onclick="olSort('from',null,'المرسِل')"><i class="bi bi-person" style="color:#2b579a"></i> من</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-person-check" style="color:#2b579a"></i> إلى</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-tag" style="color:#d63384"></i> الفئات</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-flag" style="color:#c0392b"></i> حالة العلامة</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-columns" style="color:#8a8886"></i> إضافة أعمدة</button>
   </div>
   <div class="rbn-col">
    <button type="button" class="rbn-s" onclick="olSort(null,'asc','')"><i class="bi bi-arrow-down-up" style="color:#2b579a"></i> عكس الترتيب</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-arrows-expand" style="color:#2b579a"></i> توسيع/طي</button>
   </div>
  </div>
  <div class="rbn-lbl">الترتيب</div>
 </div>
 <!-- التخطيط -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-distribute-vertical" style="color:#2b579a"></i><span>مسافات أضيق</span></a>
   <div class="rbn-col">
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-layout-sidebar" style="color:#2b579a"></i> جزء المجلدات</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-layout-text-window-reverse" style="color:#2b579a"></i> جزء القراءة</button>
    <button type="button" class="rbn-s" onclick="rbNo()"><i class="bi bi-list-check" style="color:#2b579a"></i> شريط المهام</button>
   </div>
  </div>
  <div class="rbn-lbl">التخطيط</div>
 </div>
 <!-- النافذة -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-bell" style="color:#2b579a"></i><span>نافذة التذكيرات</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-window-plus" style="color:#2b579a"></i><span>فتح في نافذة جديدة</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-x-square" style="color:#c0392b"></i><span>إغلاق كل العناصر</span></a>
  </div>
  <div class="rbn-lbl">النافذة</div>
 </div>
 <!-- القارئ الغامر -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-book" style="color:#2b579a"></i><span>القارئ الغامر</span></a>
  </div>
  <div class="rbn-lbl">القارئ الغامر</div>
 </div>
</div>
<!-- شريط التعليمات -->
<div class="rbn" id="rbn-help" style="display:none">
 <!-- تعليمات -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-question-circle-fill" style="color:#2b579a"></i><span>تعليمات</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-headset" style="color:#2b579a"></i><span>الاتصال بالدعم</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-lightbulb" style="color:#e0a800"></i><span>اقتراح ميزة</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-mortarboard-fill" style="color:#2b579a"></i><span>عرض التدريب</span></a>
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-tools" style="color:#2b579a"></i><span>أداة الدعم</span></a>
  </div>
  <div class="rbn-lbl">تعليمات</div>
 </div>
 <!-- أدوات -->
 <div class="rbn-grp">
  <div class="rbn-top">
   <a class="rbn-big" href="#" onclick="rbNo();return false"><i class="bi bi-briefcase-fill" style="color:#2b579a"></i><span>الحصول على التشخيص</span></a>
  </div>
  <div class="rbn-lbl">أدوات</div>
 </div>
</div>
<form id="rbform" method="POST" action="{{ url_for('mail_action', kind=kind, oid=oid) }}" style="display:none">
 <input type="hidden" name="f" value="{{ folder }}">
 <input type="hidden" name="uid" id="rbuid">
 <input type="hidden" name="act" id="rbactval">
 <input type="hidden" name="dest" id="rbdest">
 <input type="hidden" name="back" value="{{ request.full_path }}">
</form>

{% if (switch_accounts or switch_employees) and not bare %}
<div class="mbox-switch">
 {% if switch_accounts %}<span class="lbl">الحسابات:</span>{% endif %}
 {% for a in switch_accounts %}
 <a class="chip {{ 'on' if kind=='account' and a.id==oid }}"
    href="{{ url_for('mail_view', kind='account', oid=a.id) }}">
  <i class="bi bi-send-fill"></i> {{ a.display_name or a.email }}</a>
 {% endfor %}
 {% if switch_employees %}<span class="lbl ms-2">صناديق الموظفين:</span>{% endif %}
 {% for e in switch_employees %}
 <a class="chip {{ 'on' if kind=='employee' and e.id==oid }}"
    href="{{ url_for('mail_view', kind='employee', oid=e.id) }}">
  <i class="bi bi-person-fill"></i> {{ e.name }}</a>
 {% endfor %}
</div>
{% endif %}

{% if error %}<div class="alert alert-danger"><i class="bi bi-plug"></i> {{ error }}</div>{% endif %}

<div class="olx">
 <aside class="olx-fold">
  <div class="mbx"><i class="bi bi-person-circle"></i> {{ meta.email }}</div>
  {% for f in folders %}
  <a class="{{ 'on' if f.name==folder }}"
     href="{{ url_for('mail_view', kind=kind, oid=oid, bare=bare, f=f.name) }}">
   <i class="bi {{ f.icon }}"></i>
   <span class="text-truncate">{{ f.label }}</span>
   {% if f.unseen %}<span class="cnt">{{ f.unseen }}</span>{% endif %}
  </a>
  {% else %}
  <div class="text-muted small p-2">لا توجد مجلدات</div>
  {% endfor %}
 </aside>

 <section class="olx-list">
  <div class="olx-ltop">
   <div class="d-flex align-items-center gap-2">
    <span class="olx-ltitle">{{ folder_label or 'البريد الوارد' }}</span>
    <div class="dropdown ms-auto">
     <button class="btn btn-sm btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown">
      <i class="bi bi-sort-down"></i> <span id="sortLbl">التاريخ</span></button>
     <ul class="dropdown-menu dropdown-menu-end">
      <li><h6 class="dropdown-header">ترتيب حسب</h6></li>
      <li><a class="dropdown-item" href="#" onclick="olSort('date',null,'التاريخ');return false">التاريخ</a></li>
      <li><a class="dropdown-item" href="#" onclick="olSort('from',null,'المرسِل');return false">المرسِل</a></li>
      <li><a class="dropdown-item" href="#" onclick="olSort('subj',null,'الموضوع');return false">الموضوع</a></li>
      <li><a class="dropdown-item" href="#" onclick="olSort('seen',null,'المقروء');return false">مقروء/غير مقروء</a></li>
      <li><hr class="dropdown-divider"></li>
      <li><h6 class="dropdown-header">الاتجاه</h6></li>
      <li><a class="dropdown-item" href="#" onclick="olSort(null,'desc','');return false">الأحدث أولاً</a></li>
      <li><a class="dropdown-item" href="#" onclick="olSort(null,'asc','');return false">الأقدم أولاً</a></li>
     </ul>
    </div>
    <span class="text-muted small">{{ page.total }} رسالة</span>
   </div>
   <form class="d-flex gap-1" method="GET" action="{{ url_for('mail_view', kind=kind, oid=oid, bare=bare) }}">
    <input type="hidden" name="f" value="{{ folder }}">
    <input class="form-control form-control-sm" name="q" value="{{ q }}" placeholder="بحث">
    <button class="btn btn-sm btn-outline-primary"><i class="bi bi-search"></i></button>
    <a class="btn btn-sm {{ 'btn-primary' if unseen else 'btn-outline-secondary' }}"
       href="{{ url_for('mail_view', kind=kind, oid=oid, bare=bare, f=folder, q=q, unseen=0 if unseen else 1) }}"
       title="غير المقروء فقط"><i class="bi bi-envelope"></i></a>
   </form>
   <div class="d-flex gap-1">
    <a class="btn btn-sm btn-outline-secondary"
       href="{{ url_for('mail_view', kind=kind, oid=oid, bare=bare, f=folder, q=q, unseen=unseen, refresh=1) }}">
     <i class="bi bi-arrow-clockwise"></i></a>
   </div>
  </div>
  <div class="olx-scroll">
   {% set ns = namespace(grp='') %}
   {% for m in page['items'] %}
    {% set g = m.date|dategroup %}
    {% if g != ns.grp %}<div class="olx-grp">{{ g }}</div>{% set ns.grp = g %}{% endif %}
    <a class="olx-item {{ '' if m.seen else 'unseen' }}" data-uid="{{ m.uid }}"
       data-date="{{ m.date }}" data-seen="{{ 1 if m.seen else 0 }}"
       data-from="{{ ((m.to_name or m.to_email) if folder_kind in ('sent','drafts') else (m.from_name or m.from_email))|lower }}"
       data-subj="{{ (m.subject or '')|lower }}"
       href="{{ url_for('mail_message_view', kind=kind, oid=oid, uid=m.uid, f=folder) }}"
       onclick="return olOpen(this, {{ m.uid }})">
     <div class="r1">
      <span class="who">
       {%- if folder_kind in ('sent','drafts') -%}{{ m.to_name or m.to_email or '—' }}
       {%- else -%}{{ m.from_name or m.from_email or '—' }}{%- endif -%}
      </span>
      {% if m.attach %}<i class="bi bi-paperclip text-muted small"></i>{% endif %}
      {% if m.flagged %}<i class="bi bi-flag-fill text-danger small"></i>{% endif %}
      <span class="dt">{{ m.date|mdate }}</span>
      <span class="olx-quick">
       <i class="bi bi-reply-fill" title="رد" onclick="return olQuick(event,{{ m.uid }},'reply')"></i>
       <i class="bi bi-x-lg xdel" title="حذف" onclick="return olQuick(event,{{ m.uid }},'delete')"></i>
      </span>
     </div>
     <div class="sub">{{ m.subject }}{% if m.answered %} <i class="bi bi-reply small"></i>{% endif %}</div>
    </a>
   {% else %}
    <div class="olx-empty"><i class="bi bi-inbox" style="font-size:2rem"></i>
     {% if q %}لا توجد نتائج{% else %}لا توجد رسائل{% endif %}</div>
   {% endfor %}
  </div>
  {% if page.pages > 1 %}
  <div class="d-flex align-items-center gap-2 p-2 border-top">
   <a class="btn btn-sm btn-outline-secondary {{ 'disabled' if page.page<=1 }}"
      href="{{ url_for('mail_view', kind=kind, oid=oid, bare=bare, f=folder, q=q, unseen=unseen, p=page.page-1) }}">أحدث</a>
   <span class="text-muted small">{{ page.page }}/{{ page.pages }}</span>
   <a class="btn btn-sm btn-outline-secondary {{ 'disabled' if page.page>=page.pages }}"
      href="{{ url_for('mail_view', kind=kind, oid=oid, bare=bare, f=folder, q=q, unseen=unseen, p=page.page+1) }}">أقدم</a>
  </div>
  {% endif %}
 </section>

 <section class="olx-read" id="readpane">
  <div class="olx-empty"><i class="bi bi-envelope-open" style="font-size:2.6rem"></i>
   اختر رسالة لعرضها</div>
 </section>
</div>
{% set curf = (folders|selectattr('name','equalto',folder)|first) if folders else none %}
<div class="olx-status">
 <div class="olx-nav">
  <a href="{{ url_for('mail_view', kind=kind, oid=oid, bare=bare, f='INBOX') }}" title="البريد"><i class="bi bi-envelope"></i></a>
  <span title="التقويم"><i class="bi bi-calendar3"></i></span>
  <span title="جهات الاتصال"><i class="bi bi-people"></i></span>
  <span title="المهام"><i class="bi bi-check2-square"></i></span>
  <span title="المزيد"><i class="bi bi-three-dots"></i></span>
 </div>
 <div class="olx-stat-info">
  <span>العناصر: {{ page.total }}</span>
  <span class="sep">|</span>
  <span>غير المقروء: {{ curf.unseen if curf else 0 }}</span>
  <span class="sep">|</span>
  <span>الإصدار v{{ app_version }}</span>
 </div>
 <div class="olx-stat-right">
  <span><i class="bi bi-check-circle-fill"></i> كل المجلدات محدّثة</span>
  <span class="sep">|</span>
  <span><i class="bi bi-hdd-network"></i> متصل بـ: الخادم الداخلي</span>
  <span class="olx-viewicons">
   <i class="bi bi-list-ul" title="عرض عادي"></i>
   <i class="bi bi-layout-sidebar-reverse" title="عرض القراءة"></i>
  </span>
  <span class="sep">|</span>
  <span class="olx-zoom">
   <i class="bi bi-dash-lg" title="تصغير" onclick="olZoom(-10)"></i>
   <span id="zoomVal">100%</span>
   <i class="bi bi-plus-lg" title="تكبير" onclick="olZoom(10)"></i>
  </span>
 </div>
</div>
<script>
var _msgBase = "{{ url_for('mail_message_view', kind=kind, oid=oid, uid=0, f=folder, bare=bare) }}";
var _composeBase = "{{ url_for('mail_compose', kind=kind, oid=oid, bare=bare, f=folder) }}";
var _curUid = null;
function olOpen(el, uid){
 document.querySelectorAll('.olx-item').forEach(function(i){i.classList.remove('sel')});
 el.classList.add('sel'); el.classList.remove('unseen');
 _curUid = uid;
 var url = _msgBase.replace(/\\/m\\/0/, '/m/'+uid) + '&frag=1';
 var pane = document.getElementById('readpane');
 pane.innerHTML = '<div class="olx-empty">جارٍ التحميل…</div>';
 fetch(url).then(function(r){return r.text()}).then(function(h){pane.innerHTML=h;})
  .catch(function(){pane.innerHTML='<div class="olx-empty">تعذّر فتح الرسالة</div>'});
 return false;
}
function olQuick(ev, uid, act){
 ev.preventDefault(); ev.stopPropagation();
 _curUid = uid;
 if(act==='reply') rbCompose('reply');
 else rbAct(act);
 return false;
}
function rbCompose(mode){
 if(!_curUid){ alert('اختر رسالة أولاً'); return; }
 var sep = _composeBase.indexOf('?')===-1 ? '?' : '&';
 window.location = _composeBase + sep + 'uid='+_curUid+'&mode='+mode;
}
function rbAct(act){
 if(!_curUid){ alert('اختر رسالة أولاً'); return; }
 if(act==='delete' && !confirm('حذف الرسالة؟')) return;
 document.getElementById('rbuid').value = _curUid;
 document.getElementById('rbactval').value = act;
 document.getElementById('rbdest').value = '';
 document.getElementById('rbform').submit();
}
function rbMove(dest){
 if(!_curUid){ alert('اختر رسالة أولاً'); return; }
 document.getElementById('rbuid').value = _curUid;
 document.getElementById('rbactval').value = 'move';
 document.getElementById('rbdest').value = dest;
 document.getElementById('rbform').submit();
}
function rbNo(){ /* أزرار عرض فقط (زي أوتلوك) بدون وظيفة في البرنامج */ }
var _zoom=100;
function olZoom(delta){
 _zoom=Math.max(50, Math.min(200, _zoom+delta));
 var pane=document.getElementById('readpane');
 if(pane) pane.style.zoom=(_zoom/100);
 var v=document.getElementById('zoomVal'); if(v) v.textContent=_zoom+'%';
 try{ localStorage.setItem('mailZoom', _zoom); }catch(e){}
}
try{ var _z=localStorage.getItem('mailZoom'); if(_z){ _zoom=parseInt(_z)||100;
 document.addEventListener('DOMContentLoaded',function(){ var p=document.getElementById('readpane'); if(p)p.style.zoom=(_zoom/100); var v=document.getElementById('zoomVal'); if(v)v.textContent=_zoom+'%'; }); } }catch(e){}
function rbTab(which, el){
 var map={home:'rbn-home', sr:'rbn-sr', folder:'rbn-folder', view:'rbn-view', help:'rbn-help'};
 for(var k in map){ var d=document.getElementById(map[k]); if(d) d.style.display=(k===which?'':'none'); }
 document.querySelectorAll('.rbn-tab').forEach(function(t){ t.classList.remove('active'); });
 if(el) el.classList.add('active');
}
var _sortBy='date', _sortOrder='desc';
function olSort(by, order, lbl){
 if(by) _sortBy=by;
 if(order) _sortOrder=order;
 if(lbl){ var l=document.getElementById('sortLbl'); if(l) l.textContent=lbl; }
 var scroll=document.querySelector('.olx-scroll'); if(!scroll) return;
 // اخفِ عناوين المجموعات عند الترتيب المخصّص
 scroll.querySelectorAll('.olx-grp').forEach(function(g){ g.style.display=(_sortBy==='date'?'':'none'); });
 var items=[].slice.call(scroll.querySelectorAll('.olx-item'));
 items.sort(function(a,b){
  var r=0;
  if(_sortBy==='date'){ r=(a.dataset.date||'').localeCompare(b.dataset.date||''); }
  else if(_sortBy==='from'){ r=(a.dataset.from||'').localeCompare(b.dataset.from||''); }
  else if(_sortBy==='subj'){ r=(a.dataset.subj||'').localeCompare(b.dataset.subj||''); }
  else if(_sortBy==='seen'){ r=(a.dataset.seen||'')-(b.dataset.seen||''); }
  return _sortOrder==='asc'? r : -r;
 });
 items.forEach(function(it){ scroll.appendChild(it); });
}
document.addEventListener('DOMContentLoaded', function(){
 var first = document.querySelector('.olx-item');
 if(first) olOpen(first, first.dataset.uid);
});
</script>
{% endblock %}
"""

MAIL_MSG_TPL = """
{% extends "base.html" %}{% block content %}
<div class="ol">
 <aside class="ol-folders">
  <div class="ol-mbox"><div class="nm">{{ meta.title }}</div><div class="em">{{ meta.email }}</div></div>
  <nav class="ol-flist">
   {% for f in folders %}
   <a class="{{ 'on' if f.name==folder }}" href="{{ url_for('mail_view', kind=kind, oid=oid, f=f.name) }}">
    <i class="bi {{ f.icon }}"></i><span class="text-truncate">{{ f.label }}</span>
    {% if f.unseen %}<span class="cnt">{{ f.unseen }}</span>{% endif %}</a>
   {% endfor %}
  </nav>
 </aside>

 <section class="ol-main">
  <div class="ol-bar">
   <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('mail_view', kind=kind, oid=oid, f=folder) }}">
    <i class="bi bi-arrow-right"></i> رجوع</a>
   <a class="btn btn-sm btn-primary"
      href="{{ url_for('mail_compose', kind=kind, oid=oid, f=folder, uid=m.uid, mode='reply') }}">
    <i class="bi bi-reply-fill"></i> رد</a>
   <a class="btn btn-sm btn-outline-primary"
      href="{{ url_for('mail_compose', kind=kind, oid=oid, f=folder, uid=m.uid, mode='replyall') }}">
    <i class="bi bi-reply-all-fill"></i> رد على الكل</a>
   <a class="btn btn-sm btn-outline-primary"
      href="{{ url_for('mail_compose', kind=kind, oid=oid, f=folder, uid=m.uid, mode='forward') }}">
    <i class="bi bi-arrow-right-square"></i> إعادة توجيه</a>
   <form method="POST" action="{{ url_for('mail_action', kind=kind, oid=oid) }}" class="d-flex gap-2">
    <input type="hidden" name="f" value="{{ folder }}">
    <input type="hidden" name="uid" value="{{ m.uid }}">
    <input type="hidden" name="back" value="{{ url_for('mail_view', kind=kind, oid=oid, f=folder) }}">
    <button class="btn btn-sm btn-outline-secondary" name="act" value="unread"
            title="تعليم كغير مقروء"><i class="bi bi-envelope"></i></button>
    <button class="btn btn-sm btn-outline-secondary" name="act" value="{{ 'unflag' if m.flagged else 'flag' }}"
            title="علامة"><i class="bi {{ 'bi-flag-fill text-danger' if m.flagged else 'bi-flag' }}"></i></button>
    <button class="btn btn-sm btn-outline-danger" name="act" value="delete"
            title="حذف"><i class="bi bi-trash"></i></button>
   </form>
  </div>

  <div class="ol-msg">
   <div class="ol-msg-head">
    <h4>{{ m.subject }}</h4>
    <div class="small mb-1"><strong>من:</strong> {{ m.from_name }} &lt;{{ m.from_email }}&gt;</div>
    <div class="small mb-1"><strong>إلى:</strong> {{ m.to or '—' }}</div>
    {% if m.cc %}<div class="small mb-1"><strong>نسخة:</strong> {{ m.cc }}</div>{% endif %}
    <div class="text-muted small">{{ m.date }} · {{ folder }}</div>
   </div>

   {% if m.attachments %}
   <div class="mt-3">
    {% for a in m.attachments %}
    <a class="ol-att" href="{{ url_for('mail_attachment_dl', kind=kind, oid=oid, uid=m.uid, idx=a.idx, f=folder) }}">
     <i class="bi bi-paperclip"></i> {{ a.filename }}
     <span class="text-muted">({{ a.size|filesize }})</span></a>
    {% endfor %}
   </div>
   {% endif %}

   {% if blocked %}
   <div class="alert alert-warning d-flex align-items-center gap-2 mt-3 py-2">
    <i class="bi bi-image"></i> تم حجب الصور الخارجية لحمايتك.
    <a class="btn btn-sm btn-outline-dark ms-auto"
       href="{{ url_for('mail_message_view', kind=kind, oid=oid, uid=m.uid, f=folder, images=1) }}">
     عرض الصور</a>
   </div>
   {% endif %}

   <hr>
   {% if html %}
    <iframe class="ol-frame" sandbox="allow-popups allow-popups-to-escape-sandbox"
            srcdoc="{{ html }}"></iframe>
   {% else %}
    <pre class="msgbody">{{ m.text }}</pre>
   {% endif %}
  </div>
 </section>
</div>
{% endblock %}
"""

# جزء القراءة (fragment) — يُحمَّل داخل واجهة أوتلوك الجديدة عبر AJAX
MAIL_FRAG_TPL = """
{% set fromname = m.from_name or m.from_email %}
<div class="acts">
 <a class="btn btn-sm btn-outline-primary" href="{{ url_for('mail_compose', kind=kind, oid=oid, uid=m.uid, f=folder, mode='reply') }}"><i class="bi bi-reply"></i> رد</a>
 <a class="btn btn-sm btn-outline-primary" href="{{ url_for('mail_compose', kind=kind, oid=oid, uid=m.uid, f=folder, mode='replyall') }}"><i class="bi bi-reply-all"></i> رد على الكل</a>
 <a class="btn btn-sm btn-outline-primary" href="{{ url_for('mail_compose', kind=kind, oid=oid, uid=m.uid, f=folder, mode='forward') }}"><i class="bi bi-forward"></i> إعادة توجيه</a>
 <form method="POST" action="{{ url_for('mail_action', kind=kind, oid=oid) }}" class="d-inline ms-auto">
  <input type="hidden" name="f" value="{{ folder }}"><input type="hidden" name="uid" value="{{ m.uid }}">
  <input type="hidden" name="back" value="{{ url_for('mail_view', kind=kind, oid=oid, f=folder) }}">
  <button class="btn btn-sm btn-outline-danger" name="act" value="delete"><i class="bi bi-trash"></i> حذف</button>
 </form>
</div>
<div class="rdx">
 <div class="subj">{{ m.subject }}</div>
 <div class="hd">
  <div class="av">{{ (fromname[:2]).upper() }}</div>
  <div style="flex:1;min-width:0">
   <div class="frm">{{ fromname }}</div>
   <div class="tos">إلى: {{ m.to or '—' }}{% if m.cc %} · نسخة: {{ m.cc }}{% endif %}</div>
  </div>
  <div class="dtt">{{ m.date|fulldate }}</div>
 </div>
 {% if m.attachments %}
 <div style="padding-top:12px">
  {% for a in m.attachments %}
  <a class="ol-att" href="{{ url_for('mail_attachment_dl', kind=kind, oid=oid, uid=m.uid, idx=a.idx, f=folder) }}">
   <i class="bi bi-paperclip"></i> {{ a.filename }} <span class="text-muted">({{ a.size|filesize }})</span></a>
  {% endfor %}
 </div>
 {% endif %}
 {% if blocked %}
 <div class="alert alert-warning d-flex align-items-center gap-2 mt-3 py-2">
  <i class="bi bi-image"></i> تم حجب الصور الخارجية.
  <a class="btn btn-sm btn-outline-dark ms-auto"
     href="{{ url_for('mail_message_view', kind=kind, oid=oid, uid=m.uid, f=folder, images=1, frag=1) }}"
     onclick="fetch(this.href).then(function(r){return r.text()}).then(function(h){document.getElementById('readpane').innerHTML=h});return false">
   عرض الصور</a>
 </div>
 {% endif %}
 <div class="bd">
  {% if html %}
   <iframe style="width:100%;height:58vh;border:1px solid #e3e7ee;border-radius:10px;background:#fff"
           sandbox="allow-popups allow-popups-to-escape-sandbox" srcdoc="{{ html }}"></iframe>
  {% else %}
   <pre class="msgbody" style="white-space:pre-wrap;border:1px solid #e3e7ee;border-radius:10px;padding:16px;background:#fafbfd">{{ m.text }}</pre>
  {% endif %}
 </div>
</div>
"""

MAIL_COMPOSE_TPL = """
{% extends "base.html" %}{% block content %}
<form method="POST" enctype="multipart/form-data" class="cmp" onsubmit="return cmpSubmit()"
      action="{{ url_for('mail_compose', kind=kind, oid=oid, f=folder, uid=uid, mode=mode) }}">
 <input type="hidden" name="html" value="1">
 <textarea name="body" id="bodyField" hidden></textarea>
 <div class="cmp-ribbon">
  <button class="cmp-send" type="submit"><i class="bi bi-send-fill"></i><span>إرسال</span></button>
  <span class="cmp-sep"></span>
  <label class="cmp-attach"><i class="bi bi-paperclip"></i> إرفاق ملف
   <input type="file" name="files" multiple hidden onchange="cmpFiles(this)"></label>
  <span id="cmpFileList" class="cmp-files"></span>
  <span class="cmp-sep"></span>
  <div class="cmp-fmt">
   <button type="button" onclick="fmt('bold')" title="عريض"><b>B</b></button>
   <button type="button" onclick="fmt('italic')" title="مائل"><i>I</i></button>
   <button type="button" onclick="fmt('underline')" title="تسطير"><u>U</u></button>
   <span class="cmp-sep"></span>
   <button type="button" onclick="fmt('insertUnorderedList')" title="قائمة نقطية"><i class="bi bi-list-ul"></i></button>
   <button type="button" onclick="fmt('insertOrderedList')" title="قائمة مرقّمة"><i class="bi bi-list-ol"></i></button>
   <span class="cmp-sep"></span>
   <button type="button" onclick="fmt('justifyRight')" title="يمين"><i class="bi bi-text-right"></i></button>
   <button type="button" onclick="fmt('justifyCenter')" title="توسيط"><i class="bi bi-text-center"></i></button>
   <button type="button" onclick="fmt('justifyLeft')" title="يسار"><i class="bi bi-text-left"></i></button>
   <span class="cmp-sep"></span>
   <select onchange="fmt('fontSize', this.value); this.selectedIndex=0" title="حجم الخط">
    <option value="">حجم</option><option value="2">صغير</option>
    <option value="3">عادي</option><option value="5">كبير</option><option value="6">أكبر</option>
   </select>
   <button type="button" onclick="fmt('removeFormat')" title="إزالة التنسيق"><i class="bi bi-eraser"></i></button>
  </div>
  <span class="ms-auto"></span>
  <a class="cmp-cancel" href="{{ back }}"><i class="bi bi-x-lg"></i> إلغاء</a>
 </div>
 <div class="cmp-head">
  <div class="cmp-row"><span class="cmp-lbl">من</span>
   <span class="cmp-from" dir="ltr">{{ meta.email }}</span></div>
  <div class="cmp-row"><span class="cmp-lbl">إلى</span>
   <input name="to" value="{{ to }}" required placeholder="أدخل عناوين البريد مفصولة بفاصلة" dir="ltr"></div>
  <div class="cmp-row"><span class="cmp-lbl">Cc</span>
   <input name="cc" value="{{ cc }}" placeholder="نسخة (اختياري)" dir="ltr"></div>
  <div class="cmp-row"><span class="cmp-lbl">الموضوع</span>
   <input name="subject" value="{{ subject }}" placeholder="الموضوع"></div>
  {% if fwd_atts %}<div class="cmp-row"><span class="cmp-lbl"></span>
   <span class="small text-muted">سيُعاد إرفاق مرفقات الرسالة الأصلية ({{ fwd_atts }}) تلقائياً.</span></div>{% endif %}
 </div>
 <div class="cmp-body" id="cmpEditor" contenteditable="true" dir="auto"></div>
 <textarea id="rawBody" hidden>{{ body }}</textarea>
</form>
<style>
 .cmp{display:flex;flex-direction:column;height:calc(100vh - 130px);background:#fff;
   border:2px solid #b7c0d0;border-radius:14px;overflow:hidden;box-shadow:0 8px 30px rgba(20,40,80,.12)}
 .cmp-ribbon{display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid #e6e8ee;
   background:#faf9f8}
 .cmp-send{display:inline-flex;flex-direction:column;align-items:center;gap:2px;border:none;
   background:transparent;color:#0f6cbd;font-weight:700;cursor:pointer;padding:4px 12px;border-radius:8px}
 .cmp-send i{font-size:1.3rem}
 .cmp-send:hover{background:#eef4fb}
 .cmp-sep{width:1px;height:34px;background:#e2e6ee}
 .cmp-attach{display:inline-flex;align-items:center;gap:6px;color:#242424;font-weight:600;
   font-size:.88rem;cursor:pointer;padding:.4rem .7rem;border-radius:8px}
 .cmp-attach:hover{background:#eef2f8}
 .cmp-attach i{color:#0f6cbd}
 .cmp-files{font-size:.82rem;color:#0f6cbd}
 .cmp-cancel{display:inline-flex;align-items:center;gap:6px;color:#605e5c;font-size:.88rem;
   padding:.4rem .7rem;border-radius:8px}
 .cmp-cancel:hover{background:#f3f2f1;color:#242424}
 .cmp-head{padding:6px 18px;border-bottom:2px solid #c4ccda}
 .cmp-row{display:flex;align-items:center;gap:10px;border-bottom:1px solid #cfd6e2;padding:2px 0}
 .cmp-row:last-child{border-bottom:none}
 .cmp-lbl{flex:0 0 64px;color:#334; font-size:.85rem;font-weight:700}
 .cmp-row input{flex:1;border:none;outline:none;padding:10px 4px;font-size:.92rem;background:transparent}
 .cmp-from{color:#242424;font-weight:600}
 .cmp-body{flex:1;border:none;outline:none;padding:20px 22px;font-size:.95rem;
   line-height:1.7;font-family:inherit;overflow-y:auto;white-space:pre-wrap}
 .cmp-fmt{display:flex;align-items:center;gap:2px}
 .cmp-fmt button{border:none;background:transparent;color:#242424;width:30px;height:30px;
   border-radius:6px;cursor:pointer;font-size:.9rem}
 .cmp-fmt button:hover{background:#eef2f8}
 .cmp-fmt button i{color:#0f6cbd}
 .cmp-fmt select{border:1px solid #d5dbe6;border-radius:6px;font-size:.8rem;padding:2px 4px;height:30px}
</style>
<script>
function cmpFiles(inp){
 var names=[]; for(var i=0;i<inp.files.length;i++) names.push(inp.files[i].name);
 document.getElementById('cmpFileList').textContent = names.length? ('📎 '+names.join('، ')) : '';
}
function fmt(cmd, val){ document.getElementById('cmpEditor').focus();
 try{ document.execCommand(cmd, false, val||null); }catch(e){} }
function _esc(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function cmpSubmit(){
 document.getElementById('bodyField').value = document.getElementById('cmpEditor').innerHTML;
 return true;
}
document.addEventListener('DOMContentLoaded', function(){
 var raw = document.getElementById('rawBody').value || '';
 // لو التوقيع/النص فيه HTML اعرضه كما هو، وإلا حوّل الأسطر لـ <br>
 document.getElementById('cmpEditor').innerHTML =
   (/<[a-z][\\s\\S]*>/i.test(raw)) ? raw : _esc(raw).replace(/\\n/g,'<br>');
});
</script>
{% endblock %}
"""

MAILBOXES_TPL = """
{% extends "base.html" %}{% block content %}
<div class="page-head"><div><h1>صناديق البريد</h1>
 <div class="sub">كل صندوق يُفتح مباشرة من السيرفر — لا نسخ محفوظة في البرنامج</div></div></div>

<h4 class="mb-2">الحسابات المرسِلة <span class="badge bg-secondary">{{ accs|length }}</span></h4>
<div class="table-wrap">
<table class="table align-middle">
 <thead><tr><th>البريد</th><th>الوارد</th><th>غير مقروء</th><th>الاتصال</th><th></th></tr></thead>
 <tbody>
 {% for a in accs %}
 <tr>
  <td class="fw-semibold">{{ a.display_name or a.email }}<div class="small text-muted">{{ a.email }}</div></td>
  <td><span class="badge bg-primary cnt-total" data-kind="account" data-oid="{{ a.id }}">…</span></td>
  <td><span class="badge bg-warning text-dark cnt-unseen" data-kind="account" data-oid="{{ a.id }}">…</span></td>
  <td><span class="status-dot {{ 'on' if a.verify_ok else 'off' }}">
      {{ 'متصل' if a.verify_ok else 'غير متصل' }}</span></td>
  <td class="text-nowrap">
   <a class="btn btn-sm btn-primary" href="{{ url_for('mail_view', kind='account', oid=a.id) }}">
    <i class="bi bi-envelope-open"></i> فتح البريد</a>
   <a class="btn btn-sm btn-outline-dark" href="{{ url_for('sync_account', aid=a.id) }}">اختبار الاتصال</a>
  </td>
 </tr>
 {% else %}<tr><td colspan="5" class="mlist-empty">لا توجد حسابات</td></tr>{% endfor %}
 </tbody>
</table>
</div>

<div class="d-flex align-items-center gap-2 mb-2 mt-4 flex-wrap">
 <h4 class="mb-0">صناديق الموظفين
  <span class="badge bg-secondary">{{ emps|selectattr('emp_connected')|list|length }} / {{ emps|length }} متصل</span></h4>
 <a class="btn btn-sm btn-success ms-auto" href="{{ url_for('connect_all_employees') }}">
  <i class="bi bi-plug"></i> اختبار الاتصال بالكل</a>
</div>
<div class="table-wrap">
<table class="table align-middle">
 <thead><tr><th>الموظف</th><th>البريد</th><th>الحالة</th><th>الوارد</th><th>غير مقروء</th><th></th></tr></thead>
 <tbody>
 {% for e in emps %}
 <tr>
  <td class="fw-semibold">{{ e.name }}</td><td>{{ e.email }}</td>
  <td><span class="status-dot {{ 'on' if e.emp_connected else 'off' }}">
      {{ 'متصل' if e.emp_connected else 'غير متصل' }}</span></td>
  <td><span class="badge bg-primary cnt-total" data-kind="employee" data-oid="{{ e.id }}">…</span></td>
  <td><span class="badge bg-warning text-dark cnt-unseen" data-kind="employee" data-oid="{{ e.id }}">…</span></td>
  <td class="text-nowrap">
   <a class="btn btn-sm btn-primary" href="{{ url_for('mail_view', kind='employee', oid=e.id) }}">
    <i class="bi bi-envelope-open"></i> فتح البريد</a>
   <a class="btn btn-sm btn-outline-dark" href="{{ url_for('connect_employee', eid=e.id) }}">اختبار</a>
  </td>
 </tr>
 {% else %}<tr><td colspan="6" class="mlist-empty">لا يوجد موظفون ببيانات دخول</td></tr>{% endfor %}
 </tbody>
</table>
</div>
<script>
// العدّادات تُحمَّل من السيرفر بالتدريج حتى لا تتأخر الصفحة
(function(){
 var els = document.querySelectorAll('.cnt-total');
 var i = 0;
 function next(){
  if(i >= els.length) return;
  var el = els[i++];
  var k = el.dataset.kind, o = el.dataset.oid;
  fetch('/api/mailbox-counts/' + k + '/' + o).then(function(r){return r.json()}).then(function(d){
   el.textContent = d.error ? '—' : d.total;
   var u = document.querySelector('.cnt-unseen[data-kind="'+k+'"][data-oid="'+o+'"]');
   if(u) u.textContent = d.error ? '—' : d.unseen;
  }).catch(function(){el.textContent='—'}).finally(next);
 }
 next();
})();
</script>
{% endblock %}
"""

ME_TPL = """
{% extends "base.html" %}{% block content %}
<div class="page-head">
 <div><h1>إعداداتي</h1><div class="sub">{{ emp.email if emp else '' }}</div></div>
 <a class="btn btn-primary btn-sm" href="{{ url_for('me') }}"><i class="bi bi-envelope"></i> بريدي</a>
</div>
<form method="POST" action="{{ url_for('me_password') }}" class="card card-body" style="max-width:430px">
 <h5 class="mb-3">تغيير كلمة مرور الدخول</h5>
 <div class="mb-2"><label class="form-label small">كلمة المرور الحالية</label>
  <input type="password" name="old" class="form-control" required></div>
 <div class="mb-3"><label class="form-label small">كلمة المرور الجديدة</label>
  <input type="password" name="new" class="form-control" required></div>
 <button class="btn btn-primary">حفظ</button>
</form>
{% endblock %}
"""

DISTRIBUTION_TPL = """
{% extends "base.html" %}{% block content %}
<style>
 .ds-wrap{max-width:1100px;margin:0 auto}
 .ds-head{display:flex;align-items:center;gap:10px;margin-bottom:4px}
 .ds-head i{font-size:1.4rem;color:#0f6cbd}
 .ds-head h2{font-size:1.35rem;margin:0;font-weight:700;color:#1f2937}
 .ds-sub{color:#6b7280;font-size:.84rem;margin-bottom:16px}
 .ds-card{background:#fff;border:1px solid #e2e6ee;border-radius:12px;margin-bottom:16px;
   box-shadow:0 1px 4px rgba(20,40,80,.05);overflow:hidden}
 .ds-card-h{display:flex;align-items:center;gap:8px;padding:11px 16px;background:#f7f9fc;
   border-bottom:1px solid #e8ebf2;font-weight:700;font-size:.98rem;color:#243043}
 .ds-card-h i{color:#0f6cbd}
 .ds-card-b{padding:16px}
 .ds-groups{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
 .ds-acc{border:1.5px solid #c7d0e0;border-inline-start:4px solid #0f6cbd;border-radius:10px;
   padding:12px 14px;background:#fbfcfe;box-shadow:0 1px 6px rgba(20,40,80,.06)}
 .ds-acc-top{display:flex;align-items:center;gap:8px;margin-bottom:6px}
 .ds-acc-top .nm{font-weight:700;color:#243043}
 .ds-acc .em{font-size:.8rem;color:#0f6cbd;direction:ltr;text-align:right}
 .ds-cnt{margin-inline-start:auto;background:#0f6cbd;color:#fff;font-size:.72rem;font-weight:700;
   padding:2px 9px;border-radius:20px}
 .ds-depts{display:flex;flex-wrap:wrap;gap:5px;margin:8px 0}
 .ds-depts .dep{background:#eef2f9;color:#334;border:1px solid #dbe2ee;border-radius:6px;
   padding:1px 8px;font-size:.74rem}
 .ds-acc-btns{display:flex;gap:6px;margin-top:8px}
 .ds-mini{border:1px solid #cfd8e6;background:#fff;color:#0f6cbd;border-radius:6px;padding:4px 12px;
   font-size:.8rem;font-weight:600;text-decoration:none}
 .ds-mini:hover{background:#eef4fb}
 .ds-mini.dark{color:#243043}
 .ds-btn{background:#0f6cbd;border:none;color:#fff;padding:9px 16px;border-radius:8px;
   font-size:.88rem;font-weight:600;cursor:pointer}
 .ds-btn:hover{background:#115ea3}
 .ds-btn-o{background:#fff;border:1px solid #0f6cbd;color:#0f6cbd;padding:9px 16px;border-radius:8px;
   font-size:.88rem;font-weight:600;cursor:pointer}
 .ds-btn-o:hover{background:#eef4fb}
 .ds-dep-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
 .ds-dep-row{display:flex;align-items:center;gap:8px}
 .ds-dep-row .lbl{min-width:100px;font-size:.82rem;color:#243043;font-weight:600}
 .ds-sel{border:1px solid #d5dae4;border-radius:7px;padding:6px 9px;font-size:.85rem;
   background:#fcfdff;outline:none;width:100%}
 .ds-sel:focus{border-color:#0f6cbd;box-shadow:0 0 0 3px rgba(15,108,189,.1)}
 .ds-toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 12px;
   background:#f7f9fc;border:1px solid #e8ebf2;border-radius:9px;margin-bottom:10px}
 .ds-search{border:1px solid #d5dae4;border-radius:7px;padding:7px 11px;font-size:.85rem;
   background:#fff;outline:none;min-width:220px;flex:1}
 .ds-search:focus{border-color:#0f6cbd;box-shadow:0 0 0 3px rgba(15,108,189,.1)}
 .ds-table{width:100%;border-collapse:collapse;font-size:.85rem}
 .ds-table th{position:sticky;top:0;background:#eef2f9;color:#334;font-size:.76rem;font-weight:700;
   padding:8px 10px;text-align:start;white-space:nowrap;z-index:1}
 .ds-table td{padding:7px 10px;border-bottom:1px solid #eef1f6;vertical-align:middle}
 .ds-table tr:hover td{background:#f9fbff}
 .ds-warn{background:#fff7ea;border:1px solid #f0d59a;border-radius:9px;padding:10px 14px;
   font-size:.83rem;color:#8a5a00;margin-bottom:16px}
</style>
<div class="ds-wrap">
 <div class="d-flex align-items-center">
  <div>
   <div class="ds-head"><i class="bi bi-diagram-3-fill"></i><h2>توزيع الموظفين على الحسابات</h2></div>
   <div class="ds-sub">كل حساب مرسِل يصبح مسؤولاً عن مجموعته — ولا يُرسل لغيرها.</div>
  </div>
  <a class="ds-mini dark ms-auto" href="{{ url_for('distribution_clear') }}"
     onclick="return confirm('إلغاء كل التوزيع؟')" style="color:#c0392b;border-color:#e0b3b6">
   <i class="bi bi-x-circle"></i> إلغاء التوزيع</a>
 </div>

 {% if unassigned %}
 <div class="ds-warn"><i class="bi bi-exclamation-triangle"></i> {{ unassigned }} موظفاً بلا حساب مسؤول —
  سيُرسَل لهم من أي حساب متاح.</div>
 {% endif %}

 <div class="ds-card">
  <div class="ds-card-h"><i class="bi bi-people-fill"></i> مجموعات الحسابات الرئيسية</div>
  <div class="ds-card-b">
   <div class="ds-groups">
   {% for g in groups %}
    <div class="ds-acc">
     <div class="ds-acc-top">
      <span class="status-dot {{ 'on' if g.acc.active else 'off' }}"></span>
      <span class="nm text-truncate">{{ g.acc.display_name or g.acc.email }}</span>
      <span class="ds-cnt">{{ g.count }} موظف</span>
     </div>
     <div class="em">{{ g.acc.email }}</div>
     <div class="ds-depts">
      {% for d in g.depts %}<span class="dep">{{ d.department }} ({{ d.c }})</span>
      {% else %}<span class="text-muted small">لا يوجد موظفون مرتبطون</span>{% endfor %}
     </div>
     <div class="ds-acc-btns">
      <a class="ds-mini" href="{{ url_for('mail_view', kind='account', oid=g.acc.id) }}">
       <i class="bi bi-envelope"></i> بريده</a>
      <a class="ds-mini dark" href="{{ url_for('campaigns') }}?scope={{ g.acc.id }}">
       <i class="bi bi-megaphone"></i> حملة لمجموعته</a>
     </div>
    </div>
   {% else %}
    <div class="alert alert-warning mb-0">أضف حسابات مرسِلة أولاً.</div>
   {% endfor %}
   </div>
  </div>
 </div>

 <div class="ds-card">
  <div class="ds-card-h"><i class="bi bi-magic"></i> توزيع تلقائي</div>
  <div class="ds-card-b">
   <form method="POST" action="{{ url_for('distribution_auto') }}">
    <div class="small text-muted mb-1">وزّع على الحسابات دي فقط — شيل علامة أي حساب عايز تستثنيه (زي INFO):</div>
    <div class="d-flex gap-3 flex-wrap mb-2" style="gap:10px 18px">
     {% for a in accs %}
     <label class="small" style="cursor:pointer"><input type="checkbox" name="accounts" value="{{ a.id }}"
        {{ 'checked' if a.active }} {{ 'disabled' if not a.active }}>
       {{ a.display_name or a.email }}{{ ' (موقوف)' if not a.active }}</label>
     {% endfor %}
    </div>
    <div class="d-flex gap-2 flex-wrap">
     <button class="ds-btn" name="mode" value="equal">
      <i class="bi bi-distribute-horizontal"></i> بالتساوي على المحدَّدين</button>
     <button class="ds-btn-o" name="mode" value="department">
      <i class="bi bi-diagram-3"></i> أقساماً كاملة على المحدَّدين</button>
    </div>
   </form>
   <p class="small text-muted mt-2 mb-0">مثال: 214 موظفاً على 5 حسابات (باستثناء INFO) → ~43 لكل حساب.</p>
  </div>
 </div>

 <form method="POST" action="{{ url_for('distribution_departments') }}" class="ds-card">
  <div class="ds-card-h"><i class="bi bi-link-45deg"></i> ربط الأقسام بالحسابات</div>
  <div class="ds-card-b">
   <div class="ds-dep-grid">
   {% for d in departments %}
    <div class="ds-dep-row">
     <span class="lbl">{{ d or '(بدون قسم)' }}</span>
     <select name="deptacc::{{ d }}" class="ds-sel">
      <option value="">— بدون —</option>
      {% for a in accs %}<option value="{{ a.id }}"
        {{ 'selected' if dept_owner.get(d)==a.id }}>{{ a.display_name or a.email }}</option>{% endfor %}
     </select>
    </div>
   {% else %}<div class="text-muted small">لا توجد أقسام.</div>{% endfor %}
   </div>
   <button class="ds-btn mt-3"><i class="bi bi-save"></i> حفظ ربط الأقسام</button>
  </div>
 </form>

 <form method="POST" action="{{ url_for('distribution_assign') }}" id="bulkform"></form>

 <form method="POST" action="{{ url_for('distribution_save') }}" class="ds-card">
  <div class="ds-card-h"><i class="bi bi-person-lines-fill"></i> اختر موظفين واربطهم بحساب رئيسي
   <button class="ds-btn-o ms-auto" style="padding:5px 12px;font-size:.8rem">
    <i class="bi bi-save"></i> حفظ القوائم المنسدلة</button></div>
  <div class="ds-card-b">
   <div class="ds-toolbar">
    <label class="d-flex align-items-center gap-2 mb-0" style="cursor:pointer">
     <input class="form-check-input m-0" type="checkbox" onclick="dsAll(this)">
     <span class="small">تحديد الكل</span></label>
    <input class="ds-search" id="dsq" placeholder="ابحث بالاسم أو البريد أو القسم" oninput="dsFilter()">
    <button class="ds-btn-o" style="padding:6px 12px;font-size:.8rem" type="button" onclick="dsAll(true)">حدّد الظاهر</button>
    <span class="d-flex align-items-center gap-2 ms-auto">
     <span class="small fw-bold">اربط المحدَّدين بـ:</span>
     <select name="account_id" form="bulkform" class="ds-sel" style="width:auto">
      <option value="">— بدون حساب —</option>
      {% for a in accs %}<option value="{{ a.id }}">{{ a.display_name or a.email }}</option>{% endfor %}
     </select>
     <button class="ds-btn" style="padding:6px 14px;font-size:.82rem" form="bulkform" type="submit">
      <i class="bi bi-link-45deg"></i> اربط (<span id="dscount">0</span>)</button>
    </span>
   </div>

   <div style="max-height:520px;overflow:auto;border:1px solid #e8ebf2;border-radius:9px">
   <table class="ds-table" id="dstable">
    <thead><tr><th style="width:34px"></th><th>الموظف</th><th>القسم</th><th>الحساب المسؤول</th></tr></thead>
    <tbody>
    {% for e in emps %}
     <tr data-s="{{ (e.name ~ ' ' ~ e.email ~ ' ' ~ (e.department or ''))|lower }}">
      <td><input class="form-check-input m-0 dschk" form="bulkform" type="checkbox"
                 name="eid" value="{{ e.id }}" onchange="dsCount()"></td>
      <td class="fw-semibold">{{ e.name }}<div class="small text-muted" dir="ltr">{{ e.email }}</div></td>
      <td class="small">{{ e.department or '—' }}</td>
      <td><select name="own::{{ e.id }}" class="ds-sel">
        <option value="">— بدون —</option>
        {% for a in accs %}<option value="{{ a.id }}"
          {{ 'selected' if e.owner_account_id==a.id }}>{{ a.display_name or a.email }}</option>{% endfor %}
       </select></td>
     </tr>
    {% else %}<tr><td colspan="4" class="text-muted p-3">لا يوجد موظفون</td></tr>{% endfor %}
    </tbody>
   </table>
   </div>
   <p class="small text-muted mt-2 mb-0">الموظف المرتبط بحساب: يستلم رسائل الحملات من هذا
    الحساب وحده، ويرد عليه هو تلقائياً في الرد العكسي.</p>
  </div>
 </form>
</div>

<script>
function dsRows(){return Array.prototype.slice.call(
  document.querySelectorAll('#dstable tbody tr[data-s]'));}
function dsCount(){document.getElementById('dscount').textContent =
  document.querySelectorAll('.dschk:checked').length;}
function dsAll(src){
 var on = (src === true) ? true : src.checked;
 dsRows().forEach(function(tr){
  if(tr.style.display === 'none') return;
  var c = tr.querySelector('.dschk'); if(c) c.checked = on;
 });
 dsCount();
}
function dsFilter(){
 var q = document.getElementById('dsq').value.trim().toLowerCase();
 dsRows().forEach(function(tr){
  tr.style.display = (!q || tr.dataset.s.indexOf(q) !== -1) ? '' : 'none';
 });
}
</script>
{% endblock %}
"""

SERVER_TPL = """
{% extends "base.html" %}{% block content %}
<div class="page-head"><div><h1>السيرفر والنشر عبر SSH</h1>
 <div class="sub">اربط البرنامج بسيرفر Linux (Ubuntu/Debian أو RHEL) وانشره بضغطة واحدة على دومينك مع Nginx وشهادة SSL</div></div>
 {% if cfg.deploy_last_at %}<span class="badge bg-{{ 'success' if cfg.deploy_last_status=='ok' else 'danger' }}">
  آخر عملية: {{ cfg.deploy_last_at }} · {{ 'نجحت' if cfg.deploy_last_status=='ok' else 'فشلت' }}</span>{% endif %}
</div>
{% if not ssh_ok %}
<div class="alert alert-danger"><i class="bi bi-exclamation-triangle"></i>
 مكتبة <code>paramiko</code> غير مثبّتة — نفّذ <code>pip install paramiko</code> ثم أعد تشغيل البرنامج.</div>
{% endif %}

<div class="row g-3">
<div class="col-lg-7">
<form method="POST" enctype="multipart/form-data" class="card card-body">
 <h5><i class="bi bi-hdd-network"></i> بيانات السيرفر</h5>
 <div class="row">
  <div class="col-md-6 mb-2"><label>عنوان السيرفر (IP أو Hostname)</label>
   <input name="deploy_host" class="form-control" dir="ltr" value="{{ cfg.deploy_host }}" placeholder="203.0.113.10" required></div>
  <div class="col-md-3 mb-2"><label>منفذ SSH</label>
   <input name="deploy_port" type="text" inputmode="numeric" pattern="[0-9]+" title="أرقام فقط" class="form-control" dir="ltr" value="{{ cfg.deploy_port }}"></div>
  <div class="col-md-3 mb-2"><label>المستخدم</label>
   <input name="deploy_user" class="form-control" dir="ltr" value="{{ cfg.deploy_user }}" placeholder="root"></div>
 </div>
 <p class="text-muted small mb-2">لو المستخدم ليس <code>root</code> يجب أن يملك <code>sudo</code> بدون كلمة مرور (NOPASSWD).</p>

 <label class="mb-1">طريقة الدخول</label>
 <div class="d-flex gap-4 mb-2">
  <div class="form-check"><input class="form-check-input" type="radio" name="deploy_auth" id="au_p" value="password"
    {{ 'checked' if cfg.deploy_auth == 'password' }} onchange="authSw()">
   <label class="form-check-label" for="au_p">كلمة مرور {% if has_pw %}<span class="badge bg-success">محفوظة ✔</span>{% endif %}</label></div>
  <div class="form-check"><input class="form-check-input" type="radio" name="deploy_auth" id="au_k" value="key"
    {{ 'checked' if cfg.deploy_auth != 'password' }} onchange="authSw()">
   <label class="form-check-label" for="au_k">مفتاح SSH {% if has_key %}<span class="badge bg-success">محفوظ ✔</span>{% endif %}</label></div>
 </div>
 <div id="auth_pw" class="mb-2"><label>كلمة مرور السيرفر{% if has_pw %} — تُترك فارغة للإبقاء على المحفوظة{% endif %}</label>
  <input name="deploy_password" type="password" class="form-control" dir="ltr" autocomplete="new-password" placeholder="{{ '••••••••' if has_pw else 'كلمة مرور المستخدم على السيرفر' }}"></div>
 <div id="auth_key">
  <div class="mb-2"><label>المفتاح الخاص (الصقه هنا) — يُترك فارغاً للإبقاء على المحفوظ</label>
   <textarea name="deploy_key" class="form-control font-monospace" dir="ltr" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></div>
  <div class="row">
   <div class="col-md-7 mb-2"><label>أو ارفع ملف المفتاح</label>
    <input name="deploy_key_file" type="file" class="form-control"></div>
   <div class="col-md-5 mb-2"><label>عبارة مرور المفتاح (إن وُجدت)</label>
    <input name="deploy_key_pass" type="password" class="form-control" dir="ltr" value="{{ cfg.deploy_key_pass }}" autocomplete="new-password"></div>
  </div>
 </div>

 <hr>
 <h5><i class="bi bi-globe2"></i> الدومين والتشغيل</h5>
 <div class="row">
  <div class="col-md-6 mb-2"><label>الدومين (اختياري)</label>
   <input name="deploy_domain" class="form-control" dir="ltr" value="{{ cfg.deploy_domain }}" placeholder="mail.example.com"></div>
  <div class="col-md-6 mb-2"><label>بريد Let's Encrypt (لتنبيهات الشهادة)</label>
   <input name="deploy_le_email" type="email" class="form-control" dir="ltr" value="{{ cfg.deploy_le_email }}"></div>
  <div class="col-md-8 mb-2"><label>مجلد البرنامج على السيرفر</label>
   <input name="deploy_dir" class="form-control" dir="ltr" value="{{ cfg.deploy_dir }}"></div>
  <div class="col-md-4 mb-2"><label>المنفذ الداخلي للبرنامج</label>
   <input name="deploy_app_port" type="text" inputmode="numeric" pattern="[0-9]+" title="أرقام فقط" class="form-control" dir="ltr" value="{{ cfg.deploy_app_port }}"></div>
 </div>
 <div class="form-check mb-3">
  <input class="form-check-input" type="checkbox" name="deploy_ssl" id="ssl" {{ 'checked' if cfg.deploy_ssl == '1' }}>
  <label class="form-check-label" for="ssl">إصدار شهادة SSL تلقائياً (Let's Encrypt) وتحويل HTTP → HTTPS</label></div>
 <p class="text-muted small">قبل النشر بدومين: أضف سجل <strong>A</strong> في DNS يشير من الدومين إلى IP السيرفر، وافتح المنفذين 80 و443.</p>
 <div><button class="btn btn-primary"><i class="bi bi-save"></i> حفظ الإعدادات</button></div>
</form>
</div>

<div class="col-lg-5">
 <div class="card card-body">
  <h5><i class="bi bi-key-fill"></i> مفتاح SSH</h5>
  {% if pub %}
   <label>المفتاح العام — أضفه على السيرفر في <code>~/.ssh/authorized_keys</code>:</label>
   <textarea class="form-control font-monospace small mb-2" dir="ltr" rows="3" readonly onclick="this.select()">{{ pub }}</textarea>
   <details class="mb-2"><summary class="small text-muted">أمر جاهز لتنفيذه على السيرفر مرة واحدة</summary>
    <pre class="msgbody small mt-2" dir="ltr" style="user-select:all">mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '{{ pub }}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys</pre></details>
  {% elif has_key %}
   <p class="text-warning small">المفتاح المحفوظ لا يُقرأ (عبارة مرور خاطئة؟)</p>
  {% else %}
   <p class="text-muted small">لا يوجد مفتاح محفوظ. ولّد واحداً أو الصق مفتاحك في النموذج.</p>
  {% endif %}
  <div class="d-flex flex-wrap gap-2">
   <form method="POST" action="{{ url_for('server_key', act='generate') }}"
     onsubmit="return {{ 'confirm(\\'سيستبدل المفتاح المحفوظ. متابعة؟\\')' if has_key else 'true' }}">
    <button class="btn btn-sm btn-outline-primary"><i class="bi bi-magic"></i> توليد مفتاح جديد</button></form>
   {% if local_key_exists %}
   <form method="POST" action="{{ url_for('server_key', act='import') }}">
    <button class="btn btn-sm btn-outline-secondary"><i class="bi bi-file-earmark-arrow-down"></i> استيراد .deploy_email_manager_key</button></form>
   {% endif %}
   {% if has_key %}
   <form method="POST" action="{{ url_for('server_key', act='delete') }}" onsubmit="return confirm('حذف المفتاح المحفوظ؟')">
    <button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i> حذف</button></form>
   {% endif %}
  </div>
 </div>

 <div class="card card-body">
  <h5><i class="bi bi-rocket-takeoff"></i> النشر</h5>
  <form method="POST" action="{{ url_for('server_test') }}" class="mb-2">
   <button class="btn btn-outline-primary w-100" {{ 'disabled' if not ssh_ok }}><i class="bi bi-plug"></i> اختبار الاتصال بالسيرفر</button></form>
  <form method="POST" action="{{ url_for('server_deploy') }}" onsubmit="return confirm('سيتم تثبيت المتطلبات ورفع البرنامج وتشغيله على السيرفر. متابعة؟')">
   <label class="small">قاعدة البيانات والحسابات</label>
   <select name="copy_data" class="form-select form-select-sm mb-2">
    <option value="first">نسخ بياناتي المحلية إن كان السيرفر فارغاً (أول مرة)</option>
    <option value="always">استبدال بيانات السيرفر ببياناتي المحلية</option>
    <option value="never">لا تنسخ أي بيانات</option>
   </select>
   <button class="btn btn-success w-100" {{ 'disabled' if not ssh_ok or state.running }}>
    <i class="bi bi-cloud-upload"></i> نشر / تحديث البرنامج على السيرفر</button>
  </form>
  <div class="text-muted small mt-2">يثبّت Python وNginx (وCertbot)، يرفع الملفات، ينشئ خدمة <code>{{ service }}</code> تعمل تلقائياً مع الإقلاع، ويربطها بالدومين.</div>
  <hr>
  <label class="small">أوامر سريعة</label>
  <div class="d-flex flex-wrap gap-1">
   {% for a, ic, t in [('status','info-circle','الحالة'),('restart','arrow-clockwise','إعادة تشغيل'),
                       ('start','play','تشغيل'),('stop','stop','إيقاف'),('logs','journal-text','السجلّات'),('nginx','diagram-2','فحص Nginx')] %}
   <form method="POST" action="{{ url_for('server_action', act=a) }}">
    <button class="btn btn-sm btn-outline-secondary" {{ 'disabled' if not ssh_ok }}><i class="bi bi-{{ ic }}"></i> {{ t }}</button></form>
   {% endfor %}
  </div>
 </div>
</div>
</div>

<div class="card card-body">
 <h5><i class="bi bi-wifi"></i> التشغيل على الشبكة المحلية (جهاز آخر بنفس الشبكة)</h5>
 <form method="POST" action="{{ url_for('server_network') }}" class="row g-2 align-items-end">
  <div class="col-md-6">
   <div class="form-check">
    <input class="form-check-input" type="checkbox" name="listen_lan" id="lan" {{ 'checked' if net.lan }}>
    <label class="form-check-label" for="lan"><strong>السماح بالوصول من أجهزة أخرى على الشبكة</strong>
     <div class="text-muted small fw-normal">يستمع البرنامج على كل عناوين الجهاز (0.0.0.0) بدل 127.0.0.1 فقط</div></label></div>
  </div>
  <div class="col-md-3"><label>المنفذ</label>
   <input name="listen_port" type="text" inputmode="numeric" pattern="[0-9]+" title="أرقام فقط" class="form-control" dir="ltr" value="{{ net.port }}"></div>
  <div class="col-md-3"><button class="btn btn-primary w-100"><i class="bi bi-save"></i> حفظ</button></div>
 </form>
 {% if net.env_host or net.env_port %}
 <div class="alert alert-warning small mt-3 mb-0">متغيرات البيئة <code>EM_HOST</code>/<code>EM_PORT</code> مضبوطة وستتجاوز هذه الإعدادات.</div>
 {% endif %}
 <div class="mt-3 small">
  <div class="mb-1"><strong>يسري التغيير بعد إغلاق البرنامج وتشغيله من جديد.</strong></div>
  {% if net.ips %}
  <div class="mb-1">عناوين هذا الجهاز على الشبكة — افتح على الجهاز الآخر:
   {% for ip in net.ips %}<code dir="ltr">http://{{ ip }}:{{ net.port }}</code>{{ ' · ' if not loop.last }}{% endfor %}</div>
  {% endif %}
  <div class="text-muted">لو لم يفتح من الجهاز الآخر، اسمح بالمنفذ في جدار حماية Windows (نفّذ مرة واحدة كمسؤول):
   <pre class="msgbody small mt-1 mb-0" dir="ltr" style="user-select:all">netsh advfirewall firewall add rule name="Email Manager" dir=in action=allow protocol=TCP localport={{ net.port }}</pre></div>
 </div>
</div>

<div class="card card-body" id="logcard">
 <div class="d-flex align-items-center gap-2 mb-2">
  <h5 class="mb-0"><i class="bi bi-terminal"></i> سجل العملية</h5>
  <span id="dstate" class="badge bg-secondary">—</span>
  <a id="durl" href="#" target="_blank" class="btn btn-sm btn-success d-none"><i class="bi bi-box-arrow-up-right"></i> فتح البرنامج على السيرفر</a>
 </div>
 <pre id="dlog" class="msgbody" dir="ltr" style="max-height:420px;overflow:auto;font-family:Consolas,monospace;font-size:.82rem;text-align:left;margin:0">{{ state.log|join('\\n') or 'لا توجد عملية بعد.' }}</pre>
</div>

<script>
function authSw(){
 var k=document.getElementById('au_k').checked;
 document.getElementById('auth_key').style.opacity=k?'1':'.55';
 document.getElementById('auth_pw').style.opacity=k?'.55':'1';
}
authSw();
var _wasRunning={{ 'true' if state.running else 'false' }};
function poll(){
 fetch('{{ url_for("server_log") }}').then(function(r){return r.json()}).then(function(d){
  var pre=document.getElementById('dlog'), st=document.getElementById('dstate'), u=document.getElementById('durl');
  if(d.log.length){pre.textContent=d.log.join('\\n');pre.scrollTop=pre.scrollHeight;}
  var m={running:['warning','جارٍ التنفيذ…'],ok:['success','نجحت'],error:['danger','فشلت']}[d.status]||['secondary','—'];
  st.className='badge bg-'+m[0]; st.textContent=m[1];
  if(d.url){u.href=d.url;u.classList.remove('d-none');} else {u.classList.add('d-none');}
  if(d.running){_wasRunning=true;setTimeout(poll,700);}
  else if(_wasRunning){_wasRunning=false;setTimeout(function(){location.reload()},1200);}
 }).catch(function(){setTimeout(poll,3000)});
}
poll();
</script>
{% endblock %}
"""

DOMAINS_TPL = """
{% extends "base.html" %}{% block content %}
<style>
 .dompage .page-head h1{font-size:1.25rem}
 .dompage .page-head .sub{font-size:.78rem}
 .dompage .dom-card{border:1px solid #d5dae4;border-radius:10px;padding:10px 12px;margin-bottom:10px;
   background:#fff;box-shadow:0 1px 5px rgba(20,40,80,.05)}
 .dompage .dom-toggle{background:none;border:none;font-size:.98rem;font-weight:700;color:#1f2937;
   display:flex;align-items:center;gap:8px;cursor:pointer;padding:2px 4px}
 .dompage .dom-toggle .bi-globe2{color:#0f6cbd}
 .dompage .dom-toggle .chev{font-size:.8rem;color:#0f6cbd;transition:transform .18s}
 .dompage .dom-toggle[aria-expanded="true"] .chev{transform:rotate(-90deg)}
 .dompage .dom-top h5{font-size:.95rem}
 .dompage .dom-top .badge{font-size:.66rem;padding:.28em .5em}
 .dompage .dom-top .btn-sm{padding:.2rem .5rem;font-size:.76rem}
 .dompage table{font-size:.8rem;margin-bottom:0}
 .dompage table th{font-size:.72rem;color:#6b7280;font-weight:600;padding:.35rem .5rem;
   background:#f7f9fc;white-space:nowrap}
 .dompage table td{padding:.3rem .5rem;vertical-align:middle}
 .dompage table td .badge{font-size:.66rem;padding:.25em .45em}
 .dompage table .btn-sm{padding:.15rem .4rem;font-size:.72rem}
</style>
<div class="dompage">
<div class="page-head">
 <div><h1>الدومينات والصناديق <span class="badge bg-secondary">{{ domains|length }}</span></h1>
  <div class="sub">بريد داخلي مدمج بالكامل — بدون أي سيرفر خارجي. أنشئ الدومين ثم الصناديق تحته.</div></div>
 <div class="d-flex gap-2">
  <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('domains_export') }}">
   <i class="bi bi-download"></i> تصدير</a>
  <button class="btn btn-outline-success btn-sm" data-bs-toggle="modal" data-bs-target="#importbox">
   <i class="bi bi-upload"></i> استيراد</button>
  <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#adddom">
   <i class="bi bi-plus-lg"></i> إضافة دومين</button>
 </div>
</div>

<div class="modal fade" id="importbox" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
 <form method="POST" action="{{ url_for('domains_import') }}" enctype="multipart/form-data">
  <div class="modal-header"><h5 class="modal-title"><i class="bi bi-upload"></i> استيراد إيميلات من ملف</h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
   <div class="mb-2"><label>ملف CSV</label>
    <input name="file" type="file" accept=".csv,text/csv" class="form-control" required></div>
   <div class="alert alert-info py-2 small mb-2">
    كل إيميل بينزل <b>تحت دومينه تلقائياً</b> (والدومين يتعمل لو مش موجود)، والفرعي يتربط بالحساب الرئيسي لدومينه.
    تقدر تدخل تظبّطهم بعدين.</div>
   <div class="small text-muted">أعمدة الملف بالترتيب:
    <code>email</code> ثم (اختياري) <code>name</code> ثم <code>type</code> (main/sub — الافتراضي sub)
    ثم <code>password</code>. مثال:<br>
    <code dir="ltr">11@haha.sa, أحمد, sub, </code><br>
    <code dir="ltr">ahmed@haha.sa, الحساب الرئيسي, main, </code></div>
  </div>
  <div class="modal-footer">
   <a class="btn btn-outline-secondary me-auto" href="{{ url_for('domains_export') }}">
    <i class="bi bi-download"></i> نزّل نموذج/تصدير حالي</a>
   <button class="btn btn-success"><i class="bi bi-upload"></i> استيراد</button></div>
 </form>
</div></div></div>

{% for d in domains %}
<div class="dom-card" id="dom{{ d.id }}">
 <div class="dom-top d-flex align-items-center gap-2 flex-wrap">
  <button class="dom-toggle" type="button" data-bs-toggle="collapse" data-bs-target="#dombody{{ d.id }}">
   <i class="bi bi-chevron-left chev"></i>
   <i class="bi bi-globe2"></i> <span dir="ltr">{{ d.name }}</span></button>
  <span class="badge bg-info text-dark">{{ d.mains|length }} رئيسي</span>
  <span class="badge bg-secondary">{{ d.subs|length }} فرعي</span>
  <div class="ms-auto d-flex gap-2">
   <button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#addbox{{ d.id }}">
    <i class="bi bi-person-plus"></i> إضافة إيميل</button>
   <a class="btn btn-sm btn-danger" href="{{ url_for('domain_delete', did=d.id) }}"
      onclick="return confirm('حذف الدومين؟ (الإيميلات المرتبطة بيه مش هتتمسح تلقائياً)')"><i class="bi bi-trash"></i></a>
  </div>
 </div>
 <div class="collapse{{ ' show' if openbox==d.id }}" id="dombody{{ d.id }}">
 <div class="table-wrap mt-2">
 <table class="table table-sm align-middle mb-0">
  <thead><tr><th>البريد</th><th>الاسم الظاهر</th><th>النوع</th><th>الحساب الرئيسي</th>
    <th>توقيع</th><th>كلمة مرور</th><th></th></tr></thead>
  <tbody>
  {% for b in d.mains %}
  <tr>
   <td class="fw-semibold" dir="ltr">{{ b.email }}</td>
   <td>{{ b.display_name or '—' }}</td>
   <td><span class="badge bg-info text-dark">رئيسي</span></td>
   <td class="text-muted">— (هو نفسه رئيسي)</td>
   <td>{{ '✔' if b.signature else '—' }}</td>
   <td>{{ '🔑' if b.password else '—' }}</td>
   <td class="text-nowrap">
    <a class="btn btn-sm btn-danger" href="{{ url_for('mailbox_delete', kind='main', bid=b.id) }}"
       onclick="return confirm('حذف الحساب الرئيسي؟')"><i class="bi bi-trash"></i></a>
   </td>
  </tr>
  {% endfor %}
  {% for b in d.subs %}
  <tr>
   <td class="fw-semibold" dir="ltr">{{ b.email }}</td>
   <td>{{ b.name or '—' }}</td>
   <td><span class="badge bg-light text-dark">فرعي</span></td>
   <td>{% if b.owner_name %}<span class="badge bg-info text-dark">{{ b.owner_name }}</span>
       {% else %}<span class="text-muted">— غير مربوط —</span>{% endif %}</td>
   <td>{{ '✔' if b.signature else '—' }}</td>
   <td>{{ '🔑' if b.password else '—' }}</td>
   <td class="text-nowrap">
    <a class="btn btn-sm btn-danger" href="{{ url_for('mailbox_delete', kind='sub', bid=b.id) }}"
       onclick="return confirm('حذف الموظف الفرعي؟')"><i class="bi bi-trash"></i></a>
   </td>
  </tr>
  {% endfor %}
  {% if not d.mains and not d.subs %}
  <tr><td colspan="7" class="text-muted">مفيش إيميلات تحت الدومين ده لسه</td></tr>{% endif %}
  </tbody>
 </table>
 </div>
 </div>
</div>

<div class="modal fade" id="addbox{{ d.id }}" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
 <form method="POST" action="{{ url_for('mailbox_add', did=d.id) }}" enctype="multipart/form-data">
  <div class="modal-header"><h5 class="modal-title">إيميل جديد تحت {{ d.name }}</h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
   <div class="mb-2"><label>اسم الإيميل (الجزء قبل الـ@)</label>
    <div class="input-group">
     <input name="local_part" class="form-control" placeholder="ahmed" required dir="ltr">
     <span class="input-group-text" dir="ltr">@{{ d.name }}</span>
    </div></div>
   <div class="mb-2"><label>الاسم الظاهر (اختياري)</label>
    <input name="display_name" class="form-control" placeholder="أحمد محمد"></div>
   <div class="row">
    <div class="col-6 mb-2"><label>رقم الإقامة (اختياري)</label>
     <input name="iqama" class="form-control" dir="ltr" placeholder="2xxxxxxxxx"></div>
    <div class="col-6 mb-2"><label>الرقم الوظيفي (اختياري)</label>
     <input name="emp_number" class="form-control" dir="ltr" placeholder="EMP-001"></div>
   </div>
   <div class="mb-2"><label>النوع</label>
    <select name="role" class="form-select role-sel" data-dom="{{ d.id }}">
     <option value="sub">فرعي → يروح «الموظفون»</option>
     <option value="main">رئيسي → يروح «الحسابات المرسِلة»</option>
    </select></div>
   <div class="mb-2 owner-wrap" id="ownerwrap{{ d.id }}">
    {% if d.mains %}
    <div class="alert alert-info py-2 mb-0 small">
     <i class="bi bi-link-45deg"></i> هيتربط تلقائياً بالحساب الرئيسي للدومين:
     <strong dir="ltr">{{ d.mains[0].email }}</strong></div>
    {% else %}
    <div class="alert alert-warning py-2 mb-0 small">
     <i class="bi bi-exclamation-triangle"></i> الدومين ده لسه ملوش حساب رئيسي —
     أنشئ إيميل «رئيسي» الأول عشان الفرعيين يتربطوا بيه تلقائياً.</div>
    {% endif %}
   </div>
   <div class="mb-2"><label>التوقيع (بيتملّي تلقائياً من بيانات الموظف)</label>
    <textarea name="signature" class="form-control" rows="8" dir="auto">Thanks &amp; Best Regards,

{name}
{title} | {department}
Email: {email}
Phone: {phone}
Team 360 | www.team360.sa</textarea>
    <div class="form-text">المتغيرات المتاحة: <code>{name}</code> <code>{title}</code>
     <code>{department}</code> <code>{phone}</code> <code>{email}</code> —
     بتتحوّل تلقائياً لبيانات كل موظف، والأسطر الفاضية بتتحذف.</div></div>
   <div class="mb-2"><label>لوجو / صورة التوقيع (اختياري)</label>
    <input name="logo" type="file" accept="image/*" class="form-control">
    <div class="form-text">بتظهر تحت التوقيع في الرسالة (أقصى حجم 600 كيلوبايت).</div></div>
   <div class="mb-2"><label>كلمة المرور (اختياري)</label>
    <input name="password" type="password" class="form-control" autocomplete="new-password"></div>
  </div>
  <div class="modal-footer">
   <button class="btn btn-outline-primary" name="again" value="1">
    <i class="bi bi-plus-lg"></i> حفظ وإضافة آخر</button>
   <button class="btn btn-primary">حفظ</button></div>
 </form>
</div></div></div>
{% else %}
<div class="card card-body text-muted">مفيش دومينات لسه — اضغط «إضافة دومين» للبدء.</div>
{% endfor %}

<script>
document.querySelectorAll('.role-sel').forEach(function(sel){
 function upd(){
  var w=document.getElementById('ownerwrap'+sel.dataset.dom);
  if(w) w.style.display = (sel.value==='sub') ? '' : 'none';
 }
 sel.addEventListener('change', upd); upd();
});
// بعد "حفظ وإضافة آخر": افتح نفس المودال تاني وركّز على اسم الإيميل
(function(){
 var p = new URLSearchParams(location.search).get('openbox');
 if(!p) return;
 var el = document.getElementById('addbox'+p);
 if(el && window.bootstrap){
  var m = new bootstrap.Modal(el); m.show();
  el.addEventListener('shown.bs.modal', function(){
   var inp = el.querySelector('input[name=local_part]'); if(inp) inp.focus();
  }, {once:true});
 }
}());
</script>

<div class="modal fade" id="adddom" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
 <form method="POST" action="{{ url_for('domain_add') }}">
  <div class="modal-header"><h5 class="modal-title">إضافة دومين</h5>
   <button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
  <div class="modal-body">
   <div class="mb-2"><label>اسم الدومين</label>
    <input name="name" class="form-control" placeholder="team360.sa" required dir="ltr">
    <div class="form-text">اسم الدومين بس — من غير @ ومن غير أي اسم قبله.</div></div>
  </div>
  <div class="modal-footer"><button class="btn btn-primary">حفظ</button></div>
 </form>
</div></div></div>
</div>
{% endblock %}
"""

IBOX_LIST_TPL = """
{% extends "base.html" %}{% block content %}
<div class="page-head">
 <div><h1>البريد الداخلي <span class="badge bg-secondary">{{ boxes|length }}</span></h1>
  <div class="sub">صناديق البريد الداخلية — كل صندوق بيعرض الرسائل المسلَّمة له داخل البرنامج.</div></div>
</div>
<div class="table-wrap">
<table class="table align-middle">
 <thead><tr><th>الصندوق</th><th>الاسم</th><th>النوع</th><th>غير مقروء</th><th></th></tr></thead>
 <tbody>
 {% for b in boxes %}
 <tr>
  <td class="fw-semibold" dir="ltr">{{ b.email }}</td>
  <td>{{ b.name }}</td>
  <td>{% if b.role=='main' %}<span class="badge bg-info text-dark">رئيسي</span>
      {% else %}<span class="badge bg-light text-dark">فرعي</span>{% endif %}</td>
  <td>{% if b.unread %}<span class="badge bg-danger">{{ b.unread }}</span>{% else %}—{% endif %}</td>
  <td><a class="btn btn-sm btn-outline-primary" href="{{ url_for('ibox_view', email=b.email) }}">
   <i class="bi bi-envelope"></i> افتح</a></td>
 </tr>
 {% else %}<tr><td colspan="5" class="mlist-empty">مفيش صناديق داخلية — أنشئ إيميلات من صفحة الدومينات</td></tr>{% endfor %}
 </tbody>
</table>
</div>
{% endblock %}
"""

IBOX_TPL = """
{% extends "base.html" %}{% block content %}
<div class="page-head">
 <div><h1 dir="ltr">{{ box_email }}</h1>
  <div class="sub">صندوق بريد داخلي</div></div>
 <a class="btn btn-outline-secondary" href="{{ url_for('ibox_home') }}"><i class="bi bi-arrow-right"></i> كل الصناديق</a>
</div>
<div class="d-flex gap-2 mb-3">
 <a class="btn btn-sm {{ 'btn-primary' if folder=='inbox' else 'btn-outline-primary' }}"
    href="{{ url_for('ibox_view', email=box_email) }}">الوارد {% if unread %}<span class="badge bg-light text-dark">{{ unread }}</span>{% endif %}</a>
 <a class="btn btn-sm {{ 'btn-primary' if folder=='sent' else 'btn-outline-primary' }}"
    href="{{ url_for('ibox_view', email=box_email, folder='sent') }}">المُرسَل</a>
</div>
<div class="table-wrap">
<table class="table align-middle">
 <thead><tr><th style="width:60%">{{ 'من' if folder=='inbox' else 'إلى' }}</th><th>الموضوع</th><th>التاريخ</th></tr></thead>
 <tbody>
 {% for m in msgs %}
 <tr style="{{ 'font-weight:600' if (folder=='inbox' and not m.is_read) }}">
  <td dir="ltr">{{ (m.from_name or m.from_email) if folder=='inbox' else m.to_email }}</td>
  <td><a href="{{ url_for('ibox_message', email=box_email, mid=m.id) }}">{{ m.subject or '(بدون موضوع)' }}</a></td>
  <td class="small text-muted">{{ m.created_at|mdate }}</td>
 </tr>
 {% else %}<tr><td colspan="3" class="mlist-empty">مفيش رسائل</td></tr>{% endfor %}
 </tbody>
</table>
</div>
{% endblock %}
"""

IBOX_MSG_TPL = """
{% extends "base.html" %}{% block content %}
{% set fromname = m.from_name or m.from_email %}
<div class="d-flex align-items-center gap-2 mb-3">
 <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('ibox_view', email=box_email) }}">
  <i class="bi bi-arrow-right"></i> رجوع</a>
 <a class="btn btn-sm btn-outline-primary" href="{{ url_for('ibox_view', email=box_email) }}"><i class="bi bi-reply"></i> رد</a>
 <a class="btn btn-sm btn-outline-primary" href="{{ url_for('ibox_view', email=box_email) }}"><i class="bi bi-reply-all"></i> رد على الكل</a>
 <a class="btn btn-sm btn-outline-primary" href="{{ url_for('ibox_view', email=box_email) }}"><i class="bi bi-forward"></i> إعادة توجيه</a>
</div>
<div class="ol-msg">
 <div class="ol-subject">{{ m.subject or '(بدون موضوع)' }}</div>
 <div class="ol-head">
  <div class="ol-avatar">{{ (fromname[:2]).upper() }}</div>
  <div class="ol-meta">
   <div class="ol-from">{{ fromname }}</div>
   <div class="ol-to">إلى: {{ m.to_email }}</div>
  </div>
  <div class="ol-date">{{ m.created_at|fulldate }}</div>
 </div>
 <div class="ol-body" dir="auto">{{ m.body|safe }}</div>
</div>
<style>
.ol-msg{background:#fff;border:1px solid #e2e5ea;border-radius:8px;max-width:900px;
 box-shadow:0 1px 3px rgba(0,0,0,.06);overflow:hidden}
.ol-subject{font-size:1.35rem;font-weight:600;padding:16px 20px 8px;color:#1a1a1a}
.ol-head{display:flex;align-items:center;gap:12px;padding:8px 20px 14px;border-bottom:1px solid #eceef1}
.ol-avatar{width:44px;height:44px;border-radius:50%;background:#0f6cbd;color:#fff;
 display:flex;align-items:center;justify-content:center;font-weight:600;font-size:1rem;flex:0 0 auto}
.ol-meta{flex:1;min-width:0}
.ol-from{font-weight:600;color:#1a1a1a}
.ol-to{font-size:.85rem;color:#616161}
.ol-date{font-size:.82rem;color:#616161;white-space:nowrap;align-self:flex-start;padding-top:4px}
.ol-body{padding:20px;line-height:1.7;color:#242424;min-height:180px}
.ol-body img{max-width:100%}
</style>
{% endblock %}
"""

BACKUPS_TPL = """
{% extends "base.html" %}{% block content %}
<div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-3">
 <div><h1 class="mb-0"><i class="bi bi-hdd-stack-fill text-primary"></i> النسخ الاحتياطي</h1>
  <div class="text-muted small">قاعدة البيانات: <b>{{ engine }}</b> ·
   يُحتفظ تلقائياً بآخر {{ keep }} نسخة</div></div>
 <form method="post" action="{{ url_for('backup_now') }}">
  <button class="btn btn-primary"><i class="bi bi-plus-circle"></i> نسخ احتياطي الآن</button></form>
</div>

<div class="alert alert-light border small d-flex gap-2 align-items-start" style="max-width:820px">
 <i class="bi bi-info-circle-fill text-primary mt-1"></i>
 <div>النسخ التلقائية تُنشأ يومياً بواسطة خدمة <code>db-backup</code> وتُخزَّن في نفس
  السيرفر (volume مستقل عن قاعدة البيانات). تقدر كمان تعمل نسخة فورية بالزر أعلاه،
  أو تحمّل أي نسخة لجهازك.
  {% if engine == 'PostgreSQL' %}<br>الاستعادة (على السيرفر):
  <code dir="ltr">pg_restore -h db -U emailmgr -d emailmanager --clean --if-exists /backups/الملف.dump</code>
  {% endif %}</div>
</div>

<div class="card" style="max-width:820px"><div class="card-body p-0">
 <div class="table-wrap"><table class="table table-hover mb-0 align-middle">
  <thead><tr><th>الملف</th><th>التاريخ</th><th>الحجم</th>
   <th class="text-end">إجراءات</th></tr></thead>
  <tbody>
  {% for b in backups %}
   <tr>
    <td class="small" dir="ltr">{{ b.name }}</td>
    <td class="small text-muted">{{ b.mtime }}</td>
    <td class="small">{{ b.size_bytes|filesize }}</td>
    <td class="text-end text-nowrap">
     <button class="btn btn-sm btn-outline-danger"
        onclick="askRestore('{{ b.name }}')" title="استعادة هذه النسخة">
        <i class="bi bi-arrow-counterclockwise"></i> استعادة</button>
     <a class="btn btn-sm btn-outline-primary"
        href="{{ url_for('backup_download', name=b.name) }}" title="تحميل">
        <i class="bi bi-download"></i></a></td>
   </tr>
  {% else %}
   <tr><td colspan="4" class="text-center text-muted py-4">
    لا توجد نسخ احتياطية بعد — اضغط «نسخ احتياطي الآن».</td></tr>
  {% endfor %}
  </tbody>
 </table></div>
</div></div>

<form id="restoreForm" method="post" action="{{ url_for('backup_restore') }}" class="d-none">
 <input type="hidden" name="name" id="restoreName">
 <input type="hidden" name="confirm" id="restoreConfirm">
</form>

<div class="card border-danger mt-4" style="max-width:820px">
 <div class="card-header bg-danger text-white py-2">
  <i class="bi bi-exclamation-octagon-fill"></i> منطقة الخطر — مسح الرسائل للبدء من جديد</div>
 <div class="card-body">
  <div class="small text-muted mb-2">يمسح <b>كل الرسائل المرسلة والمستقبلة</b> لكل الصناديق
   (الرئيسي والفرعي) + طابور وسجل الردود + سجل الإرسال — عشان تبدأ تست نظيف.
   <b>الحسابات والموظفون والحملات والقوالب تفضل زي ما هي.</b>
   (تُؤخذ نسخة أمان تلقائية قبل المسح.)</div>
  <form method="post" action="{{ url_for('reset_mail_data') }}"
        onsubmit="return confirm('⚠️ مسح كل الرسائل المرسلة والمستقبلة للجميع؟ لا يمكن التراجع (لكن فيه نسخة أمان).');">
   <label class="small d-block mb-2">
    <input type="checkbox" name="reset_campaigns" value="1">
    صفّر حالة الحملات كمان (علشان أقدر أبعتها من جديد)</label>
   <div class="d-flex gap-2 align-items-center flex-wrap">
    <input name="confirm" class="form-control form-control-sm" style="max-width:220px"
       placeholder="اكتب: مسح" autocomplete="off" required>
    <button class="btn btn-danger btn-sm"><i class="bi bi-trash3"></i> مسح الرسائل الآن</button>
   </div>
  </form>
  <hr>
  <div class="small text-muted mb-2"><b>تنظيف التكرار:</b> يُبقي <b>رسالة واحدة ورد واحد
   لكل موظف</b> لكل حملة، ويحذف المكرر فقط (من غير ما يمسح الباقي). مفيد لو ظهرت أرقام زيادة.</div>
  <form method="post" action="{{ url_for('dedup_mail_data') }}"
        onsubmit="return confirm('إزالة الرسائل/الردود المكررة والإبقاء على واحدة لكل موظف؟ (فيه نسخة أمان).');">
   <div class="d-flex gap-2 align-items-center flex-wrap">
    <input name="confirm" class="form-control form-control-sm" style="max-width:220px"
       placeholder="اكتب: تنظيف" autocomplete="off" required>
    <button class="btn btn-warning btn-sm"><i class="bi bi-magic"></i> إزالة التكرار الآن</button>
   </div>
  </form>
 </div>
</div>
<script>
function askRestore(name){
  var msg = "⚠️ تحذير: الاستعادة ستستبدل كل البيانات الحالية بمحتوى النسخة:\\n\\n"
    + name + "\\n\\n"
    + "(سيتم أخذ نسخة أمان تلقائية قبل الاستعادة)\\n\\n"
    + "للتأكيد اكتب كلمة: استعادة";
  var ans = prompt(msg, "");
  if(ans === null) return;
  if(ans.trim() !== "استعادة"){ alert("كلمة التأكيد غير صحيحة — أُلغيت الاستعادة."); return; }
  document.getElementById('restoreName').value = name;
  document.getElementById('restoreConfirm').value = ans.trim();
  document.getElementById('restoreForm').submit();
}
</script>
{% endblock %}
"""

app.jinja_loader = ChoiceLoader([
    DictLoader({
        "base.html": BASE_TPL,
        "backups.html": BACKUPS_TPL,
        "login.html": LOGIN_TPL,
        "users.html": USERS_TPL,
        "me.html": ME_TPL,
        "index.html": INDEX_TPL,
        "accounts.html": ACCOUNTS_TPL,
        "employees.html": EMPLOYEES_TPL,
        "templates.html": TEMPLATES_TPL,
        "msg_templates.html": MSG_TEMPLATES_TPL,
        "campaigns.html": CAMPAIGNS_TPL,
        "quicksend.html": QUICKSEND_TPL,
        "distribution.html": DISTRIBUTION_TPL,
        "campaign_detail.html": CAMPAIGN_DETAIL_TPL,
        "schedule.html": SCHEDULE_TPL,
        "autoreply.html": AUTOREPLY_TPL,
        "reverse.html": REVERSE_TPL,
        "mailboxes.html": MAILBOXES_TPL,
        "mail.html": MAIL_TPL,
        "mail_message.html": MAIL_MSG_TPL,
        "mail_frag.html": MAIL_FRAG_TPL,
        "mail_compose.html": MAIL_COMPOSE_TPL,
        "server.html": SERVER_TPL,
        "domains.html": DOMAINS_TPL,
        "ibox_list.html": IBOX_LIST_TPL,
        "ibox.html": IBOX_TPL,
        "ibox_msg.html": IBOX_MSG_TPL,
    }),
    app.jinja_loader,
])


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    conn = get_connection()
    u = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
    conn.close()
    return u


PUBLIC_ENDPOINTS = {"login", "static"}
EMPLOYEE_ENDPOINTS = {"logout", "me", "me_settings", "me_password",
                      "mail_home", "mail_view", "mail_message_view",
                      "mail_attachment_dl", "mail_action", "mail_compose",
                      "api_mailbox_counts"}


@app.before_request
def _auth_guard():
    ep = request.endpoint
    if ep is None or ep in PUBLIC_ENDPOINTS:
        return
    u = current_user()
    if not u:
        return redirect(url_for("login", next=request.full_path))
    request.user = u
    if u["role"] != "admin" and ep not in EMPLOYEE_ENDPOINTS:
        return redirect(url_for("me"))


@app.context_processor
def inject_globals():
    return {"crypto_ok": HAVE_CRYPTO, "title": "Email Manager", "user": current_user(),
            "app_version": APP_VERSION}


def render(tpl, title, **kw):
    return render_template(tpl, title=title, **kw)


@app.template_filter("snippet")
def _snippet(text, n=110):
    t = " ".join((text or "").split())
    return (t[:n] + "…") if len(t) > n else t


@app.template_filter("filesize")
def _filesize(n):
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return ""
    for unit in ("بايت", "كيلوبايت", "ميجابايت", "جيجابايت"):
        if n < 1024 or unit == "جيجابايت":
            return ("%d %s" % (n, unit)) if unit == "بايت" else ("%.1f %s" % (n, unit))
        n /= 1024
    return ""


@app.template_filter("mdate")
def _mdate(iso):
    try:
        dt = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return iso or ""
    now = datetime.now()
    if dt.date() == now.date():
        return dt.strftime("%H:%M")
    if dt.year == now.year:
        return dt.strftime("%d/%m")
    return dt.strftime("%Y/%m/%d")


_AR_DAYS = ["الاثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت", "الأحد"]


@app.template_filter("dategroup")
def _dategroup(iso):
    """مجموعة تاريخ بأسلوب أوتلوك: اليوم / أمس / هذا الأسبوع / ..."""
    try:
        dt = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return "أقدم"
    today = datetime.now().date()
    d = dt.date()
    diff = (today - d).days
    if diff <= 0:
        return "اليوم"
    if diff == 1:
        return "أمس"
    if diff <= 7:
        return "هذا الأسبوع"
    if diff <= 14:
        return "الأسبوع الماضي"
    if diff <= 31:
        return "هذا الشهر"
    return "أقدم"


@app.template_filter("fulldate")
def _fulldate(iso):
    """تاريخ ووقت كامل بأسلوب أوتلوك: اليوم DD/MM/YYYY HH:MM ص/م."""
    try:
        dt = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return iso or ""
    ampm = "ص" if dt.hour < 12 else "م"
    h12 = dt.hour % 12 or 12
    return "%s %02d/%02d/%04d %d:%02d %s" % (
        _AR_DAYS[dt.weekday()], dt.day, dt.month, dt.year, h12, dt.minute, ampm)


# ------------------------------------------------------------------ الدومينات والصناديق (بريد داخلي)
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_LOCAL_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")


@app.route("/domains")
def domains_page():
    conn = get_connection()
    doms = []
    accounts = conn.execute(
        "SELECT id, email, display_name FROM accounts ORDER BY email").fetchall()
    acc_by_id = {a["id"]: (a["display_name"] or a["email"]) for a in accounts}
    for d in conn.execute("SELECT * FROM mail_domains ORDER BY name").fetchall():
        rec = dict(d)
        suffix = "@" + d["name"]
        rec["mains"] = conn.execute(
            "SELECT * FROM accounts WHERE email LIKE ? ORDER BY email",
            ("%" + suffix,)).fetchall()
        subs = conn.execute(
            "SELECT * FROM employees WHERE email LIKE ? ORDER BY email",
            ("%" + suffix,)).fetchall()
        rec["subs"] = [dict(s, owner_name=acc_by_id.get(s["owner_account_id"])) for s in subs]
        doms.append(rec)
    conn.close()
    try:
        openbox = int(request.args.get("openbox", ""))
    except (TypeError, ValueError):
        openbox = None
    return render("domains.html", "الدومينات والصناديق", domains=doms,
                  accounts=accounts, openbox=openbox)


@app.route("/domains/export")
def domains_export():
    """تصدير كل الصناديق (رئيسي + فرعي) كـ CSV — email,name,type,domain."""
    conn = get_connection()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["email", "name", "type", "domain"])
    for a in conn.execute("SELECT email, display_name FROM accounts ORDER BY email"):
        dom = a["email"].split("@", 1)[1] if "@" in a["email"] else ""
        w.writerow([a["email"], a["display_name"] or "", "main", dom])
    for e in conn.execute("SELECT email, name FROM employees ORDER BY email"):
        dom = e["email"].split("@", 1)[1] if "@" in e["email"] else ""
        w.writerow([e["email"], e["name"] or "", "sub", dom])
    conn.close()
    return Response(buf.getvalue().encode("utf-8-sig"), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=mailboxes.csv"})


@app.route("/domains/import", methods=["POST"])
def domains_import():
    """استيراد إيميلات من CSV: email[,name][,type main/sub][,password].
    كل إيميل ينزل تحت دومينه (يُنشأ الدومين لو مش موجود)، والفرعي يتربط بالرئيسي."""
    file = request.files.get("file")
    if not file or not file.filename:
        flash("اختر ملف CSV الأول", "warning")
        return redirect(url_for("domains_page"))
    raw = file.stream.read().decode("utf-8-sig", errors="ignore")
    try:
        dialect = csv.Sniffer().sniff(raw[:2048], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(raw), dialect)

    # 1) تحليل الصفوف
    rows = []
    for i, row in enumerate(reader):
        if not row:
            continue
        cells = [c.strip() for c in row]
        email = (cells[0] or "").lower()
        if i == 0 and "@" not in email:      # صف عنوان
            continue
        name = cells[1] if len(cells) > 1 else ""
        typ = (cells[2].lower() if len(cells) > 2 else "")
        pw = cells[3] if len(cells) > 3 else ""
        rows.append((email, name, typ, pw))

    conn = get_connection()
    cur = conn.cursor()
    added = skipped = new_doms = 0

    def ensure_domain(dom):
        nonlocal new_doms
        r = cur.execute("SELECT id FROM mail_domains WHERE name=?", (dom,)).fetchone()
        if r:
            return
        cur.execute("INSERT INTO mail_domains (name) VALUES (?)", (dom,))
        new_doms += 1

    def is_dup(email):
        return (cur.execute("SELECT 1 FROM accounts WHERE email=?", (email,)).fetchone()
                or cur.execute("SELECT 1 FROM employees WHERE email=?", (email,)).fetchone())

    def valid(email):
        if "@" not in email:
            return None
        local, dom = email.split("@", 1)
        if not _LOCAL_RE.match(local) or not _DOMAIN_RE.match(dom):
            return None
        return local, dom

    mains = [r for r in rows if r[2] in ("main", "رئيسي", "رئيسى")]
    subs = [r for r in rows if r not in mains]

    # 2) الحسابات الرئيسية أولاً (عشان الفرعيين يتربطوا بيها)
    for email, name, _typ, pw in mains:
        v = valid(email)
        if not v or is_dup(email):
            skipped += 1
            continue
        _local, dom = v
        ensure_domain(dom)
        cur.execute(
            """INSERT INTO accounts (email, display_name, password, smtp_server, smtp_port,
                                     imap_server, imap_port, security, signature, logo,
                                     internal, verify_ok)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'none', '', '', 1, 1)""",
            (email, name, encrypt_secret(pw or DEFAULT_MAILBOX_PASS),
             LOCAL_MAIL_HOST, INT_SMTP_PORT, LOCAL_MAIL_HOST, INT_IMAP_PORT))
        added += 1

    # 3) الفرعيين — يتربطوا بالحساب الرئيسي لدومينهم
    for email, name, _typ, pw in subs:
        v = valid(email)
        if not v or is_dup(email):
            skipped += 1
            continue
        local, dom = v
        ensure_domain(dom)
        m = cur.execute("SELECT id FROM accounts WHERE email LIKE ? ORDER BY id LIMIT 1",
                        ("%@" + dom,)).fetchone()
        owner = m["id"] if m else None
        cur.execute(
            """INSERT INTO employees (name, email, signature, logo, password, owner_account_id)
               VALUES (?, ?, '', '', ?, ?)""",
            (name or local, email, encrypt_secret(pw or DEFAULT_MAILBOX_PASS), owner))
        added += 1

    conn.commit()
    conn.close()
    flash(f"استيراد: {added} إيميل جديد · {new_doms} دومين جديد · {skipped} متخطّى (مكرر/غير صالح)",
          "success")
    return redirect(url_for("domains_page"))


@app.route("/domains/add", methods=["POST"])
def domain_add():
    name = request.form.get("name", "").strip().lower()
    if name.startswith("@"):
        name = name[1:]
    if "@" in name or not _DOMAIN_RE.match(name):
        flash("اسم دومين غير صالح — اكتب زي team360.sa بدون @ وبدون أي اسم قبله", "error")
        return redirect(url_for("domains_page"))
    conn = get_connection()
    try:
        conn.execute("INSERT INTO mail_domains (name) VALUES (?)", (name,))
        conn.commit()
        flash(f"تمت إضافة الدومين {name}", "success")
    except sqlite3.IntegrityError:
        flash("الدومين مُضاف مسبقاً", "error")
    conn.close()
    return redirect(url_for("domains_page"))


@app.route("/domains/<int:did>/delete")
def domain_delete(did):
    conn = get_connection()
    conn.execute("DELETE FROM mail_domains WHERE id=?", (did,))
    conn.commit()
    conn.close()
    flash("تم حذف الدومين وكل صناديقه", "info")
    return redirect(url_for("domains_page"))


# منفذ سيرفر البريد المحلي الافتراضي (نفس الجهاز) — يُستخدم عند إنشاء صندوق من صفحة الدومينات
LOCAL_MAIL_HOST = os.environ.get("EM_LOCAL_MAIL_HOST", "127.0.0.1")


@app.route("/domains/<int:did>/boxes/add", methods=["POST"])
def mailbox_add(did):
    f = request.form
    local = f.get("local_part", "").strip().lower()
    if local.endswith("@"):
        local = local[:-1]
    if "@" in local or not _LOCAL_RE.match(local):
        flash("اسم الصندوق غير صالح — اكتب الجزء قبل الـ@ فقط (زي ahmed)", "error")
        return redirect(url_for("domains_page"))
    conn = get_connection()
    dom = conn.execute("SELECT * FROM mail_domains WHERE id=?", (did,)).fetchone()
    if not dom:
        conn.close()
        abort(404)
    email = f"{local}@{dom['name']}"
    display_name = f.get("display_name", "").strip()
    signature = f.get("signature", "").strip()
    logo = _logo_data_uri(request.files.get("logo"))
    pw = f.get("password", "") or DEFAULT_MAILBOX_PASS   # افتراضية 022001 لو فاضية
    enc_pw = encrypt_secret(pw)
    role = "main" if f.get("role") == "main" else "sub"

    # تحقّق مبكر من التكرار عبر الجدولين
    dup = (conn.execute("SELECT 1 FROM accounts WHERE email=?", (email,)).fetchone()
           or conn.execute("SELECT 1 FROM employees WHERE email=?", (email,)).fetchone())
    if dup:
        conn.close()
        flash("الإيميل مُضاف مسبقاً", "error")
        return redirect(url_for("domains_page"))

    if role == "main":
        # يروح «الحسابات المرسِلة» — إعدادات سيرفر البريد المحلي (نفس الجهاز)
        cur = conn.execute(
            """INSERT INTO accounts (email, display_name, password, smtp_server, smtp_port,
                                     imap_server, imap_port, security, signature, logo,
                                     internal, verify_ok)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'none', ?, ?, 1, 1)""",
            (email, display_name, enc_pw, LOCAL_MAIL_HOST, INT_SMTP_PORT,
             LOCAL_MAIL_HOST, INT_IMAP_PORT, signature, logo))
        acc_id = cur.lastrowid
        conn.commit()
        conn.close()
        flash(f"تمت إضافة {email} كحساب رئيسي داخلي (الحسابات المرسِلة)", "success")
    else:
        owner_raw = f.get("owner_account_id", "").strip()
        owner_id = int(owner_raw) if owner_raw.isdigit() else None
        if owner_id is None:
            # ربط تلقائي بالحساب الرئيسي بتاع نفس الدومين
            m = conn.execute(
                "SELECT id FROM accounts WHERE email LIKE ? ORDER BY id LIMIT 1",
                ("%@" + dom["name"],)).fetchone()
            owner_id = m["id"] if m else None
        conn.execute(
            """INSERT INTO employees (name, email, signature, logo, password, owner_account_id,
               iqama, emp_number)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (display_name or local, email, signature, logo, enc_pw, owner_id,
             f.get("iqama", "").strip(), f.get("emp_number", "").strip()))
        conn.commit()
        conn.close()
        if owner_id:
            flash(f"تمت إضافة {email} كموظف فرعي — مربوط تلقائياً بالحساب الرئيسي للدومين", "success")
        else:
            flash(f"تمت إضافة {email} كموظف فرعي (مفيش حساب رئيسي للدومين ده لسه)", "success")
    # "حفظ وإضافة آخر" — يرجّع نفس المودال مفتوح لنفس الدومين
    if f.get("again") == "1":
        return redirect(url_for("domains_page", openbox=did))
    return redirect(url_for("domains_page", _anchor="dom%d" % did))


@app.route("/domains/boxes/<kind>/<int:bid>/delete")
def mailbox_delete(kind, bid):
    conn = get_connection()
    if kind == "main":
        conn.execute("DELETE FROM accounts WHERE id=?", (bid,))
    else:
        conn.execute("DELETE FROM employees WHERE id=?", (bid,))
    conn.commit()
    conn.close()
    flash("تم حذف الصندوق", "info")
    return redirect(url_for("domains_page"))


# ------------------------------------------------------------------ البريد الداخلي (viewer)
def _internal_boxes(conn):
    """كل الصناديق الداخلية: الحسابات الرئيسية الداخلية + الموظفين، مع عدّاد غير المقروء."""
    boxes = []
    for a in conn.execute("SELECT email, display_name FROM accounts WHERE internal=1 ORDER BY email"):
        boxes.append({"email": a["email"], "name": a["display_name"] or a["email"], "role": "main"})
    for e in conn.execute("SELECT email, name FROM employees ORDER BY email"):
        boxes.append({"email": e["email"], "name": e["name"] or e["email"], "role": "sub"})
    for b in boxes:
        b["unread"] = conn.execute(
            "SELECT COUNT(*) c FROM mail_messages WHERE box_email=? AND folder='inbox' AND is_read=0",
            (b["email"],)).fetchone()["c"]
    return boxes


@app.route("/ibox")
def ibox_home():
    conn = get_connection()
    boxes = _internal_boxes(conn)
    conn.close()
    return render("ibox_list.html", "البريد الداخلي", boxes=boxes)


@app.route("/ibox/<path:email>")
def ibox_view(email):
    folder = request.args.get("folder", "inbox")
    folder = "sent" if folder == "sent" else "inbox"
    conn = get_connection()
    msgs = conn.execute(
        """SELECT * FROM mail_messages WHERE box_email=? AND folder=?
           ORDER BY created_at DESC, id DESC""", (email.lower(), folder)).fetchall()
    unread = conn.execute(
        "SELECT COUNT(*) c FROM mail_messages WHERE box_email=? AND folder='inbox' AND is_read=0",
        (email.lower(),)).fetchone()["c"]
    conn.close()
    return render("ibox.html", "صندوق " + email, box_email=email, folder=folder,
                  msgs=msgs, unread=unread)


@app.route("/ibox/<path:email>/m/<int:mid>")
def ibox_message(email, mid):
    conn = get_connection()
    m = conn.execute("SELECT * FROM mail_messages WHERE id=? AND box_email=?",
                     (mid, email.lower())).fetchone()
    if not m:
        conn.close()
        abort(404)
    if not m["is_read"]:
        conn.execute("UPDATE mail_messages SET is_read=1 WHERE id=?", (mid,))
        conn.commit()
    conn.close()
    return render("ibox_msg.html", "رسالة", box_email=email, m=m)


# ------------------------------------------------------------------ تسجيل الدخول
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        conn = get_connection()
        u = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if u and verify_password(pw, u["password_hash"]):
            conn.close()
            session["uid"] = u["id"]
            session.permanent = True
            nxt = request.args.get("next") or ""
            if nxt.startswith("/") and not nxt.startswith("//"):
                return redirect(nxt)
            return redirect(url_for("index") if u["role"] == "admin" else url_for("me"))

        # دخول الموظف بإيميله وكلمة مرور صندوقه مباشرة (بدون إنشاء لوج إن يدوي)
        emp = conn.execute("SELECT * FROM employees WHERE lower(email)=? AND active=1",
                           (username.lower(),)).fetchone()
        if emp and emp["password"] and decrypt_secret(emp["password"]) == pw and pw:
            # اضمن وجود صف مستخدم لهذا الموظف (يُنشأ تلقائياً أول مرة)
            eu = conn.execute("SELECT * FROM users WHERE employee_id=?", (emp["id"],)).fetchone()
            if eu is None:
                cur = conn.execute(
                    """INSERT INTO users (username, password_hash, role, employee_id, full_name, active)
                       VALUES (?, ?, 'employee', ?, ?, 1)""",
                    (emp["email"], hash_password(pw), emp["id"], emp["name"]))
                uid = cur.lastrowid
            else:
                # حدّث الهاش ليطابق كلمة مرور الصندوق الحالية، وفعّله
                conn.execute("UPDATE users SET password_hash=?, active=1 WHERE id=?",
                             (hash_password(pw), eu["id"]))
                uid = eu["id"]
            conn.commit()
            conn.close()
            session["uid"] = uid
            session.permanent = True
            return redirect(url_for("me"))
        conn.close()
        flash("اسم المستخدم أو كلمة المرور غير صحيحة", "error")
    return render_template("login.html", vision2030_svg=VISION2030_SVG)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------ إدارة المستخدمين (مدير)
@app.route("/users")
def users_page():
    conn = get_connection()
    rows = conn.execute("""SELECT u.*, e.email AS emp_email FROM users u
                           LEFT JOIN employees e ON e.id = u.employee_id
                           ORDER BY u.role, u.username""").fetchall()
    employees = conn.execute("SELECT id, name, email FROM employees ORDER BY name").fetchall()
    conn.close()
    return render("users.html", "المستخدمون", rows=rows, employees=employees)


@app.route("/users/add", methods=["POST"])
def user_add():
    f = request.form
    role = "admin" if f.get("role") == "admin" else "employee"
    emp_id = f.get("employee_id") or None
    try:
        conn = get_connection()
        conn.execute("""INSERT INTO users (username, password_hash, role, employee_id, full_name)
                        VALUES (?, ?, ?, ?, ?)""",
                     (f["username"].strip(), hash_password(f["password"]), role,
                      int(emp_id) if emp_id else None, f.get("full_name", "").strip()))
        conn.commit()
        conn.close()
        flash("تمت إضافة المستخدم", "success")
    except sqlite3.IntegrityError:
        flash("اسم المستخدم موجود مسبقاً", "error")
    return redirect(url_for("users_page"))


@app.route("/users/<int:uid>/reset", methods=["POST"])
def user_reset(uid):
    pw = request.form.get("password", "")
    if pw:
        conn = get_connection()
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(pw), uid))
        conn.commit()
        conn.close()
        flash("تم تغيير كلمة المرور", "success")
    return redirect(url_for("users_page"))


@app.route("/users/<int:uid>/toggle")
def user_toggle(uid):
    conn = get_connection()
    row = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
    if uid == session.get("uid"):
        flash("لا يمكنك إيقاف نفسك", "error")
    elif row and row["username"] == DEFAULT_ADMIN_USER:
        flash("لا يمكن إيقاف المستخدم الرئيسي (admin)", "error")
    else:
        conn.execute("UPDATE users SET active = 1 - active WHERE id=?", (uid,))
        conn.commit()
    conn.close()
    return redirect(url_for("users_page"))


@app.route("/users/<int:uid>/delete")
def user_delete(uid):
    if uid == session.get("uid"):
        flash("لا يمكنك حذف نفسك", "error")
        return redirect(url_for("users_page"))
    conn = get_connection()
    row = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
    if row and row["username"] == DEFAULT_ADMIN_USER:
        conn.close()
        flash("لا يمكن حذف المستخدم الرئيسي (admin)", "error")
        return redirect(url_for("users_page"))
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    flash("تم حذف المستخدم", "info")
    return redirect(url_for("users_page"))


# ------------------------------------------------------------------ بوابة الموظف
def _my_employee(conn):
    u = current_user()
    if not u or not u["employee_id"]:
        return None
    return conn.execute("SELECT * FROM employees WHERE id=?", (u["employee_id"],)).fetchone()


@app.route("/me")
def me():
    """صندوق الموظف = نفس واجهة البريد الحيّة على صندوقه هو."""
    conn = get_connection()
    emp = _my_employee(conn)
    conn.close()
    if not emp:
        flash("حسابك غير مرتبط بموظف — راجع المدير", "error")
        return redirect(url_for("me_settings"))
    if not (emp["password"] or "").strip():
        flash("لا توجد بيانات دخول لصندوق بريدك — راجع المدير", "warning")
        return redirect(url_for("me_settings"))
    q = (request.args.get("q") or "").strip()
    return redirect(url_for("mail_view", kind="employee", oid=emp["id"], q=q or None))


@app.route("/me/settings")
def me_settings():
    conn = get_connection()
    emp = _my_employee(conn)
    conn.close()
    return render("me.html", "إعداداتي", emp=emp)


@app.route("/me/password", methods=["POST"])
def me_password():
    u = current_user()
    old = request.form.get("old", "")
    new = request.form.get("new", "")
    if not verify_password(old, u["password_hash"]):
        flash("كلمة المرور الحالية غير صحيحة", "error")
    elif len(new) < 4:
        flash("كلمة المرور الجديدة قصيرة", "error")
    else:
        conn = get_connection()
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new), u["id"]))
        # غيّر كلمة مرور صندوق الموظف على السيرفر كمان (لو المستخدم مرتبط بموظف)
        if u["employee_id"]:
            conn.execute("UPDATE employees SET password=? WHERE id=?",
                         (encrypt_secret(new), u["employee_id"]))
            close_mail_sessions()      # اقطع أي جلسة IMAP قديمة بالباسورد القديم
        conn.commit()
        conn.close()
        flash("تم تغيير كلمة المرور — على البرنامج والسيرفر معاً", "success")
    return redirect(url_for("me_settings"))


# ------------------------------------------------------------------ لوحة التحكم
@app.route("/")
def index():
    conn = get_connection()
    q = conn.execute
    total_emp = q("SELECT COUNT(*) c FROM employees").fetchone()["c"]
    total_acc = q("SELECT COUNT(*) c FROM accounts").fetchone()["c"]
    sent_ct = q("SELECT COUNT(*) c FROM sent_emails WHERE status='sent'").fetchone()["c"]
    failed_ct = q("SELECT COUNT(*) c FROM sent_emails WHERE status='failed'").fetchone()["c"]
    pending_ct = q("SELECT COUNT(*) c FROM campaign_recipients WHERE status='pending'").fetchone()["c"]
    groups_ct = q("SELECT COUNT(DISTINCT owner_account_id) c FROM employees "
                  "WHERE owner_account_id IS NOT NULL").fetchone()["c"]
    recent = q("SELECT sent_at, to_email, subject, status, error FROM sent_emails "
               "ORDER BY id DESC LIMIT 10").fetchall()
    total_msgs = q("SELECT COUNT(*) c FROM mail_messages").fetchone()["c"]
    total_reps = q("SELECT COUNT(*) c FROM emp_replies WHERE status='sent'").fetchone()["c"]
    db_info = {"engine": "PostgreSQL" if USE_PG else "SQLite",
               "messages": total_msgs, "replies": total_reps}
    if USE_PG:
        try:
            db_info["size"] = q("SELECT pg_size_pretty(pg_database_size(current_database())) s"
                                ).fetchone()["s"]
        except Exception:  # noqa: BLE001
            db_info["size"] = "—"
    _bks = list_backups()
    db_info["last_backup"] = _bks[0]["mtime"] if _bks else None
    db_info["backup_count"] = len(_bks)
    # ---- تنبيه ذكي: موظفون «مش شغّالين» ----
    emp_alerts = []
    # 1) صندوقه مش متصل رغم إننا جرّبنا الاتصال (نشط + عنده كلمة مرور + آخر فحص فشل)
    for r in q("""SELECT name, email, emp_last_check FROM employees
                  WHERE active=1 AND password != '' AND emp_connected=0
                    AND emp_last_check IS NOT NULL
                  ORDER BY name""").fetchall():
        emp_alerts.append({"name": r["name"], "email": r["email"],
                           "reason": "الصندوق مش متصل", "when": r["emp_last_check"]})
    # 2) فشل في الرد التلقائي (ردود عكسية فشلت)
    for r in q("""SELECT e.name, e.email, COUNT(*) c, MAX(rq.sent_at) w
                  FROM reverse_queue rq JOIN employees e ON e.id=rq.employee_id
                  WHERE rq.status='failed'
                  GROUP BY e.id, e.name, e.email ORDER BY c DESC""").fetchall():
        emp_alerts.append({"name": r["name"], "email": r["email"],
                           "reason": "فشل الرد التلقائي (%d مرة)" % r["c"], "when": r["w"]})
    conn.close()
    with _health_lock:
        health = {"db": dict(_health["db"]), "smtp": dict(_health["smtp"]),
                  "imap": dict(_health["imap"]), "last_check": _health["last_check"],
                  "fixes": list(_health["fixes"][:5])}
    cards = [
        {"label": "الموظفين", "value": total_emp, "icon": "bi-people", "color": "#667eea",
         "href": url_for("employees")},
        {"label": "الحسابات", "value": total_acc, "icon": "bi-person-badge", "color": "#48bb78",
         "href": url_for("accounts")},
        {"label": "تم الإرسال", "value": sent_ct, "icon": "bi-check-circle", "color": "#38b2ac",
         "href": url_for("campaigns")},
        {"label": "بانتظار الإرسال", "value": pending_ct, "icon": "bi-hourglass-split",
         "color": "#ed8936", "href": url_for("campaigns")},
        {"label": "فشل الإرسال", "value": failed_ct, "icon": "bi-x-circle", "color": "#f56565",
         "href": url_for("campaigns")},
        {"label": "أقسام الإرسال", "value": groups_ct, "icon": "bi-diagram-3",
         "color": "#805ad5", "href": url_for("distribution")},
    ]
    return render("index.html", "لوحة التحكم", cards=cards, recent=recent, db_info=db_info,
                  health=health, emp_alerts=emp_alerts)


# ------------------------------------------------------------------ النسخ الاحتياطي
def list_backups():
    """قائمة النسخ الاحتياطية (الأحدث أولاً)."""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
    except OSError:
        return []
    items = []
    for p in glob.glob(os.path.join(BACKUP_DIR, "emailmanager_*.*")):
        try:
            st = os.stat(p)
        except OSError:
            continue
        items.append({
            "name": os.path.basename(p),
            "size_bytes": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "ts": st.st_mtime,
        })
    items.sort(key=lambda x: x["ts"], reverse=True)
    return items


def _prune_backups():
    """يحذف النسخ الأقدم مع الإبقاء على آخر BACKUP_KEEP نسخة."""
    for old in list_backups()[BACKUP_KEEP:]:
        try:
            os.remove(os.path.join(BACKUP_DIR, old["name"]))
        except OSError:
            pass


def create_backup():
    """ينشئ نسخة احتياطية الآن. يعيد (ok, msg, filename|None)."""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
    except OSError as e:
        return False, "تعذّر إنشاء مجلد النسخ: %s" % e, None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if USE_PG:
        fname = "emailmanager_%s.dump" % ts
        path = os.path.join(BACKUP_DIR, fname)
        try:
            r = subprocess.run(
                ["pg_dump", "--dbname", PG_DSN, "-F", "c", "-f", path],
                capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            return False, "أداة pg_dump غير مثبتة داخل الحاوية", None
        except subprocess.TimeoutExpired:
            return False, "انتهت مهلة النسخ الاحتياطي", None
        if r.returncode != 0:
            try:
                os.remove(path)
            except OSError:
                pass
            return False, "فشل pg_dump: " + (r.stderr.strip()[:300] or "خطأ غير معروف"), None
    else:
        fname = "emailmanager_%s.db" % ts
        path = os.path.join(BACKUP_DIR, fname)
        try:
            src = sqlite3.connect(DB_NAME)
            dst = sqlite3.connect(path)
            with dst:
                src.backup(dst)
            dst.close()
            src.close()
        except Exception as e:  # noqa: BLE001
            return False, "فشل النسخ: %s" % e, None
    _prune_backups()
    return True, "تم إنشاء نسخة احتياطية: %s" % fname, fname


def restore_backup(name):
    """يستعيد قاعدة البيانات من نسخة احتياطية موجودة. يعيد (ok, msg).
    يأخذ نسخة أمان تلقائية قبل الاستعادة، والاستعادة ذرّية (كلها أو لا شيء)."""
    safe = os.path.basename(name)
    if not re.fullmatch(r"emailmanager_\d{8}_\d{6}\.(dump|db)", safe):
        return False, "اسم ملف غير صالح"
    path = os.path.join(BACKUP_DIR, safe)
    if not os.path.isfile(path):
        return False, "الملف غير موجود"
    # نسخة أمان قبل الاستعادة (نتجاهل فشلها حتى لا نمنع الاستعادة)
    try:
        create_backup()
    except Exception:  # noqa: BLE001
        log.exception("safety backup before restore failed")
    if USE_PG:
        if not safe.endswith(".dump"):
            return False, "هذه النسخة ليست بصيغة Postgres"
        try:
            r = subprocess.run(
                ["pg_restore", "--clean", "--if-exists", "--no-owner",
                 "--single-transaction", "--dbname", PG_DSN, path],
                capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            return False, "أداة pg_restore غير مثبتة داخل الحاوية"
        except subprocess.TimeoutExpired:
            return False, "انتهت مهلة الاستعادة"
        if r.returncode != 0:
            return False, "فشلت الاستعادة (تم الإبقاء على البيانات الحالية): " + \
                (r.stderr.strip()[:300] or "خطأ غير معروف")
    else:
        if not safe.endswith(".db"):
            return False, "هذه النسخة ليست بصيغة SQLite"
        try:
            shutil.copyfile(path, DB_NAME)
        except Exception as e:  # noqa: BLE001
            return False, "فشلت الاستعادة: %s" % e
    return True, "تمت الاستعادة بنجاح من: %s" % safe


@app.route("/backups")
def backups_page():
    return render("backups.html", "النسخ الاحتياطي",
                  backups=list_backups(),
                  engine="PostgreSQL" if USE_PG else "SQLite",
                  keep=BACKUP_KEEP)


@app.route("/backups/now", methods=["POST"])
def backup_now():
    ok, msg, _ = create_backup()
    flash(msg, "success" if ok else "error")
    return redirect(url_for("backups_page"))


@app.route("/backups/restore", methods=["POST"])
def backup_restore():
    if (request.form.get("confirm", "") or "").strip() != "استعادة":
        flash("لم تتم الاستعادة — اكتب كلمة التأكيد «استعادة» بالضبط.", "error")
        return redirect(url_for("backups_page"))
    ok, msg = restore_backup(request.form.get("name", ""))
    flash(msg, "success" if ok else "error")
    return redirect(url_for("backups_page"))


@app.route("/backups/reset-mail", methods=["POST"])
def reset_mail_data():
    """مسح كل الرسائل المرسلة والمستقبلة (الرئيسي والفرعي) للبدء من جديد.
    يأخذ نسخة أمان أولاً. اختيارياً يصفّر حالة الحملات لإعادة إرسالها."""
    f = request.form
    if (f.get("confirm", "") or "").strip() != "مسح":
        flash("لم يتم المسح — اكتب كلمة التأكيد «مسح» بالضبط.", "error")
        return redirect(url_for("backups_page"))
    # نسخة أمان قبل المسح (نتجاهل فشلها حتى لا نمنع العملية)
    try:
        create_backup()
    except Exception:  # noqa: BLE001
        log.exception("safety backup before reset-mail failed")
    conn = get_connection()
    cur = conn.cursor()

    def _count(sql):
        try:
            return cur.execute(sql).fetchone()[0]
        except Exception:  # noqa: BLE001
            return 0
    n_msgs = _count("SELECT COUNT(*) FROM mail_messages")
    n_sent = _count("SELECT COUNT(*) FROM sent_emails")
    n_rep = _count("SELECT COUNT(*) FROM emp_replies")
    for sql in ("DELETE FROM mail_messages",
                "DELETE FROM reverse_queue",
                "DELETE FROM emp_replies",
                "DELETE FROM sent_emails"):
        try:
            cur.execute(sql)
        except Exception:  # noqa: BLE001
            log.exception("reset-mail: %s", sql)
    reset_camps = f.get("reset_campaigns") == "1"
    if reset_camps:
        try:
            cur.execute("UPDATE campaign_recipients SET status='pending', attempts=0, error=NULL")
            cur.execute("UPDATE campaigns SET status='active'")
        except Exception:  # noqa: BLE001
            log.exception("reset-mail: reset campaigns")
    conn.commit()
    conn.close()
    extra = " · وأُعيد ضبط الحملات للإرسال من جديد" if reset_camps else ""
    flash("تم مسح الرسائل للبدء من جديد: %d رسالة (وارد/صادر) · %d سجل إرسال · %d رد%s "
          "(أُخذت نسخة أمان قبل المسح)" % (n_msgs, n_sent, n_rep, extra), "success")
    return redirect(url_for("backups_page"))


@app.route("/backups/dedup-mail", methods=["POST"])
def dedup_mail_data():
    """إزالة التكرار: الإبقاء على رسالة حملة واحدة لكل موظف + رد واحد، وحذف الباقي."""
    if (request.form.get("confirm", "") or "").strip() != "تنظيف":
        flash("لم يتم التنظيف — اكتب كلمة التأكيد «تنظيف» بالضبط.", "error")
        return redirect(url_for("backups_page"))
    try:
        create_backup()
    except Exception:  # noqa: BLE001
        log.exception("safety backup before dedup failed")
    conn = get_connection()
    cur = conn.cursor()
    removed = 0

    def _run(sql):
        nonlocal removed
        try:
            cur.execute(sql)
            removed += cur.rowcount if (cur.rowcount and cur.rowcount > 0) else 0
        except Exception:  # noqa: BLE001
            log.exception("dedup: %s", sql)
    # 1) رسائل الحملات: رسالة واحدة لكل (صندوق، مجلد، حملة)
    _run("""DELETE FROM mail_messages WHERE campaign_id IS NOT NULL AND id NOT IN (
              SELECT MIN(id) FROM mail_messages WHERE campaign_id IS NOT NULL
              GROUP BY box_email, folder, campaign_id)""")
    # 2) الردود: رد واحد لكل محادثة (مالك الصندوق، المجلد، المُرسِل، المُستقبِل).
    #    النسخة القديمة كانت تبعت نفس الحملة أكثر من مرة بمعرّفات مختلفة، فكل رد له
    #    in_reply_to مختلف — فنجمّع حسب طرفَي المحادثة لا حسب المعرّف، فيتبقى رد واحد
    #    لكل موظف↔حساب (في صندوق الوارد وفي صندوق الصادر على السواء).
    _run("""DELETE FROM mail_messages WHERE in_reply_to IS NOT NULL AND in_reply_to<>'' AND id NOT IN (
              SELECT MIN(id) FROM mail_messages WHERE in_reply_to IS NOT NULL AND in_reply_to<>''
              GROUP BY lower(box_email), folder, lower(from_email), lower(to_email))""")
    # 3) سجل الردود العكسية: رد واحد لكل (موظف، الحساب المُرسَل إليه)
    _run("""DELETE FROM emp_replies WHERE id NOT IN (
              SELECT MIN(id) FROM emp_replies GROUP BY employee_id, lower(sender_account))""")
    # 4) سجل الإرسال: سطر واحد لكل (حملة، موظف)
    _run("""DELETE FROM sent_emails WHERE campaign_id IS NOT NULL AND id NOT IN (
              SELECT MIN(id) FROM sent_emails WHERE campaign_id IS NOT NULL
              GROUP BY campaign_id, employee_id)""")
    conn.commit()
    conn.close()
    flash("تم التنظيف: حُذفت الرسائل/الردود المكررة (أُبقيت رسالة ورد واحد لكل موظف). "
          "أُخذت نسخة أمان قبل التنظيف.", "success")
    return redirect(url_for("backups_page"))


@app.route("/backups/download/<name>")
def backup_download(name):
    # منع اجتياز المسار — نسمح فقط بأسماء النسخ داخل المجلد
    safe = os.path.basename(name)
    if not re.fullmatch(r"emailmanager_\d{8}_\d{6}\.(dump|db)", safe):
        abort(404)
    path = os.path.join(BACKUP_DIR, safe)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=safe)


def _mailbox_msg_counts(conn):
    """عدد الرسائل في كل صندوق: {البريد: {'inbox': مستقبَلة, 'sent': مُرسَلة}}."""
    out = {}
    try:
        for r in conn.execute("SELECT lower(box_email) be, folder, COUNT(*) c "
                              "FROM mail_messages GROUP BY lower(box_email), folder").fetchall():
            out.setdefault(r["be"], {})[r["folder"]] = r["c"]
    except Exception:  # noqa: BLE001
        pass
    return out


# ------------------------------------------------------------------ الحسابات
@app.route("/accounts")
def accounts():
    conn = get_connection()
    cur = conn.cursor()
    mcounts = _mailbox_msg_counts(cur)
    rows = []
    for a in cur.execute("SELECT * FROM accounts ORDER BY id").fetchall():
        h, d = _account_send_counts(cur, a["id"])
        rec = dict(a)
        rec["used_hour"], rec["used_day"] = h, d
        mc = mcounts.get((a["email"] or "").lower(), {})
        rec["recv_ct"] = mc.get("inbox", 0)
        rec["sent_ct"] = mc.get("sent", 0)
        rec["employees"] = cur.execute(
            "SELECT name, email, emp_connected, active FROM employees "
            "WHERE owner_account_id=? ORDER BY name", (a["id"],)
        ).fetchall()
        rows.append(rec)
    # مجموعات الموظفين (أقسام + مناصب) للتعيين السريع بالجروب
    groups = []
    for col, kind in (("department", "قسم"), ("title", "منصب")):
        for r in cur.execute(
            "SELECT %s v, COUNT(*) c FROM employees WHERE active=1 AND %s!='' "
            "GROUP BY %s ORDER BY %s" % (col, col, col, col)).fetchall():
            groups.append({"type": col, "value": r["v"],
                           "label": "%s: %s (%d)" % (kind, r["v"], r["c"])})
    unassigned = cur.execute("SELECT COUNT(*) c FROM employees "
                             "WHERE active=1 AND owner_account_id IS NULL").fetchone()["c"]
    total_active = cur.execute("SELECT COUNT(*) c FROM employees WHERE active=1").fetchone()["c"]
    conn.close()
    return render("accounts.html", "الإيميلات المرسِلة", rows=rows,
                  groups=groups, unassigned=unassigned, total_active=total_active)


@app.route("/accounts/<int:aid>/assign", methods=["POST"])
def account_assign_employees(aid):
    """تعيين موظفين لحساب رئيسي: بالمجموعة (قسم/منصب) أو عدد عشوائي."""
    f = request.form
    conn = get_connection()
    cur = conn.cursor()
    if not cur.execute("SELECT 1 FROM accounts WHERE id=?", (aid,)).fetchone():
        conn.close()
        abort(404)
    mode = f.get("mode", "")
    n = 0
    if mode == "group":
        col = f.get("group_type", "")
        val = (f.get("group_value", "") or "").strip()
        if col not in ("department", "title") or not val:
            conn.close()
            flash("اختر مجموعة صحيحة", "error")
            return redirect(url_for("accounts"))
        cur.execute("UPDATE employees SET owner_account_id=? "
                    "WHERE active=1 AND %s=?" % col, (aid, val))
        n = cur.execute("SELECT COUNT(*) c FROM employees WHERE owner_account_id=? AND %s=?"
                        % col, (aid, val)).fetchone()["c"]
        msg = "تم تعيين موظفي المجموعة «%s» على الحساب (%d موظف)" % (val, n)
    elif mode == "random":
        try:
            want = max(1, int(f.get("count", "0")))
        except (TypeError, ValueError):
            conn.close()
            flash("اكتب عدداً صحيحاً", "error")
            return redirect(url_for("accounts"))
        from_all = f.get("from_all") == "1"
        if from_all:
            cand = cur.execute(
                "SELECT id FROM employees WHERE active=1 AND (owner_account_id IS NULL "
                "OR owner_account_id<>?) ORDER BY RANDOM() LIMIT ?", (aid, want)).fetchall()
        else:
            cand = cur.execute(
                "SELECT id FROM employees WHERE active=1 AND owner_account_id IS NULL "
                "ORDER BY RANDOM() LIMIT ?", (want,)).fetchall()
        ids = [r["id"] for r in cand]
        if ids:
            ph = ",".join(["?"] * len(ids))
            cur.execute("UPDATE employees SET owner_account_id=? WHERE id IN (%s)" % ph,
                        [aid] + ids)
        n = len(ids)
        msg = "تم تعيين %d موظف عشوائياً على الحساب" % n
    else:
        conn.close()
        flash("إجراء غير معروف", "error")
        return redirect(url_for("accounts"))
    conn.commit()
    conn.close()
    flash(msg, "success")
    return redirect(url_for("accounts"))


@app.route("/accounts/add", methods=["POST"])
def add_account():
    f = request.form
    email = f["email"].strip().lower()
    password = f["password"]

    conn = get_connection()
    if conn.execute("SELECT 1 FROM accounts WHERE email=?", (email,)).fetchone():
        conn.close()
        flash("هذا البريد مُضاف مسبقاً", "error")
        return redirect(url_for("accounts"))

    # إعدادات يدوية إن أُدخلت، وإلا اكتشاف تلقائي بتجربة الاتصال
    manual = f.get("smtp_server", "").strip() and f.get("imap_server", "").strip()
    try:
        if manual:
            cfg = {
                "smtp_server": f["smtp_server"].strip(),
                "smtp_port": int(f.get("smtp_port") or 587),
                "security": f.get("security", "").strip() or "starttls",
                "imap_server": f["imap_server"].strip(),
                "imap_port": int(f.get("imap_port") or 993),
            }
            tmp = dict(cfg, email=email, password=encrypt_secret(password))
            ok, msg = verify_account_full(tmp)
            if not ok:
                raise RuntimeError(msg)
        else:
            cfg = autodiscover(email, password)   # يرمي RuntimeError عند الفشل
    except Exception as exc:  # noqa: BLE001
        conn.close()
        flash(f"لم تتم الإضافة — فشل الاتصال: {exc}", "error")
        return redirect(url_for("accounts"))

    cur = conn.execute("""
        INSERT INTO accounts (email, display_name, password, smtp_server, smtp_port,
                              imap_server, imap_port, security)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (email, f.get("display_name", "").strip(), encrypt_secret(password),
          cfg["smtp_server"], cfg["smtp_port"], cfg["imap_server"], cfg["imap_port"],
          cfg["security"]))
    conn.commit()
    acc_id = cur.lastrowid
    _set_account_verified(conn, acc_id, True)

    conn.close()
    flash("تم الاتصال بنجاح وأُضيف الحساب ✔ — افتح «البريد» لتصفّح صندوقه.", "success")
    return redirect(url_for("mail_view", kind="account", oid=acc_id))


@app.route("/accounts/<int:aid>/edit", methods=["POST"])
def edit_account(aid):
    conn = get_connection()
    conn.execute("UPDATE accounts SET display_name=? WHERE id=?",
                 (request.form.get("display_name", "").strip(), aid))
    conn.commit()
    conn.close()
    flash("تم تحديث الاسم الظاهر", "success")
    return redirect(url_for("accounts"))


@app.route("/accounts/<int:aid>/sync")
def sync_account(aid):
    """اختبار اتصال حيّ بالصندوق + تحديث قائمة المجلدات والعدّادات."""
    conn = get_connection()
    row = conn.execute("SELECT * FROM accounts WHERE id=?", (aid,)).fetchone()
    if not row:
        conn.close()
        abort(404)
    acct = dict(row)
    try:
        close_mail_sessions(acct)
        folders = cached_folders(acct, force=True)
        inbox_name = folder_by_kind(folders, "inbox", "INBOX")
        n = next((f["unseen"] for f in folders if f["name"] == inbox_name), 0)
        _set_account_verified(conn, aid, True)
        flash(f"{row['email']}: الاتصال ناجح — {len(folders)} مجلد، {n} رسالة غير مقروءة",
              "success")
    except Exception as exc:  # noqa: BLE001
        _set_account_verified(conn, aid, False)
        flash(f"تعذّر الاتصال: {exc}", "error")
    conn.close()
    return redirect(request.referrer or url_for("mailboxes"))


@app.route("/accounts/<int:aid>/test")
def test_account_route(aid):
    conn = get_connection()
    acc = conn.execute("SELECT * FROM accounts WHERE id=?", (aid,)).fetchone()
    conn.close()
    if not acc:
        abort(404)
    ok, msg = verify_account_full(acc)
    conn = get_connection()
    _set_account_verified(conn, aid, ok)
    conn.close()
    flash(("✔ " if ok else "✖ ") + msg, "success" if ok else "error")
    return redirect(url_for("accounts"))


@app.route("/accounts/<int:aid>/toggle")
def toggle_account(aid):
    conn = get_connection()
    conn.execute("UPDATE accounts SET active = 1 - active WHERE id=?", (aid,))
    conn.commit()
    conn.close()
    return redirect(url_for("accounts"))


@app.route("/accounts/<int:aid>/delete")
def delete_account(aid):
    conn = get_connection()
    conn.execute("DELETE FROM accounts WHERE id=?", (aid,))
    conn.commit()
    conn.close()
    flash("تم حذف الحساب", "info")
    return redirect(url_for("accounts"))


# ------------------------------------------------------------------ الموظفون
@app.route("/employees")
def employees():
    conn = get_connection()
    rows = conn.execute("""SELECT e.*, a.email AS owner_email, a.display_name AS owner_name
                           FROM employees e LEFT JOIN accounts a ON a.id = e.owner_account_id
                           ORDER BY e.name""").fetchall()
    accs = conn.execute("SELECT id, email, display_name FROM accounts ORDER BY id").fetchall()
    counts = _mailbox_msg_counts(conn)
    conn.close()
    return render("employees.html", "الموظفين", rows=rows, accs=accs, counts=counts)


@app.route("/employees/bulk", methods=["POST"])
def employees_bulk():
    """إجراءات جماعية على الموظفين المحدَّدين: تفعيل/إيقاف/نقل/حذف."""
    f = request.form
    action = (f.get("bulk_action", "") or "").strip()
    ids = [int(x) for x in f.getlist("ids") if x.isdigit()]
    if not ids:
        flash("لم تحدّد أي موظف", "error")
        return redirect(url_for("employees"))
    conn = get_connection()
    cur = conn.cursor()
    ph = ",".join(["?"] * len(ids))
    if action == "activate":
        cur.execute(f"UPDATE employees SET active=1 WHERE id IN ({ph})", ids)
        msg = "تم تفعيل %d موظف" % len(ids)
    elif action == "deactivate":
        cur.execute(f"UPDATE employees SET active=0 WHERE id IN ({ph})", ids)
        msg = "تم إيقاف %d موظف" % len(ids)
    elif action == "move":
        acc = (f.get("target_account", "") or "").strip()
        if acc == "":
            cur.execute(f"UPDATE employees SET owner_account_id=NULL WHERE id IN ({ph})", ids)
            msg = "تم إلغاء تعيين %d موظف" % len(ids)
        elif acc.isdigit() and cur.execute("SELECT 1 FROM accounts WHERE id=?",
                                            (int(acc),)).fetchone():
            cur.execute(f"UPDATE employees SET owner_account_id=? WHERE id IN ({ph})",
                        [int(acc)] + ids)
            msg = "تم نقل %d موظف للحساب المحدّد" % len(ids)
        else:
            conn.close()
            flash("اختر حساباً صحيحاً للنقل", "error")
            return redirect(url_for("employees"))
    elif action == "delete":
        cur.execute(f"DELETE FROM employees WHERE id IN ({ph})", ids)
        msg = "تم حذف %d موظف" % len(ids)
    elif action == "connect":
        # اتصال بصناديق الموظفين المحدَّدين في الخلفية
        conn.close()
        sel = list(ids)

        def _bulk_connect(sel_ids):
            c = get_connection()
            ok = 0
            for eid in sel_ids:
                emp = c.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
                if emp and emp["password"]:
                    try:
                        good, _ = _connect_one_employee(c, emp)
                        ok += good
                    except Exception:  # noqa: BLE001
                        log.exception("bulk connect %s", eid)
                _stop_event.wait(random.uniform(1, 3))
            c.close()
            log.info("اتصال جماعي انتهى: نجح %d من %d", ok, len(sel_ids))

        threading.Thread(target=_bulk_connect, args=(sel,), daemon=True).start()
        flash("بدأ الاتصال بصناديق %d موظف في الخلفية — راجع عمود «الاتصال» بعد قليل." % len(ids),
              "info")
        return redirect(url_for("employees"))
    elif action == "login":
        # إنشاء لوج إن للموظفين المحدَّدين (المستخدم=البريد، كلمة المرور=كلمة مرور صندوقه)
        created = already = 0
        for eid in ids:
            emp = cur.execute("SELECT id, email, name, password FROM employees WHERE id=?",
                              (eid,)).fetchone()
            if not emp:
                continue
            if cur.execute("SELECT 1 FROM users WHERE employee_id=?", (eid,)).fetchone():
                already += 1
                continue
            pw = decrypt_secret(emp["password"]) if emp["password"] else DEFAULT_MAILBOX_PASS
            try:
                cur.execute("""INSERT INTO users (username, password_hash, role, employee_id, full_name)
                               VALUES (?, ?, 'employee', ?, ?)""",
                            (emp["email"], hash_password(pw), eid, emp["name"]))
                created += 1
            except sqlite3.IntegrityError:
                already += 1
        conn.commit()
        conn.close()
        flash("تم إنشاء لوج إن لـ %d موظف (المستخدم = البريد · كلمة المرور = كلمة مرور صندوقه، "
              "الافتراضي 022001)%s" % (created,
              ("، و%d عندهم لوج إن مسبقاً" % already) if already else ""), "success")
        return redirect(url_for("employees"))
    else:
        conn.close()
        flash("إجراء غير معروف", "error")
        return redirect(url_for("employees"))
    conn.commit()
    conn.close()
    flash(msg, "success")
    return redirect(url_for("employees"))


@app.route("/employees/add", methods=["POST"])
def add_employee():
    f = request.form
    pw = f.get("password", "") or DEFAULT_MAILBOX_PASS   # افتراضية 022001 لو فاضية
    # التوقيع اختياري: لو فاضي، الموظف بياخد توقيع الحساب الرئيسي تلقائياً
    signature = f.get("signature", "").strip()
    try:
        conn = get_connection()
        conn.execute("""INSERT INTO employees (name, email, title, department, phone, password,
                        signature, iqama, emp_number)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                     (f["name"].strip(), f["email"].strip().lower(),
                      f.get("title", "").strip(), f.get("department", "").strip(),
                      f.get("phone", "").strip(),
                      encrypt_secret(pw), signature,
                      f.get("iqama", "").strip(), f.get("emp_number", "").strip()))
        conn.commit()
        conn.close()
        flash("تمت إضافة الموظف", "success")
    except sqlite3.IntegrityError:
        flash("هذا البريد مُضاف مسبقاً", "error")
    return redirect(url_for("employees"))


@app.route("/employees/<int:eid>/edit", methods=["POST"])
def edit_employee(eid):
    f = request.form
    pw = f.get("password", "")
    signature = f.get("signature", "").strip()
    try:
        conn = get_connection()
        iqama = f.get("iqama", "").strip()
        emp_number = f.get("emp_number", "").strip()
        if signature:   # التوقيع لا يُمسح أبداً — يُحدَّث فقط لو أُدخلت قيمة جديدة
            conn.execute("""UPDATE employees SET name=?, email=?, title=?, department=?,
                            phone=?, iqama=?, emp_number=?, signature=? WHERE id=?""",
                         (f["name"].strip(), f["email"].strip().lower(),
                          f.get("title", "").strip(), f.get("department", "").strip(),
                          f.get("phone", "").strip(), iqama, emp_number, signature, eid))
        else:
            conn.execute("""UPDATE employees SET name=?, email=?, title=?, department=?,
                            phone=?, iqama=?, emp_number=? WHERE id=?""",
                         (f["name"].strip(), f["email"].strip().lower(),
                          f.get("title", "").strip(), f.get("department", "").strip(),
                          f.get("phone", "").strip(), iqama, emp_number, eid))
        if pw:   # حدّث كلمة المرور فقط لو أُدخلت
            conn.execute("UPDATE employees SET password=? WHERE id=?",
                         (encrypt_secret(pw), eid))
        conn.commit()
        conn.close()
        flash("تم تحديث الموظف", "success")
    except sqlite3.IntegrityError:
        flash("البريد مستخدم لموظف آخر", "error")
    return redirect(url_for("employees"))


# أسماء الأعمدة المقبولة في ملف الاستيراد (عربي/إنجليزي) → الحقل
_IMPORT_ALIASES = {
    "name":       {"name", "الاسم", "اسم", "اسم المشترك", "اسم الموظف", "المشترك"},
    "email":      {"email", "e-mail", "mail", "البريد", "بريد", "الايميل", "الإيميل",
                   "البريد الالكتروني", "البريد الإلكتروني"},
    "iqama":      {"iqama", "id", "رقم الهوية", "الهوية", "هوية", "رقم الاقامة",
                   "رقم الإقامة", "الاقامة", "الإقامة"},
    "title":      {"title", "job", "المهنة", "المنصب", "الوظيفة", "الصفة"},
    "department": {"department", "dept", "القسم", "الاداره", "الإدارة"},
    "phone":      {"phone", "mobile", "tel", "الهاتف", "الجوال", "التليفون", "موبايل",
                   "رقم الهاتف", "رقم الجوال"},
    "password":   {"password", "pass", "كلمة المرور", "الباسورد", "باسورد", "كلمة السر"},
    "emp_number": {"emp_number", "الرقم الوظيفي", "رقم الموظف", "الرقم الوظيفى"},
}


def _import_colmap(header):
    """يبني خريطة {حقل: فهرس العمود} من صف العناوين. يعيد {} لو مفيش عناوين واضحة."""
    colmap = {}
    for idx, cell in enumerate(header):
        h = (cell or "").strip().lower()
        if not h:
            continue
        for field, aliases in _IMPORT_ALIASES.items():
            if field in colmap:
                continue
            if h in {a.lower() for a in aliases}:
                colmap[field] = idx
                break
    return colmap


@app.route("/employees/import", methods=["POST"])
def import_employees():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("اختر ملف CSV أو Excel", "warning")
        return redirect(url_for("employees"))
    fname = (file.filename or "").lower()
    all_rows = []
    if fname.endswith((".xlsx", ".xlsm")):
        try:
            from openpyxl import load_workbook
            wb = load_workbook(io.BytesIO(file.stream.read()), read_only=True, data_only=True)
            ws = wb.active
            for row in ws.iter_rows(values_only=True):
                all_rows.append(["" if v is None else str(v).strip() for v in row])
        except Exception as exc:  # noqa: BLE001
            flash("تعذّر قراءة ملف Excel: %s" % exc, "error")
            return redirect(url_for("employees"))
    else:
        raw = file.stream.read().decode("utf-8-sig", errors="ignore")
        try:
            dialect = csv.Sniffer().sniff(raw[:2048], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        all_rows = [r for r in csv.reader(io.StringIO(raw), dialect)]
    conn = get_connection()
    cur = conn.cursor()
    added = updated = skipped = 0
    skipped_rows = []       # (رقم الصف، السبب)
    dup_rows = []           # صفوف إيميلها مكرر داخل نفس الملف
    seen_emails = {}        # email → رقم أول صف ظهر فيه

    # وضع العناوين: لو أول صف فيه أسماء أعمدة معروفة (name+email) نقرأ حسبها
    colmap = _import_colmap(all_rows[0]) if all_rows else {}
    header_mode = ("name" in colmap and "email" in colmap)
    data_rows = all_rows[1:] if header_mode else all_rows
    base = 2 if header_mode else 1   # رقم الصف في الإكسل (العنوان = صف 1)

    for i, row in enumerate(data_rows):
        rownum = i + base
        cells = [c.strip() for c in row]
        if header_mode:
            def g(field):
                idx = colmap.get(field)
                return cells[idx] if (idx is not None and idx < len(cells)) else ""
            name, email = g("name"), g("email").lower()
            title, department = g("title"), g("department")
            phone, pw = g("phone"), g("password")
            iqama, emp_number = g("iqama"), g("emp_number")
        else:
            if not any(cells):
                continue                                  # صف فاضي تماماً — تجاهل صامت
            name = cells[0] if len(cells) > 0 else ""
            email = (cells[1].lower() if len(cells) > 1 else "")
            title = cells[2] if len(cells) > 2 else ""
            department = cells[3] if len(cells) > 3 else ""
            phone = cells[4] if len(cells) > 4 else ""
            pw = cells[5] if len(cells) > 5 else ""
            iqama = cells[6] if len(cells) > 6 else ""
            emp_number = cells[7] if len(cells) > 7 else ""
            if i == 0 and "@" not in email:               # صف عنوان غير معروف
                continue
        if not any([name, email] + cells):
            continue                                       # صف فاضي — تجاهل صامت
        if not name:
            skipped += 1
            skipped_rows.append((rownum, "بدون اسم"))
            continue
        if "@" not in email:
            skipped += 1
            skipped_rows.append((rownum, "بريد غير صالح" + (": " + email if email else " (فاضي)")))
            continue
        if email in seen_emails:
            dup_rows.append((rownum, email, seen_emails[email]))
        else:
            seen_emails[email] = rownum
        enc_pw = encrypt_secret(pw) if pw else None
        exists = cur.execute("SELECT 1 FROM employees WHERE email=?", (email,)).fetchone()
        if exists:
            cur.execute("""UPDATE employees SET name=?, title=?, department=?, phone=?,
                           iqama=?, emp_number=? WHERE email=?""",
                        (name, title, department, phone, iqama, emp_number, email))
            if enc_pw:
                cur.execute("UPDATE employees SET password=? WHERE email=?", (enc_pw, email))
            updated += 1
        else:
            cur.execute("""INSERT INTO employees (name, email, title, department, phone, password,
                           iqama, emp_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (name, email, title, department, phone,
                         enc_pw or encrypt_secret(DEFAULT_MAILBOX_PASS), iqama, emp_number))
            added += 1
    conn.commit()
    conn.close()
    msg = "استيراد: %d جديد · %d محدّث · %d متخطّى" % (added, updated, skipped)
    if dup_rows:
        ex = "، ".join("صف %d (%s)" % (r, e) for r, e, _ in dup_rows[:5])
        msg += " · ⚠️ %d إيميل مكرر في الملف (اتحسبوا تحديث مش إضافة): %s" % (len(dup_rows), ex)
    if skipped_rows:
        ex = "، ".join("صف %d: %s" % (r, why) for r, why in skipped_rows[:5])
        msg += " · المتخطّى: " + ex
    flash(msg, "success" if not (dup_rows or skipped_rows) else "warning")
    return redirect(url_for("employees"))


@app.route("/employees/import-template")
def employees_import_template():
    """ينزّل نموذج استيراد Excel (.xlsx) بأعمدة منفصلة جاهزة للتعبئة."""
    headers = ["اسم المشترك", "رقم الهوية", "المهنة", "Email"]
    sample = ["محمد أحمد", "1234567890", "محاسب", "mohamed@example.com"]
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        wb = Workbook()
        ws = wb.active
        ws.title = "الموظفون"
        ws.sheet_view.rightToLeft = True
        ws.append(headers)
        ws.append(sample)
        green = PatternFill("solid", fgColor="21A366")
        hfont = Font(bold=True, color="FFFFFF", size=12)
        thin = Side(style="thin", color="BBBBBB")
        border = Border(left=thin, right=thin, top=thin, bottom=thin)
        center = Alignment(horizontal="center", vertical="center")
        for c in ws[1]:
            c.fill = green
            c.font = hfont
            c.alignment = center
            c.border = border
        for c in ws[2]:
            c.alignment = center
            c.border = border
        for i, w in enumerate([26, 18, 22, 34], start=1):
            ws.column_dimensions[chr(64 + i)].width = w
        ws.row_dimensions[1].height = 26
        bio = io.BytesIO()
        wb.save(bio)
        bio.seek(0)
        return Response(
            bio.read(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition":
                     "attachment; filename=employees_import_template.xlsx"})
    except ImportError:
        # احتياطي: CSV بفاصلة منقوطة (أفضل توافق مع إكسل العربي)
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";")
        w.writerow(headers)
        w.writerow(sample)
        return Response(buf.getvalue().encode("utf-8-sig"), mimetype="text/csv",
                        headers={"Content-Disposition":
                                 "attachment; filename=employees_import_template.csv"})


@app.route("/employees/<int:eid>/signature-preview")
def employee_signature_preview(eid):
    """يعيد HTML التوقيع الفعلي لموظف (للعرض في نافذة منبثقة)."""
    conn = get_connection()
    e = conn.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
    if not e:
        conn.close()
        abort(404)
    style = get_setting("signature_style", "rich")
    elogo = e["logo"] if "logo" in e.keys() else ""
    if style == "rich":
        ent = {"name": e["name"], "title": e["title"], "department": e["department"],
               "email": e["email"]}
        html = _rich_signature_html(ent, _effective_logo(elogo))
    else:
        txt, logo = resolve_signature(conn, e)
        html = _signature_html(txt, _effective_logo(logo or elogo))
    conn.close()
    return "<div style='background:#fff;padding:20px;border-radius:10px'>%s</div>" % (
        html or "<span style='color:#888'>— لا يوجد توقيع —</span>")


@app.route("/employees/export")
def export_employees():
    conn = get_connection()
    rows = conn.execute("""SELECT name, email, title, department, phone, iqama, emp_number, active
                           FROM employees ORDER BY name""").fetchall()
    conn.close()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "email", "title", "department", "phone", "password", "iqama", "emp_number"])
    for r in rows:
        w.writerow([r["name"], r["email"], r["title"], r["department"], r["phone"], "",
                    r["iqama"], r["emp_number"]])
    return Response(buf.getvalue().encode("utf-8-sig"), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=employees.csv"})


@app.route("/employees/<int:eid>/toggle")
def toggle_employee(eid):
    conn = get_connection()
    conn.execute("UPDATE employees SET active = 1 - active WHERE id=?", (eid,))
    conn.commit()
    conn.close()
    return redirect(url_for("employees"))


@app.route("/employees/<int:eid>/delete")
def delete_employee(eid):
    conn = get_connection()
    conn.execute("DELETE FROM employees WHERE id=?", (eid,))
    conn.commit()
    conn.close()
    flash("تم حذف الموظف", "info")
    return redirect(url_for("employees"))


def _connect_one_employee(conn, emp):
    """يتحقق من صندوق الموظف (بدون تحميل رسائل). يعيد (ok, رسالة)."""
    if not emp["password"]:
        return False, "لا توجد كلمة مرور"
    acct = _emp_account(emp)
    pw = decrypt_secret(acct["password"])
    try:
        _imap_login_test(acct["imap_server"], acct["imap_port"], acct["email"], pw)
    except Exception as e:  # noqa: BLE001
        conn.execute("UPDATE employees SET emp_connected=0 WHERE id=?", (emp["id"],))
        conn.commit()
        return False, f"IMAP: {e}"
    conn.execute("UPDATE employees SET emp_connected=1, emp_last_check=? WHERE id=?",
                 (datetime.now().isoformat(timespec="seconds"), emp["id"]))
    conn.commit()
    return True, "اتصال ناجح بصندوق %s" % emp["email"]


@app.route("/employees/<int:eid>/connect")
def connect_employee(eid):
    conn = get_connection()
    emp = conn.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
    if not emp:
        conn.close()
        abort(404)
    ok, msg = _connect_one_employee(conn, emp)
    conn.close()
    flash(f"{emp['email']}: {msg}", "success" if ok else "error")
    return redirect(request.referrer or url_for("employees"))


@app.route("/employees/<int:eid>/make-login")
def employee_make_login(eid):
    conn = get_connection()
    emp = conn.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
    if not emp:
        conn.close()
        abort(404)
    existing = conn.execute("SELECT username FROM users WHERE employee_id=?", (eid,)).fetchone()
    if existing:
        conn.close()
        flash(f"للموظف لوج إن بالفعل: {existing['username']}", "info")
        return redirect(url_for("employees"))
    username = emp["email"]
    pw = secrets.token_urlsafe(6)
    try:
        conn.execute("""INSERT INTO users (username, password_hash, role, employee_id, full_name)
                        VALUES (?, ?, 'employee', ?, ?)""",
                     (username, hash_password(pw), eid, emp["name"]))
        conn.commit()
        flash(f"تم إنشاء لوج إن — المستخدم: {username} · كلمة المرور: {pw} "
              f"(انسخها الآن، لن تظهر ثانية)", "success")
    except sqlite3.IntegrityError:
        flash("اسم المستخدم (البريد) مستخدم مسبقاً في لوج إن آخر", "error")
    conn.close()
    return redirect(url_for("employees"))


@app.route("/employees/connect-all")
def connect_all_employees():
    def worker():
        conn = get_connection()
        emps = conn.execute("SELECT * FROM employees WHERE active=1 AND password != ''").fetchall()
        ok = fail = 0
        for emp in emps:
            try:
                good, _ = _connect_one_employee(conn, emp)
                ok += good
                fail += (not good)
            except Exception:  # noqa: BLE001
                fail += 1
                log.exception("connect-all: %s", emp["email"])
            _stop_event.wait(random.uniform(2, 5))
        conn.close()
        log.info("connect-all انتهى: نجح=%d فشل=%d", ok, fail)

    threading.Thread(target=worker, daemon=True).start()
    flash("بدأ الاتصال بصناديق كل الموظفين في الخلفية — راجع صفحة صناديق البريد بعد قليل.", "info")
    return redirect(url_for("employees"))



# ------------------------------------------------------------------ توزيع الموظفين على الحسابات
def _distribution_data(conn):
    accs = conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()
    counts = {r["owner_account_id"]: r["c"] for r in conn.execute(
        "SELECT owner_account_id, COUNT(*) c FROM employees WHERE active=1 "
        "GROUP BY owner_account_id").fetchall()}
    depts = {}
    for r in conn.execute("""SELECT owner_account_id, department, COUNT(*) c
                             FROM employees WHERE active=1
                             GROUP BY owner_account_id, department""").fetchall():
        depts.setdefault(r["owner_account_id"], []).append(
            {"department": r["department"] or "(بدون قسم)", "c": r["c"]})
    groups = []
    for a in accs:
        groups.append({"acc": a, "count": counts.get(a["id"], 0),
                       "depts": depts.get(a["id"], [])})
    return accs, groups, counts.get(None, 0)


@app.route("/distribution")
def distribution():
    conn = get_connection()
    accs, groups, unassigned = _distribution_data(conn)
    emps = conn.execute("""SELECT e.*, a.email AS owner_email, a.display_name AS owner_name
                           FROM employees e LEFT JOIN accounts a ON a.id = e.owner_account_id
                           WHERE e.active=1
                           ORDER BY e.department, e.name""").fetchall()
    departments = [r["department"] for r in conn.execute(
        "SELECT DISTINCT department FROM employees WHERE active=1 ORDER BY department").fetchall()]
    dept_owner = {}
    for r in conn.execute("""SELECT department, owner_account_id, COUNT(*) c FROM employees
                             WHERE active=1 GROUP BY department, owner_account_id""").fetchall():
        cur = dept_owner.get(r["department"])
        if cur is None or r["c"] > cur[1]:
            dept_owner[r["department"]] = (r["owner_account_id"], r["c"])
    conn.close()
    return render("distribution.html", "توزيع الموظفين", accs=accs, groups=groups,
                  emps=emps, departments=departments, unassigned=unassigned,
                  dept_owner={k: v[0] for k, v in dept_owner.items()})


@app.route("/distribution/auto", methods=["POST"])
def distribution_auto():
    """توزيع تلقائي: بالتساوي على الحسابات، أو أقساماً كاملة لكل حساب."""
    mode = request.form.get("mode", "equal")
    sel = [int(x) for x in request.form.getlist("accounts") if x.isdigit()]
    conn = get_connection()
    cur = conn.cursor()
    accs = cur.execute("SELECT id FROM accounts WHERE active=1 ORDER BY id").fetchall()
    acc_ids = [a["id"] for a in accs]
    if sel:                       # اقصر التوزيع على الحسابات المختارة فقط
        acc_ids = [i for i in acc_ids if i in sel]
    if not acc_ids:
        conn.close()
        flash("اختر حساباً واحداً نشطاً على الأقل للتوزيع عليه", "error")
        return redirect(url_for("distribution"))

    if mode == "department":
        # كل قسم كامل لحساب واحد، مع موازنة الأعداد (الأكبر أولاً)
        rows = cur.execute("""SELECT department, COUNT(*) c FROM employees
                              WHERE active=1 GROUP BY department ORDER BY c DESC""").fetchall()
        load = {i: 0 for i in acc_ids}
        for r in rows:
            target = min(load, key=lambda k: load[k])
            cur.execute("UPDATE employees SET owner_account_id=? WHERE active=1 AND department=?",
                        (target, r["department"]))
            load[target] += r["c"]
        msg = "تم توزيع %d قسماً على %d حساب" % (len(rows), len(acc_ids))
    else:
        emps = cur.execute("""SELECT id FROM employees WHERE active=1
                              ORDER BY department, name""").fetchall()
        for i, e in enumerate(emps):
            cur.execute("UPDATE employees SET owner_account_id=? WHERE id=?",
                        (acc_ids[i % len(acc_ids)], e["id"]))
        per = len(emps) // len(acc_ids) if acc_ids else 0
        msg = "تم توزيع %d موظفاً بالتساوي (~%d لكل حساب)" % (len(emps), per)
    conn.commit()
    conn.close()
    flash(msg, "success")
    return redirect(url_for("distribution"))


@app.route("/distribution/departments", methods=["POST"])
def distribution_departments():
    """ربط كل قسم بحساب مسؤول يدوياً."""
    conn = get_connection()
    n = 0
    for key, val in request.form.items():
        if not key.startswith("deptacc::"):
            continue
        dept = key[9:]
        acc = int(val) if val.strip().isdigit() else None
        conn.execute("UPDATE employees SET owner_account_id=? WHERE active=1 AND department=?",
                     (acc, dept))
        n += 1
    conn.commit()
    conn.close()
    flash("تم تحديث %d قسماً" % n, "success")
    return redirect(url_for("distribution"))


@app.route("/distribution/save", methods=["POST"])
def distribution_save():
    """حفظ تعيين يدوي لكل موظف."""
    conn = get_connection()
    n = 0
    for key, val in request.form.items():
        if not key.startswith("own::"):
            continue
        eid = key[5:]
        if not eid.isdigit():
            continue
        acc = int(val) if val.strip().isdigit() else None
        conn.execute("UPDATE employees SET owner_account_id=? WHERE id=?", (acc, int(eid)))
        n += 1
    conn.commit()
    conn.close()
    flash("تم حفظ توزيع %d موظف" % n, "success")
    return redirect(url_for("distribution"))


@app.route("/distribution/assign", methods=["POST"])
def distribution_assign():
    """يربط الموظفين المحدَّدين بحساب رئيسي واحد."""
    ids = [int(i) for i in request.form.getlist("eid") if i.strip().isdigit()]
    raw = (request.form.get("account_id") or "").strip()
    acc = int(raw) if raw.isdigit() else None
    if not ids:
        flash("لم تحدّد أي موظف", "warning")
        return redirect(url_for("distribution"))
    conn = get_connection()
    name = "— بدون حساب —"
    if acc is not None:
        row = conn.execute("SELECT email, display_name FROM accounts WHERE id=?", (acc,)).fetchone()
        if not row:
            conn.close()
            flash("الحساب غير موجود", "error")
            return redirect(url_for("distribution"))
        name = row["display_name"] or row["email"]
    conn.executemany("UPDATE employees SET owner_account_id=? WHERE id=?",
                     [(acc, i) for i in ids])
    conn.commit()
    conn.close()
    flash("تم ربط %d موظفاً بـ %s" % (len(ids), name), "success")
    return redirect(url_for("distribution"))


@app.route("/distribution/clear")
def distribution_clear():
    conn = get_connection()
    conn.execute("UPDATE employees SET owner_account_id=NULL")
    conn.commit()
    conn.close()
    flash("تم إلغاء كل التوزيع", "info")
    return redirect(url_for("distribution"))


# ------------------------------------------------------------------ توقيع الموظفين
@app.route("/templates")
def templates_page():
    conn = get_connection()
    mains = conn.execute(
        "SELECT id, email, display_name, signature, logo FROM accounts ORDER BY email").fetchall()
    emps = conn.execute("""SELECT e.id, e.name, e.email, e.signature, e.iqama, e.emp_number,
                                  e.title, e.department,
                                  a.email AS owner_email, a.display_name AS owner_name
                           FROM employees e LEFT JOIN accounts a ON a.id = e.owner_account_id
                           ORDER BY a.email, e.email""").fetchall()
    glogo = get_setting("global_logo", "")
    style = get_setting("signature_style", "rich")
    # معاينة توضيحية للتصميم ببيانات مثال كاملة (كل الصفوف تظهر)
    rich_preview = _rich_signature_html(
        {"name": "Fahad Al Harbi", "title": "Human Resources",
         "department": "Dammam", "email": "fahad@solutionstech.sa"}, glogo)
    # معاينة لكل حساب/موظف ببياناته الحقيقية (بدون لوجو لتخفيف حجم الصفحة)
    main_rich = {m["id"]: _rich_signature_html(
        {"name": m["display_name"] or m["email"], "title": "", "department": "",
         "email": m["email"]}, "") for m in mains}
    emp_rich = {e["id"]: _rich_signature_html(
        {"name": e["name"], "title": e["title"], "department": e["department"],
         "email": e["email"]}, "") for e in emps}
    conn.close()
    return render("templates.html", "توقيع الموظفين", mains=mains, emps=emps,
                  signature_template=get_setting("signature_template", ""),
                  company_phone=get_setting("company_phone", "920035640"),
                  company_website=get_setting("company_website", "www.solutionstech.sa"),
                  global_logo=glogo, rich_preview=rich_preview,
                  signature_style=style, main_rich=main_rich, emp_rich=emp_rich)


@app.route("/templates/employee-signature/<int:eid>", methods=["POST"])
def save_employee_signature(eid):
    """توقيع خاص لموظف واحد — يتغلّب على توقيع حسابه الرئيسي."""
    sig = request.form.get("signature", "").strip()
    conn = get_connection()
    if not conn.execute("SELECT 1 FROM employees WHERE id=?", (eid,)).fetchone():
        conn.close()
        abort(404)
    conn.execute("UPDATE employees SET signature=? WHERE id=?", (sig, eid))
    conn.commit()
    conn.close()
    flash("تم حفظ توقيع الموظف" if sig else "تم مسح التوقيع الخاص — الموظف يرث توقيع حسابه الرئيسي",
          "success")
    return redirect(url_for("templates_page") + "#emps")


# ------------------------------------------------------------------ قوالب رسائل الحملات
@app.route("/message-templates")
def message_templates_page():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM templates ORDER BY id DESC").fetchall()
    rctx = _reverse_ctx(conn)
    conn.close()
    return render("msg_templates.html", "القوالب والردود التلقائية", rows=rows, **rctx)


@app.route("/templates/signature", methods=["POST"])
def save_signature_template():
    set_setting("signature_template", request.form.get("signature_template", ""))
    flash("تم حفظ قالب التوقيع", "success")
    return redirect(url_for("templates_page"))


@app.route("/templates/company-info", methods=["POST"])
def save_company_info():
    """بيانات ثابتة لكل التواقيع: الهاتف + الموقع + اللوجو الموحّد."""
    f = request.form
    set_setting("company_phone", (f.get("company_phone", "") or "").strip())
    set_setting("company_website", (f.get("company_website", "") or "").strip())
    style = f.get("signature_style", "rich")
    set_setting("signature_style", "rich" if style == "rich" else "text")
    if f.get("remove_logo"):
        set_setting("global_logo", "")
        flash("تم حذف اللوجو الموحّد + حفظ الهاتف والموقع", "success")
    else:
        logo, err = _read_logo(request.files.get("logo"))
        if err:
            flash("لم يُرفع اللوجو: " + err + " — (تم حفظ الهاتف والموقع)", "error")
        elif logo:
            set_setting("global_logo", logo)
            flash("تم حفظ اللوجو الموحّد + الهاتف والموقع لكل التواقيع", "success")
        else:
            flash("تم حفظ الهاتف والموقع لكل التواقيع", "success")
    return redirect(url_for("templates_page"))


@app.route("/templates/account-signature/<int:aid>", methods=["POST"])
def save_account_signature(aid):
    """توقيع حساب رئيسي (بلوجو) — يُطبَّق عليه وعلى موظفيه تلقائياً."""
    conn = get_connection()
    if not conn.execute("SELECT 1 FROM accounts WHERE id=?", (aid,)).fetchone():
        conn.close()
        abort(404)
    signature = request.form.get("signature", "").strip()
    if request.form.get("remove_logo"):
        conn.execute("UPDATE accounts SET signature=?, logo='' WHERE id=?", (signature, aid))
    else:
        logo = _logo_data_uri(request.files.get("logo"))
        if logo:
            conn.execute("UPDATE accounts SET signature=?, logo=? WHERE id=?",
                         (signature, logo, aid))
        else:
            conn.execute("UPDATE accounts SET signature=? WHERE id=?", (signature, aid))
    conn.commit()
    conn.close()
    flash("تم حفظ توقيع الحساب — بيتطبّق عليه وعلى موظفيه تلقائياً", "success")
    return redirect(url_for("templates_page"))


@app.route("/templates/add", methods=["POST"])
def add_template():
    f = request.form
    name = f["name"].strip()
    # موضوع الإيميل = اسم القالب، والتوقيع يُضاف تلقائياً حسب الحساب المرسِل
    conn = get_connection()
    conn.execute("INSERT INTO templates (name, subject, body, signature) VALUES (?, ?, ?, '')",
                 (name, name, f["body"]))
    conn.commit()
    conn.close()
    flash("تم حفظ القالب", "success")
    return redirect(url_for("message_templates_page"))


@app.route("/templates/<int:tid>/edit", methods=["POST"])
def edit_template(tid):
    f = request.form
    name = f["name"].strip()
    conn = get_connection()
    conn.execute("""UPDATE templates SET name=?, subject=?, body=?,
                    updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                 (name, name, f["body"], tid))
    conn.commit()
    conn.close()
    flash("تم تحديث القالب", "success")
    return redirect(url_for("message_templates_page"))


@app.route("/templates/<int:tid>/delete")
def delete_template(tid):
    conn = get_connection()
    conn.execute("DELETE FROM templates WHERE id=?", (tid,))
    conn.commit()
    conn.close()
    flash("تم حذف القالب", "info")
    return redirect(url_for("message_templates_page"))


@app.route("/templates/<int:tid>/config", methods=["POST"])
def template_config(tid):
    """إعداد القالب: الحسابات المرسِلة له + رد الموظفين التلقائي عليه (إرسال + استقبال)."""
    f = request.form
    send_accounts = ",".join(a for a in f.getlist("send_accounts") if a.isdigit())
    reply_body = f.get("reply_body", "")
    conn = get_connection()
    if not conn.execute("SELECT 1 FROM templates WHERE id=?", (tid,)).fetchone():
        conn.close()
        abort(404)
    conn.execute("UPDATE templates SET send_accounts=?, reply_body=? WHERE id=?",
                 (send_accounts, reply_body, tid))
    conn.commit()
    conn.close()
    flash("تم حفظ إعدادات الإرسال والاستقبال للقالب", "success")
    return redirect(url_for("message_templates_page"))


# ------------------------------------------------------------------ الحملات
@app.route("/campaigns")
def campaigns():
    conn = get_connection()
    templates = conn.execute("SELECT id, name FROM templates ORDER BY name").fetchall()
    departments = [r["department"] for r in conn.execute(
        "SELECT DISTINCT department FROM employees WHERE active=1 ORDER BY department").fetchall()]
    raw = conn.execute("""
        SELECT c.*, t.name AS template_name,
               (SELECT COUNT(*) FROM campaign_recipients r WHERE r.campaign_id=c.id) AS total,
               (SELECT COUNT(*) FROM campaign_recipients r WHERE r.campaign_id=c.id AND r.status='sent') AS sent,
               (SELECT COUNT(*) FROM campaign_recipients r WHERE r.campaign_id=c.id AND r.status='failed') AS failed,
               (SELECT COUNT(*) FROM campaign_dept_templates dt WHERE dt.campaign_id=c.id) AS dept_count,
               (SELECT MAX(r.sent_at) FROM campaign_recipients r
                  WHERE r.campaign_id=c.id AND r.status='sent') AS last_sent,
               (SELECT MAX(er.replied_at) FROM emp_replies er WHERE er.employee_id IN
                  (SELECT r.employee_id FROM campaign_recipients r WHERE r.campaign_id=c.id)) AS last_reply,
               (SELECT COUNT(*) FROM mail_messages mm
                  WHERE mm.campaign_id=c.id AND mm.folder='inbox' AND mm.is_replied=1) AS replied
        FROM campaigns c JOIN templates t ON t.id=c.template_id
        ORDER BY c.id DESC
    """).fetchall()
    conn.close()
    rows = []
    for c in raw:
        d = dict(c)
        total = d["total"] or 0
        d["done"] = d["sent"] + d["failed"]
        d["pct_sent"] = round(100 * d["sent"] / total, 1) if total else 0
        d["pct_failed"] = round(100 * d["failed"] / total, 1) if total else 0
        d["replied"] = d.get("replied") or 0
        d["send_done"] = total > 0 and d["done"] >= total
        d["reply_done"] = total > 0 and d["replied"] >= total
        d["pct_reply"] = round(100 * d["replied"] / total) if total else 0
        d["pct_done"] = round(100 * d["done"] / total) if total else 0
        rows.append(d)
    conn2 = get_connection()
    accs = conn2.execute("SELECT id, email, display_name, "
                         "(SELECT COUNT(*) FROM employees e WHERE e.owner_account_id=accounts.id "
                         " AND e.active=1) AS n_emp FROM accounts ORDER BY id").fetchall()
    conn2.close()
    return render("campaigns.html", "الحملات", rows=rows, templates=templates,
                  departments=departments, accs=accs,
                  scope=request.args.get("scope", ""))


@app.route("/quick-send")
def quick_send():
    """شاشة إرسال سريع: قالب + حساب + تواريخ في مكان واحد → حملة فوراً."""
    conn = get_connection()
    templates = conn.execute("SELECT id, name FROM templates ORDER BY name").fetchall()
    accs = conn.execute(
        "SELECT id, email, display_name, "
        "(SELECT COUNT(*) FROM employees e WHERE e.owner_account_id=accounts.id "
        " AND e.active=1) AS n_emp FROM accounts ORDER BY id").fetchall()
    total_emp = conn.execute("SELECT COUNT(*) c FROM employees WHERE active=1").fetchone()["c"]
    conn.close()
    today = datetime.now().strftime("%Y-%m-%d")
    return render("quicksend.html", "إرسال سريع", templates=templates, accs=accs,
                  total_emp=total_emp, today=today)


@app.route("/campaigns/add", methods=["POST"])
def add_campaign():
    f = request.form
    name = (f.get("name", "") or "").strip()
    template_id = int(f["template_id"])
    flt = f.get("filter", "").strip().lower()
    scope_acc = (f.get("scope_account") or "").strip()
    send_date = (f.get("send_date", "") or "").strip()
    send_time = (f.get("send_time", "") or "12:00").strip() or "12:00"
    reply_date = (f.get("reply_date", "") or "").strip()
    reply_time = (f.get("reply_time", "") or "12:00").strip() or "12:00"

    # تاريخ الإرسال وتاريخ التسليم (الرد) إجباريان — معتمدان من داخل الحملة نفسها
    if not send_date or not reply_date:
        flash("لازم تحدّد تاريخ الإرسال وتاريخ التسليم (الرد) للحملة", "error")
        return redirect(url_for("campaigns"))

    conn = get_connection()
    cur = conn.cursor()
    valid_tpls = {r["id"]: r["name"] for r in
                  cur.execute("SELECT id, name FROM templates").fetchall()}
    if template_id not in valid_tpls:
        conn.close()
        flash("القالب غير موجود", "error")
        return redirect(url_for("campaigns"))

    # اسم تلقائي لو فاضي (يفيد شاشة الإرسال السريع): اسم القالب + تاريخ الإرسال
    if not name:
        name = "%s — %s" % (valid_tpls[template_id], send_date)

    cur.execute("""INSERT INTO campaigns (name, template_id, send_date, send_time,
                   reply_date, reply_time) VALUES (?, ?, ?, ?, ?, ?)""",
                (name, template_id, send_date, send_time, reply_date, reply_time))
    cid = cur.lastrowid

    # قوالب الأقسام
    dept_map = 0
    for key, val in f.items():
        if key.startswith("dept_tpl::") and val.strip().isdigit() and int(val) in valid_tpls:
            cur.execute("""INSERT INTO campaign_dept_templates (campaign_id, department, template_id)
                           VALUES (?, ?, ?)""", (cid, key[10:], int(val)))
            dept_map += 1

    where, params = ["active=1"], []
    if flt:
        where.append("(lower(name) LIKE ? OR lower(email) LIKE ? OR lower(department) LIKE ?)")
        params += [f"%{flt}%", f"%{flt}%", f"%{flt}%"]
    if scope_acc.isdigit():
        where.append("owner_account_id = ?")
        params.append(int(scope_acc))
    emps = cur.execute("SELECT id FROM employees WHERE " + " AND ".join(where), params).fetchall()

    cur.executemany("INSERT OR IGNORE INTO campaign_recipients (campaign_id, employee_id) VALUES (?, ?)",
                    [(cid, e["id"]) for e in emps])
    conn.commit()
    conn.close()
    extra = f" · {dept_map} قسم بقالب مخصّص" if dept_map else ""
    flash(f"أُنشئت الحملة بـ {len(emps)} مستلماً — تابع الإرسال لحظيًا هنا.{extra}", "success")
    return redirect(url_for("campaigns"))


@app.route("/campaigns/<int:cid>")
def campaign_detail(cid):
    conn = get_connection()
    c = conn.execute("""SELECT c.*, t.name AS template_name FROM campaigns c
                        JOIN templates t ON t.id=c.template_id WHERE c.id=?""", (cid,)).fetchone()
    if not c:
        conn.close()
        abort(404)
    recipients = conn.execute("""
        SELECT r.*, e.name, e.email FROM campaign_recipients r
        JOIN employees e ON e.id=r.employee_id
        WHERE r.campaign_id=? ORDER BY r.status, e.name
    """, (cid,)).fetchall()
    counts = {"sent": 0, "pending": 0, "failed": 0}
    for r in recipients:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    dept_tpls = conn.execute("""SELECT dt.department, t.name FROM campaign_dept_templates dt
                                JOIN templates t ON t.id=dt.template_id
                                WHERE dt.campaign_id=? ORDER BY dt.department""", (cid,)).fetchall()
    sched_on = conn.execute("SELECT enabled FROM schedule_settings WHERE id=1").fetchone()["enabled"]
    conn.close()
    return render("campaign_detail.html", f"حملة {c['name']}", c=c,
                  recipients=recipients, counts=counts, dept_tpls=dept_tpls,
                  scheduler_on=bool(sched_on))


@app.route("/campaigns/<int:cid>/<act>")
def campaign_action(cid, act):
    conn = get_connection()
    cur = conn.cursor()
    if not cur.execute("SELECT 1 FROM campaigns WHERE id=?", (cid,)).fetchone():
        conn.close()
        abort(404)

    if act == "pause":
        cur.execute("UPDATE campaigns SET status='paused' WHERE id=?", (cid,))
        flash("أُوقفت الحملة مؤقتاً", "info")
    elif act == "resume":
        cur.execute("UPDATE campaigns SET status='active' WHERE id=?", (cid,))
        flash("استُؤنفت الحملة", "info")
    elif act == "retry_failed":
        cur.execute("UPDATE campaign_recipients SET status='pending', error=NULL "
                    "WHERE campaign_id=? AND status='failed'", (cid,))
        cur.execute("UPDATE campaigns SET status='active' WHERE id=?", (cid,))
        flash("أُعيدت جدولة الرسائل الفاشلة", "info")
    elif act == "delete":
        cur.execute("DELETE FROM campaigns WHERE id=?", (cid,))
        conn.commit()
        conn.close()
        flash("تم حذف الحملة", "info")
        return redirect(url_for("campaigns"))
    elif act == "send_now":
        conn.commit()
        conn.close()
        threading.Thread(target=_run_batch_bg, daemon=True).start()
        flash("بدأ إرسال دفعة في الخلفية", "info")
        return redirect(url_for("campaign_detail", cid=cid))
    else:
        conn.close()
        abort(404)

    conn.commit()
    conn.close()
    return redirect(url_for("campaign_detail", cid=cid))


@app.route("/campaigns/<int:cid>/dates", methods=["POST"])
def campaign_edit_dates(cid):
    """تعديل تاريخ الإرسال/التسليم لحملة (يفيد الحملات اللي لسه ماتبعتتش)."""
    f = request.form
    send_date = (f.get("send_date", "") or "").strip()
    send_time = (f.get("send_time", "") or "12:00").strip() or "12:00"
    reply_date = (f.get("reply_date", "") or "").strip()
    reply_time = (f.get("reply_time", "") or "12:00").strip() or "12:00"
    if not send_date or not reply_date:
        flash("لازم تحدّد تاريخ الإرسال وتاريخ التسليم", "error")
        return redirect(url_for("campaigns"))
    conn = get_connection()
    if not conn.execute("SELECT 1 FROM campaigns WHERE id=?", (cid,)).fetchone():
        conn.close()
        abort(404)
    conn.execute("""UPDATE campaigns SET send_date=?, send_time=?, reply_date=?, reply_time=?
                    WHERE id=?""", (send_date, send_time, reply_date, reply_time, cid))
    conn.commit()
    conn.close()
    flash("تم تحديث تواريخ الحملة", "success")
    return redirect(url_for("campaigns"))


@app.route("/campaigns/<int:cid>/duplicate")
def campaign_duplicate(cid):
    """ينشئ نسخة جديدة من حملة موجودة: نفس القالب والمستلمين وقوالب الأقسام
    والتواريخ — كلهم جاهزين، وإنت بس تعدّل التاريخ لو حبيت."""
    conn = get_connection()
    cur = conn.cursor()
    c = cur.execute("SELECT * FROM campaigns WHERE id=?", (cid,)).fetchone()
    if not c:
        conn.close()
        abort(404)
    new_name = (c["name"] or "حملة") + " (نسخة)"
    cur.execute("""INSERT INTO campaigns (name, template_id, send_date, send_time,
                   reply_date, reply_time, status) VALUES (?, ?, ?, ?, ?, ?, 'active')""",
                (new_name, c["template_id"], c["send_date"], c["send_time"],
                 c["reply_date"], c["reply_time"]))
    new_cid = cur.lastrowid
    # قوالب الأقسام
    for dt in cur.execute("SELECT department, template_id FROM campaign_dept_templates "
                          "WHERE campaign_id=?", (cid,)).fetchall():
        cur.execute("""INSERT INTO campaign_dept_templates (campaign_id, department, template_id)
                       VALUES (?, ?, ?)""", (new_cid, dt["department"], dt["template_id"]))
    # نفس المستلمين (كلهم معلّقون من جديد)
    emp_ids = [r["employee_id"] for r in cur.execute(
        "SELECT employee_id FROM campaign_recipients WHERE campaign_id=?", (cid,)).fetchall()]
    cur.executemany("INSERT OR IGNORE INTO campaign_recipients (campaign_id, employee_id) "
                    "VALUES (?, ?)", [(new_cid, eid) for eid in emp_ids])
    conn.commit()
    conn.close()
    flash("اتعملت نسخة من الحملة بـ %d مستلماً — عدّل التاريخ لو حبيت من «تعديل التواريخ»."
          % len(emp_ids), "success")
    return redirect(url_for("campaign_detail", cid=new_cid))


@app.route("/campaigns/<int:cid>/export")
def campaign_export(cid):
    """يصدّر نتائج الحملة (المستلمون وحالاتهم) كملف CSV."""
    conn = get_connection()
    c = conn.execute("SELECT name FROM campaigns WHERE id=?", (cid,)).fetchone()
    if not c:
        conn.close()
        abort(404)
    rows = conn.execute("""
        SELECT e.name, e.email, e.department, r.status, r.attempts, r.error, r.sent_at
        FROM campaign_recipients r JOIN employees e ON e.id=r.employee_id
        WHERE r.campaign_id=? ORDER BY r.status, e.name""", (cid,)).fetchall()
    conn.close()
    status_ar = {"sent": "تم الإرسال", "pending": "معلّق", "failed": "فشل"}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["الاسم", "البريد", "القسم", "الحالة", "المحاولات", "الخطأ", "وقت الإرسال"])
    for r in rows:
        w.writerow([r["name"], r["email"], r["department"] or "",
                    status_ar.get(r["status"], r["status"]),
                    r["attempts"], r["error"] or "", r["sent_at"] or ""])
    fname = "campaign_%d.csv" % cid
    return Response(buf.getvalue().encode("utf-8-sig"), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=%s" % fname})


def _run_batch_bg():
    try:
        process_batch()
    except Exception:  # noqa: BLE001
        log.exception("خطأ في دفعة الخلفية")


# ------------------------------------------------------------------ الجدولة
_SCHED_KEYS = ["send_min_delay", "send_max_delay", "per_account_hourly_limit",
               "per_account_daily_limit", "randomize_send", "save_to_sent",
               "campaign_spread_seconds"]


@app.route("/schedule", methods=["GET", "POST"])
def schedule_page():
    conn = get_connection()
    if request.method == "POST":
        f = request.form
        conn.execute("""UPDATE schedule_settings SET batch_size=?, interval_minutes=?, enabled=?
                        WHERE id=1""",
                     (max(1, int(f["batch_size"])),
                      max(1, int(f["interval_minutes"])),
                      1 if f.get("enabled") else 0))
        conn.commit()
        conn.close()
        for k in ("send_min_delay", "send_max_delay",
                  "per_account_hourly_limit", "per_account_daily_limit",
                  "campaign_spread_seconds"):
            try:
                set_setting(k, max(0, int(f.get(k, "0"))))
            except ValueError:
                pass
        set_setting("randomize_send", "1" if f.get("randomize_send") else "0")
        set_setting("save_to_sent", "1" if f.get("save_to_sent") else "0")
        set_setting("campaign_send_date", (f.get("campaign_send_date", "") or "").strip())
        set_setting("campaign_send_time", (f.get("campaign_send_time", "") or "").strip())
        flash("تم حفظ إعدادات الجدولة والحماية", "success")
        return redirect(url_for("schedule_page"))
    s = conn.execute("SELECT * FROM schedule_settings WHERE id=1").fetchone()
    conn.close()
    cfg = {k: get_setting(k, "0") for k in _SCHED_KEYS}
    cfg["campaign_send_date"] = get_setting("campaign_send_date", "")
    cfg["campaign_send_time"] = get_setting("campaign_send_time", "")
    return render("schedule.html", "الجدولة والحماية", s=s, cfg=cfg)


@app.route("/send-now")
def send_now():
    threading.Thread(target=_run_batch_bg, daemon=True).start()
    flash("بدأ إرسال دفعة في الخلفية", "info")
    return redirect(url_for("schedule_page"))


# ------------------------------------------------------------------ الرد التلقائي (إعداد)
@app.route("/autoreply", methods=["GET", "POST"])
def autoreply_page():
    if request.method == "POST":
        set_setting("auto_reply_enabled", "1" if request.form.get("auto_reply_enabled") else "0")
        set_setting("auto_reply_subject", request.form.get("auto_reply_subject", "").strip())
        set_setting("auto_reply_body", request.form.get("auto_reply_body", ""))
        set_setting("mark_seen_on_fetch", "1" if request.form.get("mark_seen_on_fetch") else "0")
        flash("تم حفظ إعدادات الرد التلقائي", "success")
        return redirect(url_for("autoreply_page"))
    keys = ["auto_reply_enabled", "auto_reply_subject", "auto_reply_body", "mark_seen_on_fetch"]
    settings = {k: get_setting(k, "") for k in keys}
    return render("autoreply.html", "الرد التلقائي", settings=settings)


# ------------------------------------------------------------------ الرد العكسي
_REVERSE_KEYS = ["emp_imap_server", "emp_imap_port", "emp_smtp_server", "emp_smtp_port",
                 "emp_security", "reverse_enabled", "reverse_batch_size",
                 "reverse_min_delay", "reverse_max_delay", "reverse_default_reply",
                 "reverse_delay_minutes", "reverse_delay_seconds", "reverse_scan_minutes"]


def _reverse_ctx(conn):
    """يجمع متغيّرات قالب الرد العكسي (للعرض داخل صفحة القوالب الموحّدة)."""
    departments = [r["department"] for r in conn.execute(
        "SELECT DISTINCT department FROM employees ORDER BY department").fetchall()]
    dept_map = {r["department"]: r["body"]
                for r in conn.execute("SELECT department, body FROM dept_replies").fetchall()}
    accs = conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()
    acc_replies = {r["account_id"]: dict(r) for r in
                   conn.execute("SELECT * FROM account_replies").fetchall()}
    queue = conn.execute("""SELECT q.*, e.name, e.email AS emp_email FROM reverse_queue q
                            JOIN employees e ON e.id=q.employee_id
                            WHERE q.status='pending' ORDER BY q.due_at ASC LIMIT 40""").fetchall()
    emps = conn.execute("""SELECT e.id, e.name, e.email, e.department, e.emp_connected,
                                  (e.password != '') AS has_pw, e.owner_account_id,
                                  (SELECT COUNT(*) FROM emp_replies er
                                     WHERE er.employee_id=e.id AND er.status='sent') AS n_replies
                           FROM employees e WHERE e.active=1
                           ORDER BY e.email""").fetchall()
    stats = {
        "total": conn.execute("SELECT COUNT(*) c FROM employees").fetchone()["c"],
        "waiting": conn.execute("SELECT COUNT(*) c FROM reverse_queue "
                                "WHERE status='pending'").fetchone()["c"],
        "with_creds": conn.execute("SELECT COUNT(*) c FROM employees "
                                   "WHERE password != ''").fetchone()["c"],
        "sent": conn.execute("SELECT COUNT(*) c FROM emp_replies "
                             "WHERE status='sent'").fetchone()["c"],
        "failed": conn.execute("SELECT COUNT(*) c FROM emp_replies "
                               "WHERE status='failed'").fetchone()["c"],
    }
    return {"s": {k: get_setting(k, "") for k in _REVERSE_KEYS},
            "departments": departments, "dept_map": dept_map, "stats": stats,
            "accs": accs, "acc_replies": acc_replies, "queue": queue, "emps": emps,
            "delay_default": REVERSE_DELAY_DEFAULT, "scan_default": REVERSE_SCAN_DEFAULT}


@app.route("/reverse", methods=["GET", "POST"])
def reverse_page():
    conn = get_connection()
    if request.method == "POST":
        f = request.form
        for k in ("emp_imap_server", "emp_smtp_server", "emp_security", "reverse_default_reply"):
            set_setting(k, f.get(k, "").strip() if k != "reverse_default_reply" else f.get(k, ""))
        for k in ("emp_imap_port", "emp_smtp_port"):
            raw = f.get(k, "").strip()
            set_setting(k, str(max(0, int(raw))) if raw.isdigit() else "")
        for k in ("reverse_batch_size", "reverse_min_delay", "reverse_max_delay",
                  "reverse_delay_minutes", "reverse_delay_seconds", "reverse_scan_minutes"):
            try:
                set_setting(k, max(0, int(f.get(k, "0"))))
            except ValueError:
                pass
        set_setting("reverse_enabled", "1" if f.get("reverse_enabled") else "0")
        # نص الرد وتأخيره لكل حساب مرسِل
        for key, val in f.items():
            if not key.startswith("accrep::"):
                continue
            aid = key[8:]
            if not aid.isdigit():
                continue
            raw_delay = (f.get("accdelay::" + aid) or "").strip()
            delay = int(raw_delay) if raw_delay.isdigit() else 0
            conn.execute("""INSERT INTO account_replies (account_id, body, delay_minutes)
                            VALUES (?, ?, ?)
                            ON CONFLICT(account_id) DO UPDATE
                            SET body=excluded.body, delay_minutes=excluded.delay_minutes""",
                         (int(aid), val, max(0, delay)))
        # قوالب الرد حسب القسم
        for key, val in f.items():
            if key.startswith("dept::"):
                dept = key[6:]
                if val.strip():
                    conn.execute("""INSERT INTO dept_replies (department, body) VALUES (?, ?)
                                    ON CONFLICT(department) DO UPDATE SET body=excluded.body""",
                                 (dept, val))
                else:
                    conn.execute("DELETE FROM dept_replies WHERE department=?", (dept,))
        conn.commit()
        conn.close()
        flash("تم حفظ إعدادات الرد العكسي", "success")
        return redirect(url_for("message_templates_page") + "#reverse")

    # الصفحة اتدمجت مع «القوالب» — أي فتح مباشر يوجّه للشاشة الموحّدة
    conn.close()
    return redirect(url_for("message_templates_page") + "#reverse")


@app.route("/reverse/run")
def reverse_run():
    def _run_both():
        # فحص الصناديق الداخلية (محرك البرنامج) + صناديق IMAP معاً
        try:
            conn = get_connection()
            scan_reverse_internal(conn)
            conn.close()
        except Exception:  # noqa: BLE001
            log.exception("خطأ في الفحص الداخلي للرد العكسي")
        _safe(scan_reverse_inboxes)
    threading.Thread(target=_run_both, daemon=True).start()
    flash("بدأ فحص صناديق الموظفين في الخلفية — الردود ستُرسل في مواعيدها", "info")
    return redirect(url_for("message_templates_page") + "#reverse")


@app.route("/reverse/flush")
def reverse_flush():
    threading.Thread(target=lambda: _safe(flush_reverse_queue), daemon=True).start()
    flash("جارٍ إرسال الردود المستحقّة الآن", "info")
    return redirect(url_for("message_templates_page") + "#reverse")


def _safe(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001
        log.exception("خطأ في مهمة خلفية")


# ------------------------------------------------------------------ البريد (واجهة أوتلوك)
_folders_cache = {}          # key -> (وقت, قائمة المجلدات)
_FOLDERS_TTL = 90


def cached_folders(acct, force=False):
    key = _session_key(acct)
    now = time.time()
    hit = _folders_cache.get(key)
    if hit and not force and now - hit[0] < _FOLDERS_TTL:
        return hit[1]
    folders = mail_folders(acct, counts=True)
    _folders_cache[key] = (now, folders)
    return folders


def _mail_owner(kind, oid):
    """يعيد (acct, meta) لأي صندوق: حساب مرسِل أو صندوق موظف."""
    conn = get_connection()
    try:
        if kind == "account":
            row = conn.execute("SELECT * FROM accounts WHERE id=?", (oid,)).fetchone()
            if not row:
                return None, None
            return dict(row), {"kind": "account", "id": oid, "email": row["email"],
                               "title": row["display_name"] or row["email"]}
        if kind == "employee":
            row = conn.execute("SELECT * FROM employees WHERE id=?", (oid,)).fetchone()
            if not row:
                return None, None
            if not (row["password"] or "").strip():
                # موظف داخلي بدون كلمة مرور — اضبط الافتراضية عشان يفتح صندوقه
                if _email_domain_internal(conn, row["email"]):
                    conn.execute("UPDATE employees SET password=? WHERE id=?",
                                 (encrypt_secret(DEFAULT_MAILBOX_PASS), oid))
                    conn.commit()
                    row = conn.execute("SELECT * FROM employees WHERE id=?", (oid,)).fetchone()
                else:
                    return None, None
            return _emp_account(row), {"kind": "employee", "id": oid, "email": row["email"],
                                       "title": row["name"]}
    finally:
        conn.close()
    return None, None


def _mail_guard(kind, oid):
    """المدير يفتح أي صندوق، والموظف صندوقه فقط."""
    u = getattr(request, "user", None)
    if u is None:
        abort(403)
    if u["role"] == "admin":
        return
    if kind == "employee" and u["employee_id"] and int(oid) == int(u["employee_id"]):
        return
    abort(403)


def _mail_context(kind, oid):
    if kind not in ("account", "employee"):
        abort(404)
    _mail_guard(kind, oid)
    acct, meta = _mail_owner(kind, oid)
    if not acct:
        abort(404)
    return acct, meta


def _switch_lists():
    """قوائم التبديل السريع بين الصناديق (للمدير فقط)."""
    u = getattr(request, "user", None)
    if not u or u["role"] != "admin":
        return [], []
    conn = get_connection()
    accs = conn.execute("SELECT id, email, display_name FROM accounts ORDER BY id").fetchall()
    emps = conn.execute("""SELECT id, name, email FROM employees
                           WHERE password != '' AND active=1
                           ORDER BY emp_connected DESC, name LIMIT 40""").fetchall()
    conn.close()
    return accs, emps


@app.route("/mail")
def mail_home():
    u = request.user
    if u["role"] != "admin":
        if not u["employee_id"]:
            abort(403)
        return redirect(url_for("mail_view", kind="employee", oid=u["employee_id"]))
    conn = get_connection()
    a = conn.execute("SELECT id FROM accounts WHERE active=1 ORDER BY id LIMIT 1").fetchone()
    conn.close()
    if not a:
        flash("أضف حساباً مرسِلاً أولاً", "info")
        return redirect(url_for("accounts"))
    return redirect(url_for("mail_view", kind="account", oid=a["id"]))


@app.route("/mail/<kind>/<int:oid>")
def mail_view(kind, oid):
    acct, meta = _mail_context(kind, oid)
    folders, error = [], None
    try:
        folders = cached_folders(acct, force=request.args.get("refresh") == "1")
    except Exception as exc:  # noqa: BLE001
        error = "تعذّر الاتصال بصندوق %s: %s" % (meta["email"], exc)

    folder = request.args.get("f") or folder_by_kind(folders, "inbox", "INBOX")
    fkind = next((f["kind"] for f in folders if f["name"] == folder), "other")
    q = (request.args.get("q") or "").strip()
    unseen = request.args.get("unseen") == "1"
    page = request.args.get("p", 1)
    result = {"items": [], "total": 0, "page": 1, "pages": 1, "per_page": MAIL_PAGE_SIZE}
    if not error:
        try:
            result = mail_list(acct, folder, page=page, query=q, unseen_only=unseen)
        except Exception as exc:  # noqa: BLE001
            error = "تعذّر قراءة المجلد «%s»: %s" % (folder, exc)
            log.warning("mail_list %s/%s: %s", meta["email"], folder, exc)

    accs, emps = _switch_lists()
    folder_label = next((f["label"] for f in folders if f["name"] == folder), folder)
    return render("mail.html", "بريد %s" % meta["title"], kind=kind, oid=oid, meta=meta,
                  folders=folders, folder=folder, folder_kind=fkind, folder_label=folder_label,
                  page=result, q=q, unseen=1 if unseen else 0, error=error,
                  switch_accounts=accs, switch_employees=emps)


@app.route("/mail/<kind>/<int:oid>/m/<int:uid>")
def mail_message_view(kind, oid, uid):
    acct, meta = _mail_context(kind, oid)
    folder = request.args.get("f") or "INBOX"
    try:
        folders = cached_folders(acct)
    except Exception:  # noqa: BLE001
        folders = []
    try:
        m = mail_message(acct, folder, uid)
    except Exception as exc:  # noqa: BLE001
        flash("تعذّر فتح الرسالة: %s" % exc, "error")
        return redirect(url_for("mail_view", kind=kind, oid=oid, f=folder))
    show_images = request.args.get("images") == "1"
    html, blocked = sanitize_html(m["html"], block_images=not show_images)
    _folders_cache.pop(_session_key(acct), None)     # العدّاد تغيّر بعد القراءة
    if request.args.get("frag") == "1":
        bare = "1" if request.args.get("bare") == "1" else None
        return render_template("mail_frag.html", kind=kind, oid=oid, meta=meta,
                               folder=folder, m=m, html=html, blocked=blocked, bare=bare)
    return render("mail_message.html", m["subject"], kind=kind, oid=oid, meta=meta,
                  folders=folders, folder=folder, m=m, html=html, blocked=blocked)


@app.route("/mail/<kind>/<int:oid>/m/<int:uid>/att/<int:idx>")
def mail_attachment_dl(kind, oid, uid, idx):
    acct, meta = _mail_context(kind, oid)
    folder = request.args.get("f") or "INBOX"
    try:
        filename, ctype, data = mail_attachment(acct, folder, uid, idx)
    except Exception as exc:  # noqa: BLE001
        flash("تعذّر تنزيل المرفق: %s" % exc, "error")
        return redirect(url_for("mail_message_view", kind=kind, oid=oid, uid=uid, f=folder))
    from urllib.parse import quote
    disp = "attachment; filename*=UTF-8''%s" % quote(filename)
    return Response(data, mimetype=ctype or "application/octet-stream",
                    headers={"Content-Disposition": disp})


@app.route("/mail/<kind>/<int:oid>/act", methods=["POST"])
def mail_action(kind, oid):
    acct, meta = _mail_context(kind, oid)
    folder = request.form.get("f") or "INBOX"
    back = request.form.get("back") or url_for("mail_view", kind=kind, oid=oid, f=folder)
    uids = [u for u in request.form.getlist("uid") if u.strip().isdigit()]
    act = request.form.get("act") or ""
    if not uids:
        flash("لم تحدّد أي رسالة", "warning")
        return redirect(back)
    try:
        folders = cached_folders(acct)
        trash = folder_by_kind(folders, "trash", "")
        if act == "read":
            mail_flag(acct, folder, uids, r"\Seen", True)
            msg = "تم تعليم %d رسالة كمقروءة" % len(uids)
        elif act == "unread":
            mail_flag(acct, folder, uids, r"\Seen", False)
            msg = "تم تعليم %d رسالة كغير مقروءة" % len(uids)
        elif act == "flag":
            mail_flag(acct, folder, uids, r"\Flagged", True)
            msg = "تم وضع علامة على %d رسالة" % len(uids)
        elif act == "unflag":
            mail_flag(acct, folder, uids, r"\Flagged", False)
            msg = "تم إزالة العلامة"
        elif act == "delete":
            n, how = mail_delete(acct, folder, uids, trash=trash)
            msg = "%s (%d رسالة)" % (how, n)
        elif act == "purge":
            n, how = mail_delete(acct, folder, uids, trash=trash, purge=True)
            msg = "%s (%d رسالة)" % (how, n)
        elif act == "move":
            dest = request.form.get("dest") or ""
            if not dest:
                flash("اختر المجلد المنقول إليه", "warning")
                return redirect(back)
            n = mail_move(acct, folder, uids, dest)
            msg = "تم نقل %d رسالة إلى «%s»" % (n, dest)
        else:
            flash("إجراء غير معروف", "error")
            return redirect(back)
        _folders_cache.pop(_session_key(acct), None)
        flash(msg, "success")
    except Exception as exc:  # noqa: BLE001
        log.warning("mail_action %s: %s", act, exc)
        flash("تعذّر تنفيذ الإجراء: %s" % exc, "error")
    return redirect(back)


def _quote_original(m):
    head = ["", "", "-------- الرسالة الأصلية --------",
            "من: %s <%s>" % (m["from_name"], m["from_email"]),
            "التاريخ: %s" % m["date"],
            "إلى: %s" % m["to"]]
    if m["cc"]:
        head.append("نسخة: %s" % m["cc"])
    head.append("الموضوع: %s" % m["subject"])
    head.append("")
    body = m["text"] or ""
    quoted = "\n".join("> " + ln for ln in body.splitlines())
    return "\n".join(head) + "\n" + quoted


def _addr_list(text):
    out = []
    for chunk in (text or "").replace(";", ",").split(","):
        _, addr = parseaddr(chunk.strip())
        if addr:
            out.append(addr)
    return out


@app.route("/mail/<kind>/<int:oid>/compose", methods=["GET", "POST"])
def mail_compose(kind, oid):
    acct, meta = _mail_context(kind, oid)
    folder = request.args.get("f") or "INBOX"
    mode = request.args.get("mode") or "new"
    uid = request.args.get("uid") or ""
    bare = "1" if request.args.get("bare") == "1" else None
    back = url_for("mail_view", kind=kind, oid=oid, f=folder, bare=bare)
    try:
        folders = cached_folders(acct)
    except Exception:  # noqa: BLE001
        folders = []
    sent_folder = folder_by_kind(folders, "sent", "")

    src = None
    if uid.isdigit() and mode in ("reply", "replyall", "forward"):
        try:
            src = mail_message(acct, folder, int(uid), mark_seen=False)
        except Exception as exc:  # noqa: BLE001
            flash("تعذّر تحميل الرسالة الأصلية: %s" % exc, "error")
            src = None

    if request.method == "POST":
        to_list = _addr_list(request.form.get("to"))
        cc_list = _addr_list(request.form.get("cc"))
        subject = (request.form.get("subject") or "").strip()
        body = request.form.get("body") or ""
        if not to_list:
            flash("اكتب مستلماً واحداً على الأقل", "error")
            return redirect(request.full_path)

        atts = []
        for fs in request.files.getlist("files"):
            if fs and fs.filename:
                atts.append((fs.filename, fs.mimetype or "application/octet-stream", fs.read()))
        if mode == "forward" and src:
            for a in src["attachments"]:
                try:
                    fn, ct, data = mail_attachment(acct, folder, int(uid), a["idx"])
                    atts.append((fn, ct, data))
                except Exception as exc:  # noqa: BLE001
                    log.debug("مرفق إعادة التوجيه: %s", exc)

        in_reply_to = src["message_id"] if (src and mode in ("reply", "replyall")) else None
        refs = " ".join(x for x in [(src or {}).get("references"), in_reply_to] if x) or None
        is_html = request.form.get("html") == "1"
        ok, err = send_mail_full(acct, to_list, cc_list, subject, body, attachments=atts,
                                 in_reply_to=in_reply_to, references=refs,
                                 sent_folder=sent_folder or None, html_body=is_html)
        if not ok:
            flash("فشل الإرسال: %s" % err, "error")
            return redirect(request.full_path)
        if src and mode in ("reply", "replyall"):
            try:
                mail_flag(acct, folder, [int(uid)], r"\Answered", True)
            except Exception as exc:  # noqa: BLE001
                log.debug("تعليم \\Answered: %s", exc)
        _folders_cache.pop(_session_key(acct), None)
        flash("تم إرسال الرسالة إلى %s" % ", ".join(to_list), "success")
        return redirect(back)

    # توقيع المرسِل تلقائياً من السيرفر (التصميم الاحترافي افتراضياً)
    style = get_setting("signature_style", "rich")
    conn = get_connection()
    sig_text = ""
    sig_html = ""
    try:
        if kind == "account":
            a = conn.execute("SELECT signature, logo, display_name, email FROM accounts WHERE id=?",
                             (oid,)).fetchone()
            if a:
                ent = {"name": a["display_name"] or "", "email": a["email"],
                       "title": "", "department": "", "phone": ""}
                if style == "rich":
                    sig_html = _rich_signature_html(ent, _effective_logo(a["logo"]))
                else:
                    sig_text = _render_sig_text(a["signature"], ent)
        else:
            e = conn.execute("SELECT * FROM employees WHERE id=?", (oid,)).fetchone()
            if e:
                _st, elogo = resolve_signature(conn, e)
                if style == "rich":
                    ent = {"name": e["name"], "title": e["title"],
                           "department": e["department"], "email": e["email"]}
                    sig_html = _rich_signature_html(ent, _effective_logo(elogo))
                else:
                    sig_text = _st
    finally:
        conn.close()

    to = cc = subject = body = ""
    fwd_atts = 0
    heading = "رسالة جديدة"
    quoted = ""
    if src:
        if mode == "forward":
            heading = "إعادة توجيه"
            subject = src["subject"] if src["subject"].lower().startswith("fwd:") \
                else "Fwd: " + src["subject"]
            fwd_atts = len(src["attachments"])
        else:
            heading = "رد على الكل" if mode == "replyall" else "رد"
            subject = src["subject"] if src["subject"].lower().startswith("re:") \
                else "Re: " + src["subject"]
            to = src["from_email"]
            if mode == "replyall":
                mine = (meta["email"] or "").lower()
                others = [a for a in _addr_list(src["to"]) + _addr_list(src["cc"])
                          if a.lower() not in (mine, src["from_email"])]
                cc = ", ".join(dict.fromkeys(others))
        quoted = _quote_original(src)
        back = url_for("mail_message_view", kind=kind, oid=oid, uid=int(uid), f=folder, bare=bare)

    if sig_html:
        # جسم HTML: مساحة فوق بحيث يكتب المستخدم فوق والتوقيع الاحترافي تحت
        body = "<br>" * 6 + sig_html
        if quoted:
            body += "<br><br>" + _text_to_html(quoted)
    else:
        sig_block = ("\n" * 8 + sig_text) if sig_text else ""
        body = sig_block + (("\n\n" + quoted) if quoted else "")

    return render("mail_compose.html", heading, kind=kind, oid=oid, meta=meta, folder=folder,
                  mode=mode, uid=uid, heading=heading, to=to, cc=cc, subject=subject,
                  body=body, back=back, fwd_atts=fwd_atts)


@app.route("/api/mailbox-counts/<kind>/<int:oid>")
def api_mailbox_counts(kind, oid):
    """عدّاد الوارد الحيّ (يُستدعى من صفحة صناديق البريد بدون تعطيلها)."""
    acct, meta = _mail_context(kind, oid)
    try:
        return mailbox_quick_counts(acct)
    except Exception as exc:  # noqa: BLE001
        return {"total": 0, "unseen": 0, "error": str(exc)}


# ------------------------------------------------------------------ صناديق البريد
@app.route("/mailboxes")
def mailboxes():
    conn = get_connection()
    accs = conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()
    emps = conn.execute("""SELECT * FROM employees WHERE password != ''
                           ORDER BY emp_connected DESC, name""").fetchall()
    conn.close()
    return render("mailboxes.html", "صناديق البريد", accs=accs, emps=emps)

# ------------------------------------------------------------------ توافق مع الروابط القديمة
@app.route("/inbox")
def inbox():
    return redirect(url_for("mail_home"))


@app.route("/inbox/refresh")
def refresh_inbox():
    conn = get_connection()
    a = conn.execute("SELECT id FROM accounts WHERE active=1 ORDER BY id LIMIT 1").fetchone()
    conn.close()
    if not a:
        return redirect(url_for("accounts"))
    return redirect(url_for("mail_view", kind="account", oid=a["id"], refresh=1))


@app.route("/mailbox/<kind>/<int:oid>")
def mailbox_view(kind, oid):
    return redirect(url_for("mail_view", kind=kind, oid=oid,
                            f=request.args.get("folder") or None))


# ------------------------------------------------------------------ الرد التلقائي على وارد الحسابات
@app.route("/inbox/auto-reply-all")
def auto_reply_all():
    """يرد تلقائياً على كل رسالة غير مقروءة وغير مردود عليها في وارد الحسابات الـ5."""
    if get_setting("auto_reply_enabled", "0") != "1":
        flash("الرد التلقائي غير مُفعّل — فعّله من صفحة الإعداد", "warning")
        return redirect(url_for("autoreply_page"))
    body_tpl = get_setting("auto_reply_body", "") or ""
    subj_tpl = get_setting("auto_reply_subject", "") or ""
    if not body_tpl.strip():
        flash("نص الرد التلقائي فارغ", "warning")
        return redirect(url_for("autoreply_page"))

    conn = get_connection()
    accounts = conn.execute("SELECT * FROM accounts WHERE active=1").fetchall()
    conn.close()
    done = fail = 0
    for row in accounts:
        acct = dict(row)
        try:
            folders = cached_folders(acct, force=True)
            inbox_folder = folder_by_kind(folders, "inbox", "INBOX")
            sent_folder = folder_by_kind(folders, "sent", "") or None
            res = mail_list(acct, inbox_folder, per_page=100, unseen_only=True)
        except Exception as exc:  # noqa: BLE001
            log.warning("رد تلقائي: تعذّر فتح %s: %s", acct["email"], exc)
            fail += 1
            continue
        for m in res["items"]:
            if m["answered"] or not m["from_email"]:
                continue
            subject = subj_tpl or m["subject"]
            if not subject.lower().startswith("re:"):
                subject = "Re: " + subject
            ok, err = send_mail_full(acct, [m["from_email"]], [], subject, body_tpl,
                                     in_reply_to=m["message_id"] or None,
                                     sent_folder=sent_folder)
            if ok:
                done += 1
                try:
                    mail_flag(acct, inbox_folder, [m["uid"]], r"\Answered", True)
                except Exception as exc:  # noqa: BLE001
                    log.debug("تعليم \\Answered: %s", exc)
            else:
                fail += 1
                log.warning("رد تلقائي فشل %s → %s: %s", acct["email"], m["from_email"], err)
    flash("تم إرسال %d رد%s" % (done, (" وفشل %d" % fail) if fail else ""),
          "success" if done else "warning")
    return redirect(url_for("mail_home"))


# ------------------------------------------------------------------ النشر على سيرفر عبر SSH
try:
    import paramiko
    HAVE_SSH = True
except Exception:  # pragma: no cover
    paramiko = None
    HAVE_SSH = False
    log.warning("مكتبة paramiko غير مثبّتة → صفحة «السيرفر» لن تعمل. ثبّتها بـ: pip install paramiko")

# مصدر الملفات التي تُرفع للسيرفر (داخل الـ .exe تكون في مجلد الاستخراج المؤقت)
SRC_DIR = getattr(sys, "_MEIPASS", BASE_DIR)
DEPLOY_SERVICE = "email-manager"
DEPLOY_KEYS = {
    "deploy_host": "", "deploy_port": "22", "deploy_user": "root",
    "deploy_auth": "password", "deploy_key_pass": "", "deploy_domain": "",
    "deploy_ssl": "1", "deploy_le_email": "", "deploy_dir": "/opt/email_manager",
    "deploy_app_port": "8000", "deploy_last_at": "", "deploy_last_status": "",
}
DEPLOY_SECRET_KEYS = ("deploy_key", "deploy_password", "deploy_key_pass")

_deploy_lock = threading.Lock()
_DEPLOY = {"running": False, "log": [], "status": "", "url": "", "task": ""}


def deploy_cfg():
    """يقرأ إعدادات النشر (المفتاح/كلمة المرور مفكوكة التشفير)."""
    cfg = {k: get_setting(k, d) for k, d in DEPLOY_KEYS.items()}
    for k in DEPLOY_SECRET_KEYS:
        cfg[k] = decrypt_secret(get_setting(k, "") or "")
    return cfg


def _dlog(msg, level="info"):
    line = "[%s] %s" % (datetime.now().strftime("%H:%M:%S"), msg)
    with _deploy_lock:
        _DEPLOY["log"].append(line)
        if len(_DEPLOY["log"]) > 2000:
            del _DEPLOY["log"][:500]
    getattr(log, level, log.info)("deploy: %s", msg)


def _deploy_start(task):
    """يحجز مهمة نشر واحدة في وقت واحد. يعيد False لو مهمة أخرى تعمل."""
    with _deploy_lock:
        if _DEPLOY["running"]:
            return False
        _DEPLOY.update(running=True, log=[], status="running", url="", task=task)
        return True


def _deploy_finish(ok, url=""):
    with _deploy_lock:
        _DEPLOY.update(running=False, status="ok" if ok else "error", url=url)
    set_setting("deploy_last_at", datetime.now().strftime("%Y-%m-%d %H:%M"))
    set_setting("deploy_last_status", "ok" if ok else "error")


def load_private_key(text, passphrase=""):
    """يحمّل مفتاحاً خاصاً (OpenSSH/PEM) بأي خوارزمية يدعمها paramiko."""
    text = (text or "").strip().replace("\r\n", "\n") + "\n"
    pw = passphrase or None
    last = None
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(text), password=pw)
        except paramiko.PasswordRequiredException as exc:
            raise ValueError("المفتاح محمي بعبارة مرور — أدخلها في الحقل المخصص") from exc
        except Exception as exc:  # noqa: BLE001
            last = exc
    raise ValueError("تعذّر قراءة المفتاح الخاص: %s" % last)


def generate_ssh_keypair():
    """يولّد زوج مفاتيح ed25519 (أو RSA لو لم تتوفر cryptography). يعيد (private, public)."""
    if HAVE_CRYPTO:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        k = Ed25519PrivateKey.generate()
        priv = k.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.OpenSSH,
                               serialization.NoEncryption()).decode()
        pub = k.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                          serialization.PublicFormat.OpenSSH).decode()
        return priv, pub + " email-manager"
    k = paramiko.RSAKey.generate(3072)
    buf = io.StringIO()
    k.write_private_key(buf)
    return buf.getvalue(), "ssh-rsa %s email-manager" % k.get_base64()


def public_key_of(text, passphrase=""):
    try:
        k = load_private_key(text, passphrase)
        return "%s %s email-manager" % (k.get_name(), k.get_base64())
    except Exception:  # noqa: BLE001
        return ""


def ssh_connect(cfg, timeout=20):
    """يفتح اتصال SSH حسب الإعدادات المحفوظة. يرفع استثناءً عربياً واضحاً عند الفشل."""
    if not HAVE_SSH:
        raise RuntimeError("مكتبة paramiko غير مثبّتة (pip install paramiko)")
    host = (cfg.get("deploy_host") or "").strip()
    if not host:
        raise RuntimeError("أدخل عنوان السيرفر (IP أو اسم مضيف) أولاً")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = dict(hostname=host, port=int(cfg.get("deploy_port") or 22),
              username=(cfg.get("deploy_user") or "root").strip(),
              timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
              allow_agent=False, look_for_keys=False)
    if cfg.get("deploy_auth") == "password":
        if not cfg.get("deploy_password"):
            raise RuntimeError("كلمة مرور السيرفر فارغة")
        kw["password"] = cfg["deploy_password"]
    else:
        if not cfg.get("deploy_key"):
            raise RuntimeError("لا يوجد مفتاح SSH محفوظ — الصقه أو ولّد واحداً من الصفحة")
        kw["pkey"] = load_private_key(cfg["deploy_key"], cfg.get("deploy_key_pass"))
    try:
        client.connect(**kw)
    except paramiko.AuthenticationException as exc:
        if "password" in kw:
            raise RuntimeError("فشلت المصادقة: اسم المستخدم أو كلمة المرور غير صحيحة "
                               "(وتأكد أن السيرفر يسمح بالدخول بكلمة مرور: PasswordAuthentication yes)") from exc
        raise RuntimeError("فشلت المصادقة: تأكد أن المفتاح العام مضاف في "
                           "~/.ssh/authorized_keys على السيرفر") from exc
    except (paramiko.SSHException, OSError) as exc:
        raise RuntimeError("تعذّر الاتصال بـ %s:%s — %s" % (host, kw["port"], exc)) from exc
    return client


class _Remote:
    """غلاف بسيط لتنفيذ أوامر ورفع ملفات على السيرفر مع تسجيل كل شيء في سجل النشر."""

    def __init__(self, client, user):
        self.c = client
        self.sudo = (user or "root").strip() != "root"
        self.sftp = client.open_sftp()

    def run(self, cmd, check=True, quiet=False, timeout=900):
        full = ("sudo -n " if self.sudo else "") + "bash -c %s" % _shq(cmd)
        if not quiet:
            _dlog("$ " + cmd.strip().splitlines()[0][:160])
        stdin, stdout, stderr = self.c.exec_command(full, timeout=timeout, get_pty=False)
        stdin.close()
        out_lines = []
        for line in iter(stdout.readline, ""):
            line = line.rstrip("\n")
            out_lines.append(line)
            if not quiet and line.strip():
                _dlog("  " + line[:300])
        err = stderr.read().decode("utf-8", "replace").strip()
        rc = stdout.channel.recv_exit_status()
        if err and (rc != 0 or not quiet):
            for line in err.splitlines()[-15:]:
                _dlog("  ! " + line[:300], "warning")
        if check and rc != 0:
            raise RuntimeError("فشل الأمر (رمز %d): %s" % (rc, cmd.strip().splitlines()[0][:120]))
        return rc, "\n".join(out_lines)

    def write_file(self, remote_path, content, mode=0o644):
        """يكتب ملفاً نصياً (عبر /tmp ثم نقل بصلاحيات sudo لو لزم)."""
        tmp = "/tmp/em_upload_%s" % secrets.token_hex(6)
        with self.sftp.open(tmp, "w") as fh:
            fh.write(content)
        self.run("install -m %o %s %s && rm -f %s" % (mode, _shq(tmp), _shq(remote_path), _shq(tmp)),
                 quiet=True)

    def put(self, local_path, remote_path, mode=None):
        tmp = "/tmp/em_upload_%s" % secrets.token_hex(6)
        self.sftp.put(local_path, tmp)
        self.run("mv -f %s %s%s" % (_shq(tmp), _shq(remote_path),
                                    (" && chmod %o %s" % (mode, _shq(remote_path))) if mode else ""),
                 quiet=True)
        _dlog("↑ رُفع %s" % os.path.basename(local_path))

    def close(self):
        try:
            self.sftp.close()
        finally:
            self.c.close()


def _shq(s):
    """اقتباس آمن لـ bash."""
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


_SYSTEMD_UNIT = """[Unit]
Description=Email Manager
After=network.target

[Service]
Type=simple
WorkingDirectory={dir}
Environment=EM_HOST=127.0.0.1
Environment=EM_PORT={port}
Environment=EM_NO_BROWSER=1
Environment=PYTHONUNBUFFERED=1
ExecStart={dir}/venv/bin/python {dir}/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

_NGINX_SITE = """server {{
    listen 80;
    listen [::]:80;
    server_name {server_name};
    client_max_body_size 50m;

    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
    }}
}}
"""


def _db_snapshot(path):
    """نسخة متسقة من قاعدة البيانات (آمنة أثناء التشغيل مع WAL)."""
    src = sqlite3.connect(DB_NAME)
    dst = sqlite3.connect(path)
    with dst:
        src.backup(dst)
    dst.close()
    src.close()


def deploy_job(cfg, copy_data):
    """المهمة الكاملة: تجهيز السيرفر + رفع الملفات + خدمة systemd + Nginx + SSL."""
    r = None
    try:
        rdir = (cfg.get("deploy_dir") or "/opt/email_manager").rstrip("/") or "/opt/email_manager"
        port = int(cfg.get("deploy_app_port") or 8000)
        domain = (cfg.get("deploy_domain") or "").strip().lower()
        want_ssl = cfg.get("deploy_ssl") == "1" and bool(domain)
        le_email = (cfg.get("deploy_le_email") or "").strip()

        _dlog("الاتصال بـ %s ..." % cfg["deploy_host"])
        client = ssh_connect(cfg)
        r = _Remote(client, cfg.get("deploy_user"))
        _, uname = r.run("uname -a", quiet=True)
        _dlog("متصل: " + uname.strip()[:120])

        # 1) الحزم
        _dlog("── 1/6 المتطلبات (python3 / nginx%s)" % (" / certbot" if want_ssl else ""))
        need = "python3 nginx" + (" certbot" if want_ssl else "")
        rc_have, _ = r.run("for b in %s; do command -v $b >/dev/null || exit 1; done; "
                           "python3 -c 'import venv, ensurepip' 2>/dev/null" % need, check=False, quiet=True)
        rc, _ = r.run("command -v apt-get >/dev/null", check=False, quiet=True)
        if rc == 0:
            nginx_conf = "/etc/nginx/sites-available/%s" % DEPLOY_SERVICE
            nginx_link = "/etc/nginx/sites-enabled/%s" % DEPLOY_SERVICE
            if rc_have != 0:
                pk = "python3 python3-venv python3-pip nginx"
                if want_ssl:
                    pk += " certbot python3-certbot-nginx"
                r.run("export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && "
                      "apt-get install -y -qq %s" % pk)
        else:
            rc, _ = r.run("command -v dnf >/dev/null || command -v yum >/dev/null",
                          check=False, quiet=True)
            if rc != 0:
                raise RuntimeError("نظام غير مدعوم: يلزم Debian/Ubuntu (apt) أو RHEL/Fedora (dnf)")
            nginx_conf = "/etc/nginx/conf.d/%s.conf" % DEPLOY_SERVICE
            nginx_link = None
            if rc_have != 0:
                pk = "python3 python3-pip nginx"
                if want_ssl:
                    pk += " certbot python3-certbot-nginx"
                r.run("(command -v dnf >/dev/null && dnf install -y -q %s) || yum install -y -q %s" % (pk, pk))
        if rc_have == 0:
            _dlog("كل المتطلبات مثبّتة مسبقاً — تخطٍّ ✔")

        # 2) الملفات
        _dlog("── 2/6 رفع ملفات البرنامج إلى %s" % rdir)
        r.run("mkdir -p %s/data" % _shq(rdir), quiet=True)
        for name in ("app.py", "requirements.txt"):
            p = os.path.join(SRC_DIR, name)
            if not os.path.exists(p):
                raise RuntimeError("الملف %s غير موجود بجوار البرنامج — لا يمكن رفعه" % name)
            r.put(p, "%s/%s" % (rdir, name))
        r.run("grep -q '^paramiko' %s/requirements.txt || echo 'paramiko>=3.0' >> %s/requirements.txt"
              % (_shq(rdir), _shq(rdir)), quiet=True)

        rc, _ = r.run("test -f %s/data/email_manager.db" % _shq(rdir), check=False, quiet=True)
        remote_has_db = rc == 0
        if copy_data == "always" or (copy_data == "first" and not remote_has_db):
            _dlog("نسخ قاعدة البيانات والمفاتيح إلى السيرفر%s"
                  % (" (استبدال الموجود)" if remote_has_db else ""))
            r.run("systemctl stop %s 2>/dev/null || true" % DEPLOY_SERVICE, quiet=True)
            snap = os.path.join(DATA_DIR, "_deploy_snapshot.db")
            _db_snapshot(snap)
            try:
                r.put(snap, "%s/data/email_manager.db" % rdir, mode=0o600)
            finally:
                try:
                    os.remove(snap)
                except OSError:
                    pass
            for f in (KEY_FILE, FLASK_SECRET_FILE):
                if os.path.exists(f):
                    r.put(f, "%s/data/%s" % (rdir, os.path.basename(f)), mode=0o600)
            r.run("rm -f %s/data/email_manager.db-wal %s/data/email_manager.db-shm"
                  % (_shq(rdir), _shq(rdir)), quiet=True)
        elif remote_has_db:
            _dlog("قاعدة بيانات السيرفر موجودة — لم تُلمَس (اختر «استبدال» لو أردت نسخ بياناتك المحلية)")

        # 3) بيئة بايثون
        _dlog("── 3/6 بيئة Python والمكتبات")
        rc, _ = r.run("cd %s && test -x venv/bin/python && test -f .req.sha && "
                      "sha256sum -c --quiet .req.sha" % _shq(rdir), check=False, quiet=True)
        if rc == 0:
            _dlog("المكتبات مثبّتة ولم تتغير — تخطٍّ ✔")
        else:
            r.run("cd %s && (test -x venv/bin/python || python3 -m venv venv) && "
                  "venv/bin/pip install -q --upgrade pip && venv/bin/pip install -q -r requirements.txt && "
                  "sha256sum requirements.txt > .req.sha" % _shq(rdir))

        # 4) خدمة systemd
        _dlog("── 4/6 إنشاء خدمة systemd (%s)" % DEPLOY_SERVICE)
        r.write_file("/etc/systemd/system/%s.service" % DEPLOY_SERVICE,
                     _SYSTEMD_UNIT.format(dir=rdir, port=port))
        r.run("chmod 700 %s/data; systemctl daemon-reload && systemctl enable %s -q && "
              "systemctl restart %s" % (_shq(rdir), DEPLOY_SERVICE, DEPLOY_SERVICE))
        time.sleep(2)
        rc, _ = r.run("systemctl is-active --quiet %s" % DEPLOY_SERVICE, check=False, quiet=True)
        if rc != 0:
            r.run("journalctl -u %s -n 30 --no-pager" % DEPLOY_SERVICE, check=False)
            raise RuntimeError("الخدمة لم تعمل — راجع السطور أعلاه من journalctl")
        _dlog("الخدمة تعمل ✔")

        # 5) Nginx
        _dlog("── 5/6 إعداد Nginx%s" % ((" للدومين " + domain) if domain else " (بدون دومين)"))
        r.write_file(nginx_conf, _NGINX_SITE.format(server_name=domain or "_", port=port))
        if nginx_link:
            r.run("ln -sf %s %s; rm -f /etc/nginx/sites-enabled/default" % (nginx_conf, nginx_link),
                  quiet=True)
        r.run("nginx -t 2>&1 && systemctl enable nginx -q && systemctl restart nginx")
        r.run("command -v ufw >/dev/null && ufw status | grep -q 'Status: active' && "
              "ufw allow 80/tcp >/dev/null && ufw allow 443/tcp >/dev/null; "
              "command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1 && "
              "firewall-cmd -q --permanent --add-service=http --add-service=https && "
              "firewall-cmd -q --reload; true", check=False, quiet=True)

        # 6) SSL
        url = "http://%s" % (domain or cfg["deploy_host"])
        if want_ssl:
            rc, _ = r.run("test -f /etc/letsencrypt/live/%s/fullchain.pem" % _shq(domain),
                          check=False, quiet=True)
            if rc == 0:
                _dlog("── 6/6 شهادة SSL موجودة مسبقاً — تخطٍّ ✔ (تُجدَّد تلقائياً)")
                # إعداد Nginx أُعيدت كتابته في الخطوة 5 → أعد ربط الشهادة به
                rc2, _ = r.run("certbot install --nginx -n --cert-name %s --redirect" % _shq(domain),
                               check=False, quiet=True)
                if rc2 != 0:
                    _dlog("تعذّر إعادة ربط الشهادة بـ Nginx — نفّذ «نشر» مرة أخرى أو راجع certbot", "warning")
                url = "https://%s" % domain
                rc = None
            else:
                _dlog("── 6/6 إصدار شهادة SSL من Let's Encrypt للدومين %s" % domain)
                mail_opt = ("-m %s" % _shq(le_email)) if le_email else "--register-unsafely-without-email"
                rc, _ = r.run("certbot --nginx -n --agree-tos %s -d %s --redirect" % (mail_opt, _shq(domain)),
                              check=False)
            if rc is None:
                pass
            elif rc == 0:
                url = "https://%s" % domain
                _dlog("الشهادة صدرت والتجديد تلقائي ✔")
            else:
                _dlog("تعذّر إصدار الشهادة (هل الدومين يشير إلى IP السيرفر؟). "
                      "البرنامج يعمل على HTTP، وأعد المحاولة بعد ضبط DNS.", "warning")
        else:
            _dlog("── 6/6 SSL متجاوز (لا دومين أو الخيار معطّل)")

        _dlog("✅ اكتمل النشر — افتح: %s" % url)
        _deploy_finish(True, url)
    except Exception as exc:  # noqa: BLE001
        _dlog("❌ توقف النشر: %s" % exc, "error")
        _deploy_finish(False)
    finally:
        if r:
            r.close()


def server_action_job(cfg, act):
    """أوامر سريعة على السيرفر: حالة / إعادة تشغيل / إيقاف / سجلّات."""
    r = None
    try:
        client = ssh_connect(cfg)
        r = _Remote(client, cfg.get("deploy_user"))
        svc = DEPLOY_SERVICE
        cmd = {
            "status": "systemctl status %s --no-pager -l | head -n 25" % svc,
            "restart": "systemctl restart %s && sleep 2 && systemctl is-active %s" % (svc, svc),
            "stop": "systemctl stop %s && echo stopped" % svc,
            "start": "systemctl start %s && sleep 2 && systemctl is-active %s" % (svc, svc),
            "logs": "journalctl -u %s -n 80 --no-pager" % svc,
            "nginx": "nginx -t 2>&1; systemctl is-active nginx",
        }[act]
        r.run(cmd, check=False)
        _dlog("✔ تم")
        _deploy_finish(True)
    except Exception as exc:  # noqa: BLE001
        _dlog("❌ %s" % exc, "error")
        _deploy_finish(False)
    finally:
        if r:
            r.close()


@app.route("/server", methods=["GET", "POST"])
def server_page():
    if request.method == "POST":
        f = request.form
        for k in ("deploy_host", "deploy_user", "deploy_domain", "deploy_le_email", "deploy_dir"):
            set_setting(k, (f.get(k) or DEPLOY_KEYS[k]).strip())
        for k in ("deploy_port", "deploy_app_port"):
            try:
                set_setting(k, max(1, int(f.get(k) or DEPLOY_KEYS[k])))
            except ValueError:
                set_setting(k, DEPLOY_KEYS[k])
        set_setting("deploy_auth", "password" if f.get("deploy_auth") == "password" else "key")
        set_setting("deploy_ssl", "1" if f.get("deploy_ssl") else "0")
        # المفتاح: ملف مرفوع ← نص ملصوق ← الإبقاء على المحفوظ
        key_text = ""
        up = request.files.get("deploy_key_file")
        if up and up.filename:
            key_text = up.read().decode("utf-8", "replace")
        elif (f.get("deploy_key") or "").strip():
            key_text = f["deploy_key"]
        if f.get("deploy_key_pass") is not None:
            set_setting("deploy_key_pass", encrypt_secret(f.get("deploy_key_pass", "")))
        if key_text.strip():
            kt = key_text.strip()
            if kt.startswith(("ssh-", "ecdsa-")):
                flash("هذا مفتاح عام (يبدأ بـ ssh-) — المطلوب هنا المفتاح الخاص. لم يُحفظ، والمفتاح السابق كما هو.", "error")
                return redirect(url_for("server_page"))
            if HAVE_SSH:
                try:
                    load_private_key(kt, f.get("deploy_key_pass", ""))
                except ValueError as exc:
                    flash("لم يُحفظ المفتاح: %s — المفتاح السابق كما هو." % exc, "error")
                    return redirect(url_for("server_page"))
            set_setting("deploy_key", encrypt_secret(kt))
        if (f.get("deploy_password") or ""):
            set_setting("deploy_password", encrypt_secret(f["deploy_password"]))
        flash("تم حفظ إعدادات السيرفر", "success")
        return redirect(url_for("server_page"))

    cfg = deploy_cfg()
    pub = public_key_of(cfg["deploy_key"], cfg["deploy_key_pass"]) if (HAVE_SSH and cfg["deploy_key"]) else ""
    local_key = os.path.join(BASE_DIR, ".deploy_email_manager_key")
    net = dict(lan=get_setting("listen_lan", "0") == "1", port=get_setting("listen_port", "8000"),
               ips=lan_ips(), env_host=os.environ.get("EM_HOST", ""), env_port=os.environ.get("EM_PORT", ""))
    return render("server.html", "السيرفر والنشر", cfg=cfg, pub=pub, ssh_ok=HAVE_SSH, net=net,
                  has_key=bool(cfg["deploy_key"]), has_pw=bool(cfg["deploy_password"]),
                  local_key_exists=os.path.exists(local_key), state=dict(_DEPLOY),
                  service=DEPLOY_SERVICE)


@app.route("/server/key/<act>", methods=["POST"])
def server_key(act):
    if not HAVE_SSH:
        flash("مكتبة paramiko غير مثبّتة", "error")
        return redirect(url_for("server_page"))
    if act == "generate":
        priv, pub = generate_ssh_keypair()
        set_setting("deploy_key", encrypt_secret(priv))
        set_setting("deploy_key_pass", encrypt_secret(""))
        set_setting("deploy_auth", "key")
        flash("تم توليد مفتاح جديد — انسخ المفتاح العام إلى السيرفر ثم اختبر الاتصال", "success")
    elif act == "import":
        p = os.path.join(BASE_DIR, ".deploy_email_manager_key")
        if not os.path.exists(p):
            flash("لا يوجد ملف .deploy_email_manager_key بجوار البرنامج", "error")
        else:
            with open(p, "r", encoding="utf-8") as fh:
                set_setting("deploy_key", encrypt_secret(fh.read().strip()))
            set_setting("deploy_auth", "key")
            flash("تم استيراد المفتاح الموجود", "success")
    elif act == "delete":
        set_setting("deploy_key", "")
        set_setting("deploy_key_pass", "")
        flash("تم حذف المفتاح المحفوظ", "info")
    return redirect(url_for("server_page"))


@app.route("/server/test", methods=["POST"])
def server_test():
    try:
        cfg = deploy_cfg()
        c = ssh_connect(cfg, timeout=15)
        try:
            _, out, _ = c.exec_command("echo ok; uname -srm; (lsb_release -ds 2>/dev/null || "
                                       "cat /etc/os-release 2>/dev/null | head -n1); "
                                       "id -un; command -v apt-get dnf 2>/dev/null | head -n1", timeout=20)
            info = out.read().decode("utf-8", "replace").strip().splitlines()
        finally:
            c.close()
        flash("الاتصال ناجح ✔ — " + " · ".join(x.strip() for x in info[1:] if x.strip())[:220], "success")
    except Exception as exc:  # noqa: BLE001
        flash("فشل الاتصال: %s" % exc, "error")
    return redirect(url_for("server_page"))


@app.route("/server/deploy", methods=["POST"])
def server_deploy():
    cfg = deploy_cfg()
    copy_data = request.form.get("copy_data", "first")   # first | always | never
    if not _deploy_start("deploy"):
        flash("توجد عملية نشر جارية بالفعل", "warning")
        return redirect(url_for("server_page"))
    threading.Thread(target=deploy_job, args=(cfg, copy_data), daemon=True).start()
    flash("بدأ النشر في الخلفية — تابع السجل أدناه", "info")
    return redirect(url_for("server_page"))


@app.route("/server/action/<act>", methods=["POST"])
def server_action(act):
    if act not in ("status", "restart", "stop", "start", "logs", "nginx"):
        abort(404)
    if not _deploy_start(act):
        flash("توجد عملية جارية بالفعل", "warning")
        return redirect(url_for("server_page"))
    threading.Thread(target=server_action_job, args=(deploy_cfg(), act), daemon=True).start()
    return redirect(url_for("server_page"))


@app.route("/server/network", methods=["POST"])
def server_network():
    set_setting("listen_lan", "1" if request.form.get("listen_lan") else "0")
    try:
        set_setting("listen_port", min(65535, max(1, int(request.form.get("listen_port") or 8000))))
    except ValueError:
        set_setting("listen_port", 8000)
    flash("تم حفظ إعدادات الشبكة — أغلق البرنامج وشغّله من جديد ليسري التغيير", "success")
    return redirect(url_for("server_page"))


@app.route("/server/log")
def server_log():
    with _deploy_lock:
        data = dict(_DEPLOY)
    return Response(json.dumps(data, ensure_ascii=False), mimetype="application/json")


# ------------------------------------------------------------------ نقطة البداية
def _free_port(host, preferred):
    """يعيد أول منفذ لا يستمع عليه أحد (لتفادي نسخة قديمة عالقة على 8000)."""
    import socket
    for port in [preferred] + [preferred + i for i in range(1, 21)]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.35)
            if s.connect_ex((host, port)) != 0:   # لا شيء يستمع هنا
                return port
    return preferred


def listen_config():
    """عنوان/منفذ الاستماع: متغيرات البيئة أولاً، ثم إعدادات صفحة «السيرفر»، ثم الافتراضي."""
    host = os.environ.get("EM_HOST") or ("0.0.0.0" if get_setting("listen_lan", "0") == "1" else "127.0.0.1")
    try:
        port = int(os.environ.get("EM_PORT") or get_setting("listen_port", "8000") or 8000)
    except ValueError:
        port = 8000
    return host, port


def lan_ips():
    """عناوين IP المحلية لهذا الجهاز (لعرض رابط الوصول من أجهزة الشبكة)."""
    import socket
    ips = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))          # لا يُرسل شيئاً — فقط لاختيار الواجهة
            ips.append(s.getsockname()[0])
    except OSError:
        pass
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass
    return ips


# ================================================================ سيرفر البريد الداخلي المدمج
# SMTP + IMAP فعليان (stdlib فقط) يخدمان صناديق mail_messages داخل البرنامج.
# يسمح لعميل IMAP بتاع البرنامج — وحتى Outlook خارجي — بالاتصال والقراءة/الإرسال.
import socket as _socket
from email.message import EmailMessage as _EmailMessage

# مجلدات السيرفر الداخلي القياسية (بأسلوب أوتلوك) + أعلام الاستخدام الخاص
# (db folder, اسم IMAP الظاهر, علم \Special-use)
_INT_FOLDER_DEFS = [
    ("inbox",   "INBOX",          "\\Inbox"),
    ("drafts",  "Drafts",         "\\Drafts"),
    ("sent",    "Sent",           "\\Sent"),
    ("trash",   "Deleted Items",  "\\Trash"),
    ("junk",    "Junk Email",     "\\Junk"),
    ("archive", "Archive",        "\\Archive"),
]
_INT_FOLDERS = {db: nm for db, nm, _fl in _INT_FOLDER_DEFS}          # db -> IMAP name
_INT_FOLDERS_REV = {nm.lower(): db for db, nm, _fl in _INT_FOLDER_DEFS}  # IMAP name(lower) -> db
_INT_FOLDERS_REV.update({db: db for db, _n, _f in _INT_FOLDER_DEFS})     # db name أيضاً


def _int_credentials():
    """قاموس {email: plaintext_password} من كل مصادر الصناديق."""
    creds = {}
    conn = get_connection()
    try:
        for tbl in ("accounts", "employees", "mail_boxes"):
            try:
                for r in conn.execute(f"SELECT email, password FROM {tbl}").fetchall():
                    pw = decrypt_secret(r["password"]) if r["password"] else ""
                    if r["email"]:
                        creds[r["email"].lower()] = pw
            except Exception:  # noqa: BLE001
                pass
    finally:
        conn.close()
    return creds


def _int_auth(email, password):
    creds = _int_credentials()
    email = (email or "").lower()
    return email in creds and (creds[email] == password or creds[email] == "")


def _int_build_raw(row):
    """يبني رسالة MIME كاملة (bytes) من صف mail_messages."""
    msg = _EmailMessage()
    frm = row["from_email"]
    if row["from_name"]:
        frm = formataddr((str(make_header([(row["from_name"], "utf-8")])), row["from_email"]))
    msg["From"] = frm
    msg["To"] = row["to_email"]
    msg["Subject"] = row["subject"] or ""
    try:
        dt = datetime.fromisoformat(str(row["created_at"]))
    except (TypeError, ValueError):
        dt = datetime.now()
    msg["Date"] = formatdate(time.mktime(dt.timetuple()), localtime=True)
    if row["msg_id"]:
        msg["Message-ID"] = row["msg_id"]
    if row["in_reply_to"]:
        msg["In-Reply-To"] = row["in_reply_to"]
        msg["References"] = row["in_reply_to"]
    body = row["body"] or ""
    # نص بديل بسيط + HTML
    import re as _re
    text = _re.sub(r"<[^>]+>", "", body.replace("<br>", "\n").replace("<br/>", "\n"))
    msg.set_content(text or " ")
    msg.add_alternative(body or " ", subtype="html")
    return msg.as_bytes()


def _int_internaldate(row):
    try:
        dt = datetime.fromisoformat(str(row["created_at"]))
    except (TypeError, ValueError):
        dt = datetime.now()
    return dt.strftime("%d-%b-%Y %H:%M:%S +0000")


def _int_msgs(box_email, folder_db):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM mail_messages WHERE box_email=? AND folder=? ORDER BY id ASC",
            (box_email.lower(), folder_db)).fetchall()
    finally:
        conn.close()
    return rows


def _int_set_flag(mid, field, val):
    conn = get_connection()
    try:
        conn.execute(f"UPDATE mail_messages SET {field}=? WHERE id=?", (1 if val else 0, mid))
        conn.commit()
    finally:
        conn.close()


def _int_delete_msg(mid):
    conn = get_connection()
    try:
        conn.execute("DELETE FROM mail_messages WHERE id=?", (mid,))
        conn.commit()
    finally:
        conn.close()


def _int_move_msg(mid, dest_folder):
    conn = get_connection()
    try:
        conn.execute("UPDATE mail_messages SET folder=? WHERE id=?", (dest_folder, mid))
        conn.commit()
    finally:
        conn.close()


def _int_copy_msg(mid, dest_folder):
    conn = get_connection()
    try:
        r = conn.execute("SELECT * FROM mail_messages WHERE id=?", (mid,)).fetchone()
        if r:
            conn.execute(
                """INSERT INTO mail_messages (box_email, folder, from_email, from_name,
                    to_email, subject, body, msg_id, in_reply_to, is_read, is_replied, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (r["box_email"], dest_folder, r["from_email"], r["from_name"], r["to_email"],
                 r["subject"], r["body"], r["msg_id"], r["in_reply_to"], r["is_read"],
                 r["is_replied"], r["created_at"]))
            conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------- SMTP
def _int_smtp_client(sock, addr):
    def send(s):
        sock.sendall((s + "\r\n").encode("utf-8", "replace"))
    f = sock.makefile("rb")
    try:
        send("220 EmailManager internal SMTP ready")
        mail_from = None
        rcpts = []
        authed_user = None
        while True:
            line = f.readline()
            if not line:
                break
            cmd = line.decode("utf-8", "replace").rstrip("\r\n")
            up = cmd.upper()
            if up.startswith("EHLO") or up.startswith("HELO"):
                send("250-EmailManager")
                send("250-AUTH LOGIN PLAIN")
                send("250 OK")
            elif up.startswith("AUTH LOGIN"):
                send("334 " + base64.b64encode(b"Username:").decode())
                u = base64.b64decode(f.readline().strip()).decode("utf-8", "replace")
                send("334 " + base64.b64encode(b"Password:").decode())
                p = base64.b64decode(f.readline().strip()).decode("utf-8", "replace")
                if _int_auth(u, p):
                    authed_user = u.lower()
                    send("235 2.7.0 Authentication successful")
                else:
                    send("535 5.7.8 Authentication failed")
            elif up.startswith("AUTH PLAIN"):
                try:
                    blob = cmd.split(" ", 2)[2]
                    parts = base64.b64decode(blob).split(b"\x00")
                    u, p = parts[1].decode(), parts[2].decode()
                    if _int_auth(u, p):
                        authed_user = u.lower()
                        send("235 2.7.0 Authentication successful")
                    else:
                        send("535 5.7.8 Authentication failed")
                except Exception:  # noqa: BLE001
                    send("535 5.7.8 Authentication failed")
            elif up.startswith("MAIL FROM"):
                mail_from = cmd.split(":", 1)[1].strip().strip("<>").split()[0] if ":" in cmd else ""
                rcpts = []
                send("250 OK")
            elif up.startswith("RCPT TO"):
                r = cmd.split(":", 1)[1].strip().strip("<>").split()[0] if ":" in cmd else ""
                if r:
                    rcpts.append(r)
                send("250 OK")
            elif up == "DATA":
                send("354 End data with <CR><LF>.<CR><LF>")
                buf = []
                while True:
                    dl = f.readline()
                    if not dl or dl == b".\r\n" or dl == b".\n":
                        break
                    if dl.startswith(b".."):
                        dl = dl[1:]
                    buf.append(dl)
                raw = b"".join(buf)
                _int_smtp_store(mail_from or authed_user or "", rcpts, raw)
                send("250 OK message queued")
            elif up.startswith("RSET"):
                mail_from, rcpts = None, []
                send("250 OK")
            elif up.startswith("NOOP"):
                send("250 OK")
            elif up.startswith("QUIT"):
                send("221 Bye")
                break
            else:
                send("250 OK")
    except (ConnectionError, OSError):
        pass          # العميل قطع الاتصال — طبيعي
    except Exception as exc:  # noqa: BLE001
        log.debug("SMTP داخلي: %s", exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _int_smtp_store(mail_from, rcpts, raw):
    """يخزّن رسالة واردة عبر SMTP في صناديق المستقبلين + نسخة مُرسَل."""
    try:
        msg = message_from_bytes(raw)
        subject = _decode_hdr(msg.get("Subject")) or ""
        fromname, fromaddr = parseaddr(_decode_hdr(msg.get("From")))
        fromaddr = (fromaddr or mail_from or "").lower()
        html, text = _part_html_text(msg)
        body = html or _text_to_html(text)
        in_reply_to = (msg.get("In-Reply-To") or "").strip() or None
        msg_id = (msg.get("Message-ID") or make_msgid(domain="internal.local")).strip()
        # استخدم تاريخ الرسالة (ترويسة Date) لو موجود — يسمح بإرسال بتاريخ مخصّص
        now = datetime.now().isoformat(timespec="seconds")
        try:
            hd = msg.get("Date")
            if hd:
                now = parsedate_to_datetime(hd).astimezone().replace(tzinfo=None) \
                    .isoformat(timespec="seconds")
        except Exception:  # noqa: BLE001
            pass
        conn = get_connection()
        try:
            for rcpt in rcpts:
                conn.execute(
                    """INSERT INTO mail_messages (box_email, folder, from_email, from_name,
                        to_email, subject, body, msg_id, in_reply_to, created_at)
                       VALUES (?, 'inbox', ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (rcpt.lower(), fromaddr, fromname or "", rcpt.lower(), subject, body,
                     msg_id, in_reply_to, now))
            if fromaddr:
                conn.execute(
                    """INSERT INTO mail_messages (box_email, folder, from_email, from_name,
                        to_email, subject, body, msg_id, in_reply_to, created_at)
                       VALUES (?, 'sent', ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (fromaddr, fromaddr, fromname or "", ", ".join(rcpts), subject, body,
                     msg_id, in_reply_to, now))
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001
        log.warning("SMTP داخلي: فشل تخزين رسالة: %s", exc)


# ---------------------------------------------------------------- IMAP
def _int_imap_client(sock, addr):
    def send(s):
        sock.sendall((s + "\r\n").encode("utf-8", "replace"))

    def send_bytes(b):
        sock.sendall(b)

    f = sock.makefile("rb")
    user = None
    selected = None   # folder_db
    try:
        send("* OK [CAPABILITY IMAP4rev1 MOVE] EmailManager internal IMAP ready")
        while True:
            line = f.readline()
            if not line:
                break
            try:
                text = line.decode("utf-8", "replace").rstrip("\r\n")
            except Exception:
                continue
            if not text:
                continue
            parts = text.split(" ", 2)
            tag = parts[0]
            cmd = parts[1].upper() if len(parts) > 1 else ""
            rest = parts[2] if len(parts) > 2 else ""

            if cmd == "CAPABILITY":
                send("* CAPABILITY IMAP4rev1 MOVE")
                send(f"{tag} OK CAPABILITY completed")
            elif cmd == "LOGIN":
                a = _imap_split_args(rest)
                if len(a) >= 2 and _int_auth(a[0], a[1]):
                    user = a[0].lower()
                    send(f"{tag} OK LOGIN completed")
                else:
                    send(f"{tag} NO LOGIN failed")
            elif cmd == "LOGOUT":
                send("* BYE logging out")
                send(f"{tag} OK LOGOUT completed")
                break
            elif cmd == "NOOP":
                send(f"{tag} OK NOOP completed")
            elif user is None:
                send(f"{tag} NO not authenticated")
            elif cmd == "LIST":
                for _db, _nm, _fl in _INT_FOLDER_DEFS:
                    flags = "\\HasNoChildren" if _fl == "\\Inbox" else ("\\HasNoChildren " + _fl)
                    send('* LIST (%s) "/" "%s"' % (flags, _nm))
                send(f"{tag} OK LIST completed")
            elif cmd == "STATUS":
                a = _imap_split_args(rest)
                fol = _INT_FOLDERS_REV.get((a[0] if a else "INBOX").lower(), "inbox")
                rows = _int_msgs(user, fol)
                unseen = sum(1 for r in rows if not r["is_read"])
                nm = _INT_FOLDERS.get(fol, "INBOX")
                send('* STATUS "%s" (MESSAGES %d UNSEEN %d UIDNEXT %d UIDVALIDITY 1)'
                     % (nm, len(rows), unseen, (rows[-1]["id"] + 1) if rows else 1))
                send(f"{tag} OK STATUS completed")
            elif cmd in ("SELECT", "EXAMINE"):
                a = _imap_split_args(rest)
                fol = _INT_FOLDERS_REV.get((a[0] if a else "INBOX").lower(), "inbox")
                selected = fol
                rows = _int_msgs(user, fol)
                send("* FLAGS (\\Seen \\Answered \\Flagged \\Draft)")
                send("* %d EXISTS" % len(rows))
                send("* 0 RECENT")
                send("* OK [UIDVALIDITY 1] UIDs valid")
                send("* OK [UIDNEXT %d] Predicted next UID" % ((rows[-1]["id"] + 1) if rows else 1))
                rw = "READ-ONLY" if cmd == "EXAMINE" else "READ-WRITE"
                send(f"{tag} OK [{rw}] {cmd} completed")
            elif cmd == "UID":
                _imap_uid(send, send_bytes, tag, rest, user, selected)
            elif cmd == "CLOSE":
                selected = None
                send(f"{tag} OK CLOSE completed")
            elif cmd == "CHECK":
                send(f"{tag} OK CHECK completed")
            else:
                send(f"{tag} OK {cmd} completed")
    except (ConnectionError, OSError):
        pass          # العميل قطع الاتصال — طبيعي
    except Exception as exc:  # noqa: BLE001
        log.debug("IMAP داخلي: %r", exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _imap_split_args(s):
    """يقسّم وسائط IMAP مع دعم علامات الاقتباس."""
    out, cur, q = [], [], False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == '"':
            q = not q
        elif ch == " " and not q:
            if cur:
                out.append("".join(cur)); cur = []
        else:
            cur.append(ch)
        i += 1
    if cur:
        out.append("".join(cur))
    return out


def _imap_flags(row):
    fl = []
    if row["is_read"]:
        fl.append("\\Seen")
    if row["is_replied"]:
        fl.append("\\Answered")
    return "(%s)" % " ".join(fl)


def _imap_uid(send, send_bytes, tag, rest, user, selected):
    sub = rest.split(" ", 1)
    ucmd = sub[0].upper() if sub else ""
    args = sub[1] if len(sub) > 1 else ""
    fol = selected or "inbox"
    rows = _int_msgs(user, fol)
    by_uid = {r["id"]: r for r in rows}
    seq_of = {r["id"]: i + 1 for i, r in enumerate(rows)}

    if ucmd == "SEARCH":
        crit = args.upper()
        unseen = "UNSEEN" in crit
        # مصطلح بحث بين علامتي اقتباس (لو موجود)
        term = ""
        mq = re.search(r'"([^"]+)"', args)
        if mq:
            term = mq.group(1).lower()
        hits = []
        for r in rows:
            if unseen and r["is_read"]:
                continue
            if term:
                blob = ((r["from_email"] or "") + " " + (r["subject"] or "") + " " +
                        (r["body"] or "")).lower()
                if term not in blob:
                    continue
            hits.append(str(r["id"]))
        send("* SEARCH " + " ".join(hits) if hits else "* SEARCH")
        send(f"{tag} OK UID SEARCH completed")
        return

    if ucmd == "FETCH":
        m = re.match(r"([0-9,:*]+)\s+(.*)", args, re.S)
        if not m:
            send(f"{tag} OK UID FETCH completed")
            return
        uidset, items = m.group(1), m.group(2).upper()
        want = _imap_expand_uidset(uidset, rows)
        full = "BODY[]" in items or "BODY.PEEK[]" in items or "RFC822" in items
        hdr_only = "HEADER.FIELDS" in items
        for uid in want:
            r = by_uid.get(uid)
            if not r:
                continue
            seq = seq_of[uid]
            head = "* %d FETCH (UID %d FLAGS %s INTERNALDATE \"%s\"" % (
                seq, uid, _imap_flags(r), _int_internaldate(r))
            raw = _int_build_raw(r)
            head += " RFC822.SIZE %d" % len(raw)
            if full:
                head += " BODY[] {%d}\r\n" % len(raw)
                send_bytes(head.encode("utf-8", "replace"))
                send_bytes(raw)
                send_bytes(b")\r\n")
            elif hdr_only:
                block = _imap_header_fields(raw)
                head += " BODY[HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID)] {%d}\r\n" % len(block)
                send_bytes(head.encode("utf-8", "replace"))
                send_bytes(block)
                send_bytes(b")\r\n")
            else:
                send_bytes((head + ")\r\n").encode("utf-8", "replace"))
        send(f"{tag} OK UID FETCH completed")
        return

    if ucmd == "STORE":
        m = re.match(r"([0-9,:*]+)\s+([+-]?FLAGS(?:\.SILENT)?)\s+\(?([^)]*)\)?", args, re.I)
        if m:
            want = _imap_expand_uidset(m.group(1), rows)
            op = m.group(2).lower()
            flags = m.group(3).lower()
            for uid in want:
                r = by_uid.get(uid)
                if not r:
                    continue
                add = not op.startswith("-")
                if "\\deleted" in flags and add:
                    _int_delete_msg(uid)          # حذف فعلي (يكمله EXPUNGE بلا عمل)
                    continue
                if "\\seen" in flags:
                    _int_set_flag(uid, "is_read", add)
                if "\\answered" in flags:
                    _int_set_flag(uid, "is_replied", add)
                if ".SILENT" not in m.group(2).upper():
                    fresh = _int_msgs(user, fol)
                    fr = {x["id"]: x for x in fresh}.get(uid)
                    if fr:
                        send("* %d FETCH (UID %d FLAGS %s)" % (seq_of[uid], uid, _imap_flags(fr)))
        send(f"{tag} OK UID STORE completed")
        return

    if ucmd == "MOVE":
        m = re.match(r"([0-9,:*]+)\s+(.*)", args, re.S)
        if m:
            want = _imap_expand_uidset(m.group(1), rows)
            dest = _INT_FOLDERS_REV.get(_imap_split_args(m.group(2))[0].lower(), None) \
                if m.group(2).strip() else None
            if dest:
                for uid in want:
                    _int_move_msg(uid, dest)
        send(f"{tag} OK UID MOVE completed")
        return

    if ucmd == "COPY":
        m = re.match(r"([0-9,:*]+)\s+(.*)", args, re.S)
        if m:
            want = _imap_expand_uidset(m.group(1), rows)
            dest = _INT_FOLDERS_REV.get(_imap_split_args(m.group(2))[0].lower(), None) \
                if m.group(2).strip() else None
            if dest:
                for uid in want:
                    _int_copy_msg(uid, dest)
        send(f"{tag} OK UID COPY completed")
        return
    send(f"{tag} OK UID completed")


def _imap_expand_uidset(uidset, rows):
    all_ids = [r["id"] for r in rows]
    out = []
    for part in uidset.split(","):
        part = part.strip()
        if ":" in part:
            a, b = part.split(":", 1)
            lo = 1 if a == "*" else int(a)
            hi = (all_ids[-1] if all_ids else 1) if b == "*" else int(b)
            lo, hi = min(lo, hi), max(lo, hi)
            out += [u for u in all_ids if lo <= u <= hi]
        elif part == "*":
            if all_ids:
                out.append(all_ids[-1])
        elif part.isdigit():
            out.append(int(part))
    seen = set()
    return [u for u in out if not (u in seen or seen.add(u))]


def _imap_header_fields(raw):
    """يعيد كتلة الترويسات (FROM TO CC SUBJECT DATE MESSAGE-ID) بايتات."""
    msg = message_from_bytes(raw)
    wanted = ["From", "To", "Cc", "Subject", "Date", "Message-ID"]
    lines = []
    for h in wanted:
        v = msg.get(h)
        if v is not None:
            lines.append("%s: %s" % (h, v))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "replace")


def _int_server_loop(port, handler, name):
    try:
        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(50)
        log.info("سيرفر البريد الداخلي %s يعمل على المنفذ %d", name, port)
    except Exception as exc:  # noqa: BLE001
        log.warning("تعذّر تشغيل سيرفر %s على %d: %s", name, port, exc)
        return
    while True:
        try:
            client, addr = srv.accept()
            client.settimeout(120)
            threading.Thread(target=handler, args=(client, addr), daemon=True).start()
        except Exception as exc:  # noqa: BLE001
            log.debug("%s accept: %s", name, exc)


def start_internal_mail_servers():
    if not INT_MAIL_ENABLED:
        return
    threading.Thread(target=_int_server_loop,
                     args=(INT_SMTP_PORT, _int_smtp_client, "SMTP"), daemon=True).start()
    threading.Thread(target=_int_server_loop,
                     args=(INT_IMAP_PORT, _int_imap_client, "IMAP"), daemon=True).start()


def main():
    init_db()
    # إعادة التحميل التلقائي (بدون إيقاف يدوي): EM_RELOAD=1 يفعّلها.
    # نشغّل السيرفر الداخلي + الجدولة في عملية الـworker فقط (مش عملية المراقبة)
    # عشان ما يحصلش تعارض على منافذ SMTP/IMAP.
    reload_on = os.environ.get("EM_RELOAD") == "1"
    is_worker = (not reload_on) or os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    host, want = listen_config()
    port = _free_port("127.0.0.1" if host == "0.0.0.0" else host, want)
    if port != want:
        log.warning("المنفذ %s مشغول (نسخة قديمة تعمل؟) — سأستخدم %s", want, port)
    if is_worker:
        start_internal_mail_servers()
        threading.Thread(target=scheduler_loop, daemon=True).start()
    local_url = f"http://127.0.0.1:{port}" if host == "0.0.0.0" else f"http://{host}:{port}"
    if is_worker and os.environ.get("EM_NO_BROWSER") != "1":
        threading.Timer(1.0, lambda: webbrowser.open(local_url)).start()
    lan_lines = ""
    if host == "0.0.0.0":
        lan_lines = "".join(f"  من أجهزة الشبكة:   http://{ip}:{port}\n" for ip in lan_ips())
    banner = (f"\n{'='*54}\n  Email Manager يعمل الآن\n"
              f"  افتح المتصفح على:  {local_url}\n{lan_lines}"
              f"  لإيقاف البرنامج: أغلق هذه النافذة\n{'='*54}\n")
    try:
        print(banner)
    except Exception:
        pass
    log.info("التشغيل على http://%s:%s", host, port)
    app.run(host=host, port=port, debug=False, threaded=True,
            use_reloader=reload_on, reloader_type="stat")


if __name__ == "__main__":
    main()
