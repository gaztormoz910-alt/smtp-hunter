# smtp_relay_scanner/config.py
# Конфигурация проекта — все константы в одном месте

import os
from pathlib import Path

# === Базовые пути ===
BASE_DIR = Path(__file__).resolve().parent
MODULES_DIR = BASE_DIR / "modules"
DATA_DIR = BASE_DIR / "data"

# === SMTP порты по умолчанию ===
DEFAULT_PORTS = [25, 465, 587, 2525, 2526, 25025]
FAST_PORTS = [25, 587]
FULL_PORTS = [25, 465, 587, 2525, 2526, 25025, 25252, 466, 2527]

# === Таймауты (секунды) ===
TIMEOUT_CONNECT = 3
TIMEOUT_READ = 5
TIMEOUT_SEND = 5
TIMEOUT_DNS = 5
TIMEOUT_HTTP = 10

# === Треды / конкурентность ===
DEFAULT_THREADS = 100
MAX_THREADS = 2000
DEFAULT_RATE_LIMIT = 0  # ms между запросами (0 = без лимита)

# === Пути к файлам ===
PORTS_FILE = DATA_DIR / "smtp_ports.txt"
DOMAINS_FILE = DATA_DIR / "popular_domains.txt"
WORDLIST_FILE = DATA_DIR / "user_wordlist.txt"

# === Дефолтные email для тестов ===
DEFAULT_SENDER = "test@example.com"
DEFAULT_RECEIVER = "test@mail-test.com"
DEFAULT_HELO_DOMAIN = "test.local"

# === ASN lookup ===
ASN_SOURCES = ["ipwhois", "hackertarget", "bgp_he"]
HACKERTARGET_API = "https://api.hackertarget.com/aslookup/"
IPINFO_API = "https://ipinfo.io/"

# === Shodan / Censys (ключа нет — будет пропущено) ===
SHODAN_API_KEY = ""
CENSYS_API_ID = ""
CENSYS_API_SECRET = ""

# === Google Dorks ===
GOOGLE_DORKS = [
    'intitle:"smtp server list" filetype:txt',
    'inurl:"smtp" "password" filetype:txt',
    '"smtp relay" "username" "password"'
]

# === Экспорт ===
EXPORT_DIR = BASE_DIR / "results"
EXPORT_FORMATS = ["json", "csv", "html"]

# === Ретраи и бэкофф ===
MAX_RETRIES = 3
BACKOFF_BASE = 5  # секунд
GREYLIST_CODES = [451, 450]
THROTTLE_CODES = [502, 552]

# === SMTP команды ===
SMTP_EHLO = "EHLO {domain}\r\n"
SMTP_HELO = "HELO {domain}\r\n"
SMTP_MAIL_FROM = "MAIL FROM:<{email}>\r\n"
SMTP_RCPT_TO = "RCPT TO:<{email}>\r\n"
SMTP_DATA = "DATA\r\n"
SMTP_QUIT = "QUIT\r\n"
SMTP_VRFY = "VRFY {user}\r\n"
SMTP_EXPN = "EXPN {user}\r\n"
SMTP_RSET = "RSET\r\n"
SMTP_NOOP = "NOOP\r\n"

# === Сообщение для relay теста ===
RELAY_TEST_HEADERS = (
    "From: {sender}\r\n"
    "To: {receiver}\r\n"
    "Subject: SMTP Open Relay Test - {test_id}\r\n"
    "Date: {date}\r\n"
    "X-Mailer: SMTP-Relay-Scanner v1.0\r\n"
    "\r\n"
)
RELAY_TEST_BODY = (
    "This is an automated test message from SMTP Relay Scanner.\r\n"
    "Test ID: {test_id}\r\n"
    "Timestamp: {date}\r\n"
    "Source IP: {source_ip}\r\n"
    "\r\n"
    "If you received this, the SMTP server at {target}:{port} is an OPEN RELAY.\r\n"
)

# === Коды ответов ===
SUCCESS_CODES = {250, 251}
RELAY_CODES = {250}
AUTH_CODES = {334, 235, 503}
TEMP_FAIL_CODES = {450, 451, 452}
PERM_FAIL_CODES = {550, 551, 552, 553, 554, 501, 503, 504}