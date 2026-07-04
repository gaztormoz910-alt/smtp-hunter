# smtp_relay_scanner/modules/scanner/live_checker.py

import socket
import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)
import ssl
from typing import Optional, Dict, Tuple, List
from datetime import datetime

from smtp_relay_scanner.config import (
    TIMEOUT_CONNECT, TIMEOUT_READ, SMTP_EHLO, SMTP_QUIT,
    DEFAULT_HELO_DOMAIN
)

# === MTA fingerprint signatures ===
MTA_SIGNATURES = {
    "Postfix": ["Postfix", "ESMTP Postfix"],
    "Exim": ["Exim", "ESMTP Exim"],
    "Sendmail": ["Sendmail", "ESMTP Sendmail"],
    "Microsoft Exchange": ["Microsoft ESMTP MAIL Service", "Exchange"],
    "Zimbra": ["Zimbra", "Zimbra Collaboration Suite"],
    "qmail": ["qmail", "ESMTP qmail"],
    "Cisco ESA": ["Cisco Email Security Appliance", "Cisco ESA"],
    "HMailServer": ["HMailServer", "ESMTP HMailServer"],
    "OpenSMTPD": ["OpenSMTPD", "ESMTP OpenSMTPD"],
    "Courier-MTA": ["Courier-MTA"],
    "CommuniGate Pro": ["CommuniGate Pro"],
    "MDaemon": ["MDaemon", "WorldClient"],
    "Kerio Connect": ["Kerio Connect"],
    "Scalix": ["Scalix"],
    "IceWarp": ["IceWarp", "Merak"],
    "SmarterMail": ["SmarterMail"],
    "MailEnable": ["MailEnable"],
    "Axigen": ["Axigen"],
    "Apache James": ["Apache James"],
    "MTA (generic)": ["SMTP", "ESMTP", "smtp"]
}

def detect_mta(banner: str) -> str:
    """
    Определяет MTA по баннеру.
    
    Returns:
        Название MTA или "Unknown"
    """
    for mta, signatures in MTA_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in banner.lower():
                return mta
    return "Unknown"


def connect_smtp(ip: str, port: int, use_ssl: bool = False,
                 timeout: int = TIMEOUT_CONNECT) -> Optional[socket.socket]:
    """
    Устанавливает TCP/TLS соединение с SMTP сервером.
    
    Returns:
        socket object или None
    """
    try:
        log.debug(f"Attempting connection to {ip}:{port} (SSL={use_ssl})")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        log.debug(f"Connected to {ip}:{port}")
        
        if use_ssl or port == 465:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=ip)
            log.debug(f"SSL/TLS handshake completed on {ip}:{port}")
        
        return sock
    except socket.timeout:
        log.error(f"Timeout connecting to {ip}:{port}")
        return None
    except ConnectionRefusedError:
        log.error(f"Connection refused by {ip}:{port}")
        return None
    except socket.gaierror as e:
        log.error(f"DNS resolution failed for {ip}:{port} — {e}")
        return None
    except ssl.SSLError as e:
        log.error(f"SSL error on {ip}:{port} — {e}")
        return None
    except Exception as e:
        log.error(f"Connection failed to {ip}:{port} — {type(e).__name__}: {e}")
        return None


def recv_response(sock: socket.socket, timeout: int = TIMEOUT_READ) -> str:
    """Читает ответ от SMTP сервера."""
    try:
        sock.settimeout(timeout)
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n" in data and data.count(b"\r\n") >= 2:
                    # Проверяем, есть ли ещё данные (многострочный ответ)
                    lines = data.decode('utf-8', errors='ignore').split('\r\n')
                    if any(not line.startswith(('250-', '220-')) for line in lines if line):
                        break
                    if len(lines) >= 2 and lines[-2] and not lines[-2].startswith(('250-', '220-')):
                        break
                if data.count(b"\r\n") >= 5:  # безопасный лимит
                    break
            except socket.timeout:
                break
        return data.decode('utf-8', errors='ignore').strip()
    except:
        return ""


def send_command(sock: socket.socket, command: str) -> str:
    """Отправляет команду и читает ответ."""
    try:
        sock.sendall(command.encode('utf-8'))
        return recv_response(sock)
    except:
        return ""


def check_live_smtp(ip: str, port: int, use_ssl: bool = False,
                    domain: str = DEFAULT_HELO_DOMAIN) -> Optional[Dict[str, any]]:
    """
    Проверяет, жив ли SMTP сервер на IP:port, и собирает информацию.
    
    Returns:
        Dict с баннером, MTA, EHLO ответом, STARTTLS поддержкой
        или None если сервер не отвечает
    """
    sock = connect_smtp(ip, port, use_ssl)
    if not sock:
        return None
    
    try:
        # Читаем баннер
        banner = recv_response(sock)
        if not banner:
            sock.close()
            return None
        
        if not banner.startswith(("220", "220-")):
            sock.close()
            return { "ip": ip, "port": port, "banner": banner, "mta": "Unknown" }
        
        # EHLO
        ehlo_resp = send_command(sock, SMTP_EHLO.format(domain=domain))
        
        # Если EHLO не сработал, пробуем HELO
        if not ehlo_resp or not ehlo_resp.startswith("250"):
            ehlo_resp = send_command(sock, SMTP_HELO.format(domain=domain))
        
        # Определяем MTA
        mta = detect_mta(banner)
        
        # Проверка STARTTLS
        starttls = "STARTTLS" in ehlo_resp.upper() if ehlo_resp else False
        
        # Проверка AUTH
        auth_support = any(line.strip().upper().startswith("250-AUTH") 
                          for line in ehlo_resp.split('\r\n')) if ehlo_resp else False
        
        # Парсим EHLO строки
        ehlo_lines = ehlo_resp.split('\r\n') if ehlo_resp else []
        
        result = {
            "ip": ip,
            "port": port,
            "banner": banner[:200],
            "mta": mta,
            "ehlo": ehlo_resp[:500] if ehlo_resp else "",
            "starttls": starttls,
            "auth_support": auth_support,
            "timestamp": datetime.utcnow().isoformat(),
            "domain": domain
        }
        
        # QUIT
        send_command(sock, SMTP_QUIT)
        sock.close()
        
        return result
    
    except Exception as e:
        try:
            sock.close()
        except:
            pass
        return None


def bulk_check(hosts: List[Tuple[str, int]], max_workers: int = 100,
               use_ssl: bool = False) -> List[Dict[str, any]]:
    """
    Массовая проверка списка хостов.
    
    Args:
        hosts: Список (ip, port)
        max_workers: Количество потоков
    
    Returns:
        Список результатов для живых серверов
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {
            executor.submit(check_live_smtp, ip, port, use_ssl): (ip, port)
            for ip, port in hosts
        }
        
        for future in as_completed(future_to_host):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except:
                pass
    
    print(f"[+] Live checker: {len(results)}/{len(hosts)} hosts are alive")
    return results