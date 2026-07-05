# smtp_relay_scanner/modules/checker/relay_tester.py

import socket
import ssl
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging
log = logging.getLogger(__name__)
from smtp_relay_scanner.config import (
    TIMEOUT_CONNECT, TIMEOUT_READ, DEFAULT_HELO_DOMAIN,
    SMTP_EHLO, SMTP_MAIL_FROM, SMTP_RCPT_TO, SMTP_DATA,
    SMTP_QUIT, SMTP_RSET, RELAY_TEST_HEADERS, RELAY_TEST_BODY,
    SUCCESS_CODES, RELAY_CODES
)
from smtp_relay_scanner.modules.scanner.live_checker import (
    connect_smtp, recv_response, send_command
)

# === 6 методов проверки Open Relay ===

RELAY_TESTS = [
    {
        "id": "ext_ext",
        "name": "External → External",
        "description": "MAIL FROM: external@gmail.com → RCPT TO: external@hotmail.com",
        "mail_from": "user@gmail.com",
        "rcpt_to": "test@hotmail.com"
    },
    {
        "id": "int_ext",
        "name": "Internal → External",
        "description": "MAIL FROM: user@target-domain.com → RCPT TO: external@hotmail.com",
        "mail_from": "user@{domain}",
        "rcpt_to": "test@hotmail.com"
    },
    {
        "id": "null_ext",
        "name": "Null sender → External",
        "description": "MAIL FROM: <> → RCPT TO: external@hotmail.com",
        "mail_from": "",
        "rcpt_to": "test@hotmail.com"
    },
    {
        "id": "source_percent",
        "name": "Source route (percent)",
        "description": "MAIL FROM: user%external.com@{domain}",
        "mail_from": "user%hotmail.com@{domain}",
        "rcpt_to": "test@hotmail.com"
    },
    {
        "id": "source_at",
        "name": "Source route (@)",
        "description": "MAIL FROM: user@external.com@{domain}",
        "mail_from": "user@hotmail.com@{domain}",
        "rcpt_to": "test@hotmail.com"
    },
    {
        "id": "auth_bypass",
        "name": "AUTH bypass probe",
        "description": "Попытка relay без AUTH (даже если AUTH advertised)",
        "mail_from": "user@gmail.com",
        "rcpt_to": "test@hotmail.com"
    }
]

def run_relay_test(
    ip: str,
    port: int,
    test: Dict[str, str],
    domain: str = DEFAULT_HELO_DOMAIN,
    use_ssl: bool = False,
    test_id: str = "test01",
    source_ip: str = "0.0.0.0",
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> Dict[str, any]:
    """
    Выполняет один тест на open relay.
    
    Returns:
        Dict с результатом теста
    """
    result = {
        "test_id": test["id"],
        "test_name": test["name"],
        "mail_from": test["mail_from"].format(domain=domain) if "{domain}" in test["mail_from"] else test["mail_from"],
        "rcpt_to": test["rcpt_to"],
        "success": False,
        "response_code": "",
        "response_message": "",
        "error": None
    }
    
    sock = connect_smtp(ip, port, use_ssl)
    if not sock:
        result["error"] = "Connection failed"
        return result
    
    try:
        # Баннер
        banner = recv_response(sock)
        if not banner or not banner.startswith(("220", "220-")):
            result["error"] = f"Invalid banner: {banner[:50]}"
            sock.close()
            return result
        
        # EHLO
        ehlo_resp = send_command(sock, SMTP_EHLO.format(domain=domain))
        
        # Если EHLO не сработал — пробуем STARTTLS (обязательно для порта 587)
        if not ehlo_resp or not ehlo_resp.startswith("250"):
            if "220" in ehlo_resp or "STARTTLS" in ehlo_resp.upper() or "250-STARTTLS" in (recv_response(sock) if not ehlo_resp else ""):
                # Пробуем STARTTLS напрямую
                stls_resp = send_command(sock, "STARTTLS\r\n")
                if stls_resp and stls_resp.startswith("220"):
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        sock = context.wrap_socket(sock, server_hostname=ip)
                    except:
                        pass
                    # Повторяем EHLO внутри TLS
                    ehlo_resp = send_command(sock, SMTP_EHLO.format(domain=domain))
            
            # Если всё ещё не сработало — HELO
            if not ehlo_resp or not ehlo_resp.startswith("250"):
                ehlo_resp = send_command(sock, f"HELO {domain}\r\n")
                if not ehlo_resp or not ehlo_resp.startswith("250"):
                    result["error"] = "EHLO/HELO failed"
                    sock.close()
                    return result
        
        # AUTH (если есть credentials)
        if username and password and ehlo_resp and "AUTH" in ehlo_resp.upper():
            auth_resp = _try_auth(sock, username, password)
            if not auth_resp:
                result["error"] = "AUTH failed"
                send_command(sock, SMTP_QUIT)
                sock.close()
                return result
            log.debug(f"AUTH successful for {username}")
        
        # STARTTLS (если EHLO его рекламирует, но мы ещё не в TLS)
        if not use_ssl and not isinstance(sock, ssl.SSLSocket) and ehlo_resp and "STARTTLS" in ehlo_resp.upper():
            stls_resp = send_command(sock, "STARTTLS\r\n")
            if stls_resp and stls_resp.startswith("220"):
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=ip)
                    # Повторяем EHLO внутри TLS
                    tls_ehlo = send_command(sock, SMTP_EHLO.format(domain=domain))
                    if tls_ehlo and tls_ehlo.startswith("250"):
                        ehlo_resp = tls_ehlo
                except:
                    pass

        # DEBUG: показываем что вернул EHLO
        log.debug(f"EHLO response ({ip}:{port}): {ehlo_resp[:200]}")        
        
        # RSET
        send_command(sock, SMTP_RSET)
        
        # MAIL FROM
        mail_from_addr = test["mail_from"].format(domain=domain) if "{domain}" in test["mail_from"] else test["mail_from"]
        if not mail_from_addr:
            mail_from_cmd = "MAIL FROM:<>\r\n"
        else:
            mail_from_cmd = SMTP_MAIL_FROM.format(email=mail_from_addr)
        
        mail_resp = send_command(sock, mail_from_cmd)
        result["response_code"] = mail_resp[:3] if len(mail_resp) >= 3 else ""
        
        if not mail_resp.startswith(tuple(str(c) for c in SUCCESS_CODES)):
            result["response_message"] = mail_resp.strip()[:100]
            send_command(sock, SMTP_QUIT)
            sock.close()
            return result
        
        # RCPT TO
        rcpt_to_addr = test["rcpt_to"]
        rcpt_cmd = SMTP_RCPT_TO.format(email=rcpt_to_addr)
        rcpt_resp = send_command(sock, rcpt_cmd)
        result["response_code"] = rcpt_resp[:3] if len(rcpt_resp) >= 3 else ""
        
        if rcpt_resp.startswith(tuple(str(c) for c in RELAY_CODES)):
            result["success"] = True
            
            # DATA — отправляем тестовое письмо
            data_resp = send_command(sock, SMTP_DATA)
            if data_resp.startswith("354"):
                # Отправляем тело письма
                headers = RELAY_TEST_HEADERS.format(
                    sender=mail_from_addr or "test@test.com",
                    receiver=rcpt_to_addr,
                    test_id=test["id"],
                    date=datetime.utcnow().isoformat()
                )
                body = RELAY_TEST_BODY.format(
                    test_id=test["id"],
                    date=datetime.utcnow().isoformat(),
                    source_ip=source_ip,
                    target=ip,
                    port=port
                )
                send_command(sock, headers + body + "\r\n.\r\n")
            
            result["response_message"] = f"OPEN RELAY: {rcpt_resp.strip()[:100]}"
        else:
            result["response_message"] = rcpt_resp.strip()[:100]
        
        # QUIT
        send_command(sock, SMTP_QUIT)
        sock.close()
        
    except Exception as e:
        result["error"] = str(e)
        try:
            sock.close()
        except:
            pass
    
    return result


def check_open_relay(
    ip: str,
    port: int,
    domain: str = DEFAULT_HELO_DOMAIN,
    use_ssl: bool = False,
    source_ip: str = "0.0.0.0",
    username: Optional[str] = None,
    password: Optional[str] = None
) -> Dict[str, any]:
    """
    Полная проверка хоста на Open Relay всеми 6 методами.
    
    Args:
        username/password: если переданы — пробует AUTH перед тестами
    """
    print(f"[*] Checking relay on {ip}:{port}...")
    
    results = {
        "ip": ip,
        "port": port,
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat(),
        "tests": [],
        "relay_level": "CLOSED",
        "any_relay": False,
        "summary": []
    }
    
    for test in RELAY_TESTS:
        test_result = run_relay_test(ip, port, test, domain, use_ssl, test["id"], source_ip, username, password)
        results["tests"].append(test_result)
        
        if test_result["success"]:
            results["any_relay"] = True
            results["summary"].append(f"[OPEN] {test_result['test_name']}")
        else:
            err = test_result.get("response_message") or test_result.get("error") or "closed"
            results["summary"].append(f"[CLOSED] {test_result['test_name']}: {err[:50]}")
    
    # Определяем уровень уязвимости
    passed_tests = [t["test_id"] for t in results["tests"] if t["success"]]
    
    if "ext_ext" in passed_tests:
        results["relay_level"] = "OPEN"
    elif "int_ext" in passed_tests:
        results["relay_level"] = "PARTIAL"
    elif "source_percent" in passed_tests or "source_at" in passed_tests:
        results["relay_level"] = "SOURCE_ROUTE"
    else:
        results["relay_level"] = "CLOSED"
    
    print(f"    Level: {results['relay_level']} ({len(passed_tests)}/{len(RELAY_TESTS)} tests passed)")
    return results


def _try_auth(sock: socket.socket, username: str, password: str) -> bool:
    """
    Пробует аутентификацию: AUTH PLAIN, если не сработало — AUTH LOGIN.
    Returns: True если успешно, иначе False.
    """
    import base64
    
    try:
        # Пробуем AUTH PLAIN
        auth_str = f"\0{username}\0{password}"
        auth_b64 = base64.b64encode(auth_str.encode()).decode()
        
        resp = send_command(sock, f"AUTH PLAIN {auth_b64}\r\n")
        if resp.startswith(("235", "334")):
            return True
        
        # Если PLAIN не сработал — пробуем AUTH LOGIN
        sock.sendall(b"RSET\r\n")
        recv_response(sock)
        
        resp = send_command(sock, "AUTH LOGIN\r\n")
        if resp.startswith("334"):
            user_b64 = base64.b64encode(username.encode()).decode()
            resp = send_command(sock, f"{user_b64}\r\n")
            if resp.startswith("334"):
                pass_b64 = base64.b64encode(password.encode()).decode()
                resp = send_command(sock, f"{pass_b64}\r\n")
                if resp.startswith("235"):
                    return True
        
        return False
    except:
        return False


def bulk_relay_check(
    hosts: List[Tuple[str, int]],
    domain: str = DEFAULT_HELO_DOMAIN,
    max_workers: int = 50,
    source_ip: str = "0.0.0.0",
    creds_map: Optional[Dict[Tuple[str, int], Tuple[str, str]]] = None
) -> List[Dict[str, any]]:
    """
    Массовая проверка списка хостов на open relay.
    creds_map: { (host, port): (username, password) } для AUTH
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    if creds_map is None:
        creds_map = {}
    
    all_results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {}
        for ip, port in hosts:
            user, pwd = creds_map.get((ip, port), (None, None))
            future_to_host[
                executor.submit(check_open_relay, ip, port, domain, False, source_ip, user, pwd)
            ] = (ip, port)
        
        for future in as_completed(future_to_host):
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                ip, port = future_to_host[future]
                print(f"[-] Error checking {ip}:{port}: {e}")
    
    # Сортируем: сначала OPEN, потом PARTIAL, потом SOURCE_ROUTE, потом CLOSED
    level_order = {"OPEN": 0, "PARTIAL": 1, "SOURCE_ROUTE": 2, "CLOSED": 3}
    all_results.sort(key=lambda r: level_order.get(r.get("relay_level", "CLOSED"), 99))
    
    open_count = sum(1 for r in all_results if r.get("relay_level") == "OPEN")
    partial_count = sum(1 for r in all_results if r.get("relay_level") == "PARTIAL")
    print(f"[+] Relay check complete: {open_count} OPEN, {partial_count} PARTIAL")
    
    return all_results