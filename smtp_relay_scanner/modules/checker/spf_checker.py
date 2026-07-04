# smtp_relay_scanner/modules/checker/spf_checker.py

import socket
import dns.resolver
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from smtp_relay_scanner.config import (
    SMTP_EHLO, SMTP_MAIL_FROM, SMTP_RCPT_TO, SMTP_DATA,
    SMTP_QUIT, SMTP_RSET, DEFAULT_HELO_DOMAIN,
    RELAY_TEST_HEADERS, TIMEOUT_CONNECT, TIMEOUT_READ
)
from smtp_relay_scanner.modules.scanner.live_checker import (
    connect_smtp, recv_response, send_command
)


def get_spf_record(domain: str) -> Optional[str]:
    """
    Получает SPF запись для домена.
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith("v=spf1"):
                return txt
    except:
        pass
    return None


def get_spf_all_mechanism(spf_record: str) -> str:
    """
    Определяет all-механизм SPF записи.
    
    Returns:
        "-all" (hard fail), "~all" (soft fail), "?all" (neutral), "+all" (pass all)
    """
    if not spf_record:
        return "?all"
    
    parts = spf_record.lower().split()
    for part in parts:
        if part in ["-all", "~all", "?all", "+all"]:
            return part
    return "?all"


def test_spf_enforcement(
    ip: str,
    port: int,
    target_domain: str,
    test_email: str = "test@mail-test.com",
    domain: str = DEFAULT_HELO_DOMAIN,
    use_ssl: bool = False
) -> Dict[str, any]:
    """
    Тестирует SPF enforcement на SMTP сервере.
    
    Пытается отправить письмо от @target_domain с неподдерживаемого IP.
    Если письмо проходит — SPF не форсится.
    
    Returns:
        Dict с результатами теста
    """
    result = {
        "ip": ip,
        "port": port,
        "target_domain": target_domain,
        "spf_record": None,
        "spf_all": "?all",
        "tests": [],
        "spf_enforced": True,
        "spoofing_possible": False,
        "summary": ""
    }
    
    # Получаем SPF запись
    spf_record = get_spf_record(target_domain)
    result["spf_record"] = spf_record
    result["spf_all"] = get_spf_all_mechanism(spf_record) if spf_record else "?all"
    
    # Тест 1: спуфинг внутреннего домена
    test_spoof_internal(ip, port, target_domain, test_email, domain, use_ssl, result)
    
    # Тест 2: спуфинг внешнего домена (gmail)
    test_spoof_external(ip, port, target_domain, test_email, domain, use_ssl, result)
    
    # Тест 3: null sender
    test_null_sender(ip, port, target_domain, test_email, domain, use_ssl, result)
    
    # Итог
    passed = [t for t in result["tests"] if t.get("accepted")]
    if passed:
        result["spf_enforced"] = False
        result["spoofing_possible"] = True
        result["summary"] = f"SPF NOT ENFORCED — {len(passed)} spoofed sender(s) accepted"
    else:
        result["summary"] = "SPF is enforced — all spoofed senders rejected"
    
    return result


def test_spoof_internal(ip, port, target_domain, test_email, domain, use_ssl, result):
    """Тест спуфинга внутреннего домена."""
    sock = connect_smtp(ip, port, use_ssl)
    if not sock:
        result["tests"].append({"test": "spoof_internal", "accepted": False, "error": "Connection failed"})
        return
    
    try:
        banner = recv_response(sock)
        send_command(sock, SMTP_EHLO.format(domain=domain))
        send_command(sock, SMTP_RSET)
        
        mail_resp = send_command(sock, SMTP_MAIL_FROM.format(email=f"spoofed@{target_domain}"))
        rcpt_resp = send_command(sock, SMTP_RCPT_TO.format(email=test_email))
        
        accepted = mail_resp.startswith("250") and rcpt_resp.startswith(("250", "251"))
        
        result["tests"].append({
            "test": "spoof_internal",
            "name": f"Spoof internal domain (@{target_domain})",
            "mail_from": f"spoofed@{target_domain}",
            "accepted": accepted,
            "mail_response": mail_resp.strip()[:50],
            "rcpt_response": rcpt_resp.strip()[:50]
        })
        
        if accepted:
            # DATA
            data_resp = send_command(sock, SMTP_DATA)
            if data_resp.startswith("354"):
                headers = RELAY_TEST_HEADERS.format(
                    sender=f"spoofed@{target_domain}",
                    receiver=test_email,
                    test_id="spf_spoof_internal",
                    date=datetime.utcnow().isoformat()
                )
                send_command(sock, headers + ".\r\n")
        
        send_command(sock, SMTP_QUIT)
        sock.close()
    except Exception as e:
        result["tests"].append({"test": "spoof_internal", "accepted": False, "error": str(e)})
        try: sock.close()
        except: pass


def test_spoof_external(ip, port, target_domain, test_email, domain, use_ssl, result):
    """Тест спуфинга внешнего домена (gmail)."""
    sock = connect_smtp(ip, port, use_ssl)
    if not sock:
        result["tests"].append({"test": "spoof_external", "accepted": False, "error": "Connection failed"})
        return
    
    try:
        banner = recv_response(sock)
        send_command(sock, SMTP_EHLO.format(domain=domain))
        send_command(sock, SMTP_RSET)
        
        mail_resp = send_command(sock, SMTP_MAIL_FROM.format(email="spoofed@gmail.com"))
        rcpt_resp = send_command(sock, SMTP_RCPT_TO.format(email=test_email))
        
        accepted = mail_resp.startswith("250") and rcpt_resp.startswith(("250", "251"))
        
        result["tests"].append({
            "test": "spoof_external",
            "name": "Spoof external domain (@gmail.com)",
            "mail_from": "spoofed@gmail.com",
            "accepted": accepted,
            "mail_response": mail_resp.strip()[:50],
            "rcpt_response": rcpt_resp.strip()[:50]
        })
        
        send_command(sock, SMTP_QUIT)
        sock.close()
    except Exception as e:
        result["tests"].append({"test": "spoof_external", "accepted": False, "error": str(e)})
        try: sock.close()
        except: pass


def test_null_sender(ip, port, target_domain, test_email, domain, use_ssl, result):
    """Тест null sender (MAIL FROM:<>)."""
    sock = connect_smtp(ip, port, use_ssl)
    if not sock:
        result["tests"].append({"test": "null_sender", "accepted": False, "error": "Connection failed"})
        return
    
    try:
        banner = recv_response(sock)
        send_command(sock, SMTP_EHLO.format(domain=domain))
        send_command(sock, SMTP_RSET)
        
        mail_resp = send_command(sock, "MAIL FROM:<>\r\n")
        rcpt_resp = send_command(sock, SMTP_RCPT_TO.format(email=test_email))
        
        accepted = mail_resp.startswith("250") and rcpt_resp.startswith(("250", "251"))
        
        result["tests"].append({
            "test": "null_sender",
            "name": "Null sender (MAIL FROM: <>)",
            "mail_from": "<>",
            "accepted": accepted,
            "mail_response": mail_resp.strip()[:50],
            "rcpt_response": rcpt_resp.strip()[:50]
        })
        
        send_command(sock, SMTP_QUIT)
        sock.close()
    except Exception as e:
        result["tests"].append({"test": "null_sender", "accepted": False, "error": str(e)})
        try: sock.close()
        except: pass