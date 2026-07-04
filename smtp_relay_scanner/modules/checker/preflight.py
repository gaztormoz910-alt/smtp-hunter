# smtp_relay_scanner/modules/checker/preflight.py

import socket
import ssl
from typing import Optional, Dict, List, Tuple
from datetime import datetime

from smtp_relay_scanner.config import (
    TIMEOUT_CONNECT, TIMEOUT_READ, DEFAULT_HELO_DOMAIN,
    SMTP_EHLO, SMTP_MAIL_FROM, SMTP_RCPT_TO, SMTP_QUIT,
    SMTP_RSET, SMTP_VRFY, SUCCESS_CODES, GREYLIST_CODES
)
from smtp_relay_scanner.modules.scanner.live_checker import (
    connect_smtp, recv_response, send_command, detect_mta
)

def preflight_check(ip: str, port: int, use_ssl: bool = False,
                    domain: str = DEFAULT_HELO_DOMAIN,
                    test_user: str = "zz_test_username_xyz123") -> Dict[str, any]:
    """
    Pre-flight проверка SMTP сервера.
    
    Определяет:
    - MTA и баннер
    - Поддержка STARTTLS
    - Требуется ли AUTH
    - Доступность VRFY/EXPN/RCPT
    - Catch-all домен
    - Greylisting
    
    Returns:
        Dict с результатами pre-flight проверки
    """
    result = {
        "ip": ip,
        "port": port,
        "mta": "Unknown",
        "banner": "",
        "starttls": False,
        "auth_required": False,
        "auth_methods": [],
        "vrfy_supported": False,
        "expn_supported": False,
        "rcpt_supported": False,
        "catch_all": False,
        "greylisting": False,
        "ehlo_response": "",
        "preflight_passed": False,
        "error": None
    }
    
    sock = connect_smtp(ip, port, use_ssl)
    if not sock:
        result["error"] = "Connection failed"
        return result
    
    try:
        # Баннер
        banner = recv_response(sock)
        if not banner or not banner.startswith("220"):
            result["error"] = f"Invalid banner: {banner[:50]}"
            sock.close()
            return result
        
        result["banner"] = banner[:200]
        result["mta"] = detect_mta(banner)
        
        # EHLO
        ehlo_resp = send_command(sock, SMTP_EHLO.format(domain=domain))
        if not ehlo_resp or not ehlo_resp.startswith("250"):
            # Пробуем HELO
            ehlo_resp = send_command(sock, f"HELO {domain}\r\n")
            if not ehlo_resp or not ehlo_resp.startswith("250"):
                result["error"] = "EHLO/HELO failed"
                sock.close()
                return result
        
        result["ehlo_response"] = ehlo_resp[:500]
        
        # Анализируем EHLO ответ
        ehlo_lines = ehlo_resp.upper().split('\r\n')
        for line in ehlo_lines:
            if "STARTTLS" in line:
                result["starttls"] = True
            if "AUTH" in line:
                result["auth_required"] = True
                # Парсим методы аутентификации
                if "PLAIN" in line:
                    result["auth_methods"].append("PLAIN")
                if "LOGIN" in line:
                    result["auth_methods"].append("LOGIN")
                if "CRAM-MD5" in line:
                    result["auth_methods"].append("CRAM-MD5")
                if "DIGEST-MD5" in line:
                    result["auth_methods"].append("DIGEST-MD5")
                if "XOAUTH2" in line:
                    result["auth_methods"].append("XOAUTH2")
        
        # RSET
        send_command(sock, SMTP_RSET)
        
        # Проверка VRFY
        vrfy_resp = send_command(sock, SMTP_VRFY.format(user=test_user))
        result["vrfy_supported"] = vrfy_resp.startswith(("250", "252", "251"))
        
        # RSET
        send_command(sock, SMTP_RSET)
        
        # Проверка EXPN
        expn_resp = send_command(sock, f"EXPN {test_user}\r\n")
        result["expn_supported"] = expn_resp.startswith(("250", "252"))
        
        # RSET
        send_command(sock, SMTP_RSET)
        
        # Проверка RCPT TO (на несуществующий юзер — детект catch-all)
        mail_resp = send_command(sock, SMTP_MAIL_FROM.format(email=f"test@{domain}"))
        rcpt_resp = send_command(sock, SMTP_RCPT_TO.format(email=f"{test_user}@{domain}"))
        
        result["rcpt_supported"] = rcpt_resp.startswith(("250", "251"))
        
        # Catch-all детект: если RCPT на мусорный юзер дал 250/251
        if rcpt_resp.startswith(("250", "251")):
            result["catch_all"] = True
        
        # Greylisting детект
        if any(code in rcpt_resp[:3] for code in ["451", "450"]):
            result["greylisting"] = True
        
        # Silent AUTH probe: пробуем MAIL FROM без AUTH
        if result["auth_supported"]:
            send_command(sock, SMTP_RSET)
            test_mail = send_command(sock, SMTP_MAIL_FROM.format(email=f"test@{domain}"))
            if test_mail.startswith("250"):
                result["auth_required"] = False  # AUTH advertised, но не требуется
        
        result["preflight_passed"] = True
        
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


def print_preflight_report(result: Dict[str, any]) -> str:
    """
    Форматирует pre-flight результат в строку для вывода.
    """
    lines = []
    lines.append(f"[*] Pre-flight Report for {result['ip']}:{result['port']}")
    lines.append(f"    MTA     : {result['mta']}")
    lines.append(f"    Banner  : {result['banner'][:80]}")
    lines.append(f"    STARTTLS: {'✓ yes' if result['starttls'] else '✗ no'}")
    lines.append(f"    AUTH    : {'required' if result['auth_required'] else 'not required'} "
                 f"({'/'.join(result['auth_methods']) if result['auth_methods'] else 'none'})")
    lines.append(f"    VRFY    : {'✓ supported' if result['vrfy_supported'] else '✗ disabled'}")
    lines.append(f"    EXPN    : {'✓ supported' if result['expn_supported'] else '✗ disabled'}")
    lines.append(f"    RCPT TO : {'✓ supported' if result['rcpt_supported'] else '✗ disabled'}")
    lines.append(f"    CatchAll: {'⚠ DETECTED' if result['catch_all'] else '✓ none'}")
    lines.append(f"    GreyList: {'⚠ DETECTED' if result['greylisting'] else '✓ none'}")
    
    if result.get('error'):
        lines.append(f"    ERROR   : {result['error']}")
    
    return '\n'.join(lines)