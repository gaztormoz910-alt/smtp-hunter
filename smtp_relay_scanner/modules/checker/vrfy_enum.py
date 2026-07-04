# smtp_relay_scanner/modules/checker/vrfy_enum.py

import socket
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from smtp_relay_scanner.config import (
    SMTP_EHLO, SMTP_MAIL_FROM, SMTP_RCPT_TO, SMTP_VRFY,
    SMTP_EXPN, SMTP_QUIT, SMTP_RSET, DEFAULT_HELO_DOMAIN,
    TIMEOUT_CONNECT, TIMEOUT_READ
)
from smtp_relay_scanner.modules.scanner.live_checker import (
    connect_smtp, recv_response, send_command
)


def vrfy_user(ip: str, port: int, user: str, domain: str = DEFAULT_HELO_DOMAIN,
              use_ssl: bool = False) -> Dict[str, any]:
    """
    Проверяет существование пользователя через VRFY.
    
    Returns:
        Dict с результатом: user, method, status, response
    """
    result = {
        "user": user,
        "method": "VRFY",
        "valid": False,
        "potential": False,
        "response": "",
        "response_code": ""
    }
    
    sock = connect_smtp(ip, port, use_ssl)
    if not sock:
        result["response"] = "Connection failed"
        return result
    
    try:
        banner = recv_response(sock)
        ehlo_resp = send_command(sock, SMTP_EHLO.format(domain=domain))
        if not ehlo_resp or not ehlo_resp.startswith("250"):
            ehlo_resp = send_command(sock, f"HELO {domain}\r\n")
        
        # VRFY
        vrfy_resp = send_command(sock, SMTP_VRFY.format(user=user))
        result["response"] = vrfy_resp.strip()[:100]
        result["response_code"] = vrfy_resp[:3] if len(vrfy_resp) >= 3 else ""
        
        # 250 = exists, 252 = maybe exists, 550 = doesn't exist
        if vrfy_resp.startswith("250"):
            result["valid"] = True
        elif vrfy_resp.startswith("252"):
            result["potential"] = True
        
        send_command(sock, SMTP_QUIT)
        sock.close()
    except Exception as e:
        result["response"] = str(e)
        try:
            sock.close()
        except:
            pass
    
    return result


def rcpt_user(ip: str, port: int, user: str, domain: str = DEFAULT_HELO_DOMAIN,
              use_ssl: bool = False) -> Dict[str, any]:
    """
    Проверяет существование пользователя через RCPT TO.
    Более надёжный метод, чем VRFY.
    
    Returns:
        Dict с результатом: user, method, status, response
    """
    result = {
        "user": user,
        "method": "RCPT",
        "valid": False,
        "potential": False,
        "response": "",
        "response_code": ""
    }
    
    sock = connect_smtp(ip, port, use_ssl)
    if not sock:
        result["response"] = "Connection failed"
        return result
    
    try:
        banner = recv_response(sock)
        ehlo_resp = send_command(sock, SMTP_EHLO.format(domain=domain))
        if not ehlo_resp or not ehlo_resp.startswith("250"):
            ehlo_resp = send_command(sock, f"HELO {domain}\r\n")
        
        send_command(sock, SMTP_RSET)
        
        # MAIL FROM с тестовым отправителем
        mail_resp = send_command(sock, SMTP_MAIL_FROM.format(email=f"test@{domain}"))
        
        # RCPT TO на проверяемого пользователя
        email = f"{user}@{domain}" if "@" not in user else user
        rcpt_resp = send_command(sock, SMTP_RCPT_TO.format(email=email))
        result["response"] = rcpt_resp.strip()[:100]
        result["response_code"] = rcpt_resp[:3] if len(rcpt_resp) >= 3 else ""
        
        # 250/251 = valid, 550 = invalid, 252 = maybe
        if rcpt_resp.startswith(("250", "251")):
            result["valid"] = True
        elif rcpt_resp.startswith("252"):
            result["potential"] = True
        
        send_command(sock, SMTP_QUIT)
        sock.close()
    except Exception as e:
        result["response"] = str(e)
        try:
            sock.close()
        except:
            pass
    
    return result


def expn_user(ip: str, port: int, user: str, domain: str = DEFAULT_HELO_DOMAIN,
              use_ssl: bool = False) -> Dict[str, any]:
    """
    Проверяет существование пользователя через EXPN (расширение списков рассылки).
    """
    result = {
        "user": user,
        "method": "EXPN",
        "valid": False,
        "potential": False,
        "response": "",
        "response_code": ""
    }
    
    sock = connect_smtp(ip, port, use_ssl)
    if not sock:
        result["response"] = "Connection failed"
        return result
    
    try:
        banner = recv_response(sock)
        ehlo_resp = send_command(sock, SMTP_EHLO.format(domain=domain))
        if not ehlo_resp or not ehlo_resp.startswith("250"):
            ehlo_resp = send_command(sock, f"HELO {domain}\r\n")
        
        expn_resp = send_command(sock, SMTP_EXPN.format(user=user))
        result["response"] = expn_resp.strip()[:100]
        result["response_code"] = expn_resp[:3] if len(expn_resp) >= 3 else ""
        
        if expn_resp.startswith("250"):
            result["valid"] = True
        elif expn_resp.startswith("252"):
            result["potential"] = True
        
        send_command(sock, SMTP_QUIT)
        sock.close()
    except Exception as e:
        result["response"] = str(e)
        try:
            sock.close()
        except:
            pass
    
    return result


def enum_users(ip: str, port: int, userlist: List[str],
               domain: str = DEFAULT_HELO_DOMAIN,
               method: str = "RCPT",
               max_workers: int = 50,
               use_ssl: bool = False) -> List[Dict[str, any]]:
    """
    Массовый перебор пользователей на SMTP сервере.
    
    Args:
        ip: IP SMTP сервера
        port: Порт SMTP сервера
        userlist: Список пользователей для проверки
        domain: Домен для RCPT TO
        method: VRFY, RCPT, EXPN или ALL
        max_workers: Количество потоков
    
    Returns:
        Список результатов
    """
    methods_map = {
        "VRFY": vrfy_user,
        "RCPT": rcpt_user,
        "EXPN": expn_user
    }
    
    all_results = []
    
    if method == "ALL":
        methods_to_use = ["VRFY", "RCPT", "EXPN"]
    else:
        methods_to_use = [method]
    
    for m in methods_to_use:
        func = methods_map[m]
        valid_count = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_user = {
                executor.submit(func, ip, port, user, domain, use_ssl): user
                for user in userlist
            }
            
            for future in as_completed(future_to_user):
                try:
                    res = future.result()
                    all_results.append(res)
                    if res["valid"]:
                        valid_count += 1
                except:
                    pass
        
        print(f"[+] {m}: found {valid_count} valid users")
    
    return all_results


def filter_valid_users(results: List[Dict[str, any]]) -> List[str]:
    """
    Фильтрует результаты, возвращая только валидные пользователи.
    """
    valid = set()
    for r in results:
        if r["valid"]:
            valid.add(r["user"])
    return sorted(valid)