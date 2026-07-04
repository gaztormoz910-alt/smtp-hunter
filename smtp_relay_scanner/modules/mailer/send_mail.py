# smtp_relay_scanner/modules/mailer/send_mail.py

import smtplib
import ssl
import time
import random
from typing import List, Dict, Optional, Tuple
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from smtp_relay_scanner.config import TIMEOUT_CONNECT, TIMEOUT_SEND


def send_mail_single(
    smtp_host: str,
    smtp_port: int,
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
    html_body: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    use_tls: bool = False,
    use_ssl: bool = False,
    timeout: int = TIMEOUT_SEND
) -> Dict[str, any]:
    """
    Отправляет одно письмо через SMTP сервер.
    
    Args:
        smtp_host: IP/DNS SMTP сервера
        smtp_port: Порт SMTP сервера
        from_addr: Email отправителя
        to_addr: Email получателя
        subject: Тема письма
        body: Текст письма (plain text)
        html_body: HTML версия письма (опционально)
        username: Имя пользователя для AUTH (опционально)
        password: Пароль для AUTH (опционально)
        use_tls: Использовать STARTTLS
        use_ssl: Использовать SSL/TLS с первого байта (SMTPS)
        timeout: Таймаут
    
    Returns:
        Dict с результатом отправки
    """
    result = {
        "success": False,
        "host": smtp_host,
        "port": smtp_port,
        "from": from_addr,
        "to": to_addr,
        "subject": subject,
        "error": None,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    try:
        # Формируем письмо
        msg = MIMEMultipart('alternative') if html_body else MIMEText(body, 'plain', 'utf-8')
        
        if html_body:
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
        msg['X-Mailer'] = 'SMTP Relay Scanner v1.0'
        
        # Подключаемся
        if use_ssl or smtp_port == 465:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=timeout, context=context)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=timeout)
            server.set_debuglevel(0)
            
            if use_tls:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
        
        # AUTH (опционально)
        if username and password:
            server.login(username, password)
        
        # Отправляем
        server.sendmail(from_addr, [to_addr], msg.as_string())
        server.quit()
        
        result["success"] = True
        
    except smtplib.SMTPRecipientsRefused as e:
        result["error"] = f"Recipients refused: {e}"
    except smtplib.SMTPSenderRefused as e:
        result["error"] = f"Sender refused: {e}"
    except smtplib.SMTPDataError as e:
        result["error"] = f"Data error: {e}"
    except smtplib.SMTPConnectError as e:
        result["error"] = f"Connection error: {e}"
    except smtplib.SMTPAuthenticationError as e:
        result["error"] = f"Authentication error: {e}"
    except Exception as e:
        result["error"] = str(e)
    
    return result


def send_mail_bulk(
    smtp_servers: List[Tuple[str, int]],
    from_addr: str,
    to_addrs: List[str],
    subject: str,
    body: str,
    html_body: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    use_tls: bool = False,
    use_ssl: bool = False,
    max_workers: int = 10,
    rate_limit_ms: int = 0,
    rotate_servers: bool = True
) -> List[Dict[str, any]]:
    """
    Массовая отправка писем через пул SMTP серверов с ротацией.
    
    Args:
        smtp_servers: Список (host, port) для отправки
        from_addr: Email отправителя
        to_addrs: Список получателей
        subject: Тема письма
        body: Текст письма
        html_body: HTML версия (опционально)
        username: Имя пользователя (опционально)
        password: Пароль (опционально)
        use_tls: Использовать STARTTLS
        use_ssl: Использовать SMTPS
        max_workers: Количество потоков
        rate_limit_ms: Задержка между отправками (ms)
        rotate_servers: Ротировать сервера между отправками
    
    Returns:
        Список результатов отправки
    """
    results = []
    server_pool = smtp_servers.copy()
    
    def send_with_server(to_addr):
        nonlocal server_pool
        
        if rotate_servers and len(server_pool) > 1:
            server = random.choice(server_pool)
        else:
            server = server_pool[0]
        
        if rate_limit_ms > 0:
            time.sleep(rate_limit_ms / 1000.0)
        
        return send_mail_single(
            smtp_host=server[0],
            smtp_port=server[1],
            from_addr=from_addr,
            to_addr=to_addr,
            subject=subject,
            body=body,
            html_body=html_body,
            username=username,
            password=password,
            use_tls=use_tls,
            use_ssl=use_ssl
        )
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_addr = {
            executor.submit(send_with_server, addr): addr
            for addr in to_addrs
        }
        
        for future in as_completed(future_to_addr):
            try:
                result = future.result()
                results.append(result)
                status = "✓" if result["success"] else "✗"
                print(f"  [{status}] {result['to']}: {'sent' if result['success'] else result['error'][:50]}")
            except Exception as e:
                results.append({
                    "success": False,
                    "to": future_to_addr[future],
                    "error": str(e)
                })
    
    sent_count = sum(1 for r in results if r.get("success"))
    print(f"[+] Bulk send: {sent_count}/{len(results)} delivered")
    
    return results


def send_test_email(
    smtp_host: str,
    smtp_port: int,
    from_addr: str,
    to_addr: str,
    test_id: str = "relay_test"
) -> Dict[str, any]:
    """
    Отправляет короткое тестовое письмо для проверки relay.
    """
    body = (
        f"SMTP Open Relay Test\n"
        f"Test ID: {test_id}\n"
        f"Timestamp: {datetime.utcnow().isoformat()}\n"
        f"Server: {smtp_host}:{smtp_port}\n"
    )
    
    return send_mail_single(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        from_addr=from_addr,
        to_addr=to_addr,
        subject=f"SMTP Relay Test - {test_id}",
        body=body
    )