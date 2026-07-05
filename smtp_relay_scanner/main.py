#!/usr/bin/env python3
# smtp_relay_scanner/main.py

"""
SMTP Relay Scanner v1.0
Инструмент для поиска и верификации SMTP Open Relay серверов.
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# Добавляем корень проекта в PYTHONPATH
sys.path.insert(0, str(Path(__file__).resolve().parent))

from smtp_relay_scanner.config import (
    BASE_DIR, DATA_DIR, DEFAULT_PORTS, EXPORT_DIR,
    DEFAULT_SENDER, DEFAULT_RECEIVER, DEFAULT_HELO_DOMAIN,
    DEFAULT_THREADS, SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET
)

from smtp_relay_scanner.modules.recon.asn_lookup import get_ranges_by_domain
from smtp_relay_scanner.modules.recon.shodan_search import search_smtp_servers_shodan
from smtp_relay_scanner.modules.recon.censys_search import search_smtp_servers_censys
from smtp_relay_scanner.modules.recon.mx_resolver import get_ips_from_domain
from smtp_relay_scanner.modules.recon.google_dorks import google_dorks_search, parse_smtp_credentials

from smtp_relay_scanner.modules.scanner.port_scanner import scan_hosts
from smtp_relay_scanner.modules.scanner.live_checker import bulk_check

from smtp_relay_scanner.modules.checker.preflight import preflight_check, print_preflight_report
from smtp_relay_scanner.modules.checker.relay_tester import check_open_relay, bulk_relay_check
from smtp_relay_scanner.modules.checker.vrfy_enum import enum_users, filter_valid_users
from smtp_relay_scanner.modules.checker.spf_checker import test_spf_enforcement
from smtp_relay_scanner.modules.checker.smuggler import test_smtp_smuggling

from smtp_relay_scanner.modules.mailer.send_mail import (
    send_mail_single, send_mail_bulk, send_test_email
)

from smtp_relay_scanner.modules.export.json_exporter import (
    export_json, export_relays_only, export_plain_relays
)
from smtp_relay_scanner.modules.export.csv_exporter import export_csv, export_relays_csv
from smtp_relay_scanner.modules.export.html_report import export_html


def parse_args() -> argparse.Namespace:
    """Парсит аргументы командной строки."""
    parser = argparse.ArgumentParser(
        description="SMTP Relay Scanner — поиск и верификация SMTP Open Relay серверов",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  %(prog)s --domain example.com
  %(prog)s --targets targets.txt --threads 500
  %(prog)s --shodan-api KEY --query "port:25 product:SMTP"
  %(prog)s --check-relay 192.0.2.1:25
  %(prog)s --relays relays.txt --send-campaign --from admin@test.com --to recipients.txt
        """
    )
    
    # === Режимы ===
    mode = parser.add_argument_group("Mode (выберите один)")
    mode.add_argument("--domain", type=str, help="Домен для ASN lookup и сбора целей")
    mode.add_argument("--targets", type=str, help="Файл со списком IP:port (по одному на строку)")
    mode.add_argument("--check-relay", type=str, help="Проверить один хост на relay (IP:port)")
    mode.add_argument("--shodan-api", type=str, help="API ключ Shodan для поиска целей")
    mode.add_argument("--censys-id", type=str, help="Censys API ID")
    mode.add_argument("--censys-secret", type=str, help="Censys API Secret")
    mode.add_argument("--send-campaign", action="store_true", help="Режим массовой рассылки через найденные relay")
    mode.add_argument("--full-scan", action="store_true", help="Полный цикл: recon → scan → relay check → export")
    
    # === Опции сканирования ===
    scan = parser.add_argument_group("Scan options")
    scan.add_argument("--scan-ports", type=str, default="25,587",
                      help="Порты для сканирования (по умолчанию: 25,587)")
    scan.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                      help=f"Количество потоков (по умолчанию: {DEFAULT_THREADS})")
    scan.add_argument("--rate-limit", type=int, default=0,
                      help="Задержка мс между запросами")
    
    # === Email опции ===
    email = parser.add_argument_group("Email options")
    email.add_argument("--sender", type=str, default=DEFAULT_SENDER,
                       help="Email отправителя для тестов")
    email.add_argument("--receiver", type=str, default=DEFAULT_RECEIVER,
                       help="Email получателя для тестов")
    email.add_argument("--from", dest="from_addr", type=str,
                       help="From адрес для рассылки")
    email.add_argument("--to", type=str,
                       help="Файл со списком получателей для рассылки")
    email.add_argument("--subject", type=str, default="SMTP Relay Scanner Test",
                       help="Тема письма")
    email.add_argument("--body", type=str,
                       help="Текст письма или путь к файлу с телом")
    email.add_argument("--html-body", type=str,
                       help="HTML версия письма или путь к файлу")
    
    # === Дополнительные проверки ===
    extra = parser.add_argument_group("Extra checks")
    extra.add_argument("--vrfy", action="store_true",
                       help="Выполнить VRFY/EXPN/RCPT перебор пользователей")
    extra.add_argument("--spf", action="store_true",
                       help="Проверить SPF enforcement")
    extra.add_argument("--smuggling", action="store_true",
                       help="Проверить на SMTP smuggling")
    extra.add_argument("--preflight", action="store_true",
                       help="Выполнить pre-flight проверку (MTA fingerprint)")
    
    # === Экспорт ===
    export = parser.add_argument_group("Export options")
    export.add_argument("--output-dir", type=str, default=str(EXPORT_DIR),
                        help="Директория для результатов")
    export.add_argument("--json", action="store_true", help="Экспорт в JSON")
    export.add_argument("--csv", action="store_true", help="Экспорт в CSV")
    export.add_argument("--html", action="store_true", help="Экспорт в HTML")
    export.add_argument("--relays-only", action="store_true",
                        help="Сохранить только relay серверы")
    
    # === Сеть ===
    net = parser.add_argument_group("Network")
    net.add_argument("--proxy", type=str, help="SOCKS5 прокси (host:port)")
    net.add_argument("--tor", action="store_true", help="Использовать Tor")
    net.add_argument("--no-verify-ssl", action="store_true",
                     help="Отключить проверку SSL сертификатов")
    
    return parser.parse_args()


def load_targets(filepath: str) -> List[Tuple[str, int]]:
    """Загружает список целей из файла."""
    targets = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    ip, port = line.rsplit(':', 1)
                    try:
                        targets.append((ip.strip(), int(port.strip())))
                    except ValueError:
                        print(f"[-] Invalid line: {line}")
                else:
                    targets.append((line.strip(), 25))
        print(f"[+] Loaded {len(targets)} targets from {filepath}")
    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")
    return targets


def load_recipients(filepath: str) -> List[str]:
    """Загружает список получателей из файла."""
    recipients = []
    try:
        with open(filepath, 'r') as f:
            recipients = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"[+] Loaded {len(recipients)} recipients from {filepath}")
    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")
    return recipients


def load_creds_from_file(filepath: str) -> List[Tuple[str, int, str, str]]:
    """Загружает SMTP credentials в формате host:port:user:pass"""
    creds = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':')
                if len(parts) >= 4:
                    host = parts[0]
                    try:
                        port = int(parts[1])
                    except ValueError:
                        continue
                    user = parts[2]
                    password = ':'.join(parts[3:])
                    creds.append((host, port, user, password))
        print(f"[+] Loaded {len(creds)} SMTP credentials from {filepath}")
    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")
    return creds


def resolve_domain(domain: str) -> List[Tuple[str, int]]:
    """Получает список целей по домену."""
    print(f"[*] Resolving domain: {domain}")
    targets = []
    
    # 1. MX записи
    print("[*] Trying MX record resolution...")
    mx_ips = get_ips_from_domain(domain)
    for ip in mx_ips:
        targets.append((ip, 25))
        targets.append((ip, 587))
    print(f"    MX: found {len(mx_ips)} IPs")
    
    # 2. ASN диапазоны
    if not mx_ips:
        print("[*] Trying ASN lookup...")
        ranges = get_ranges_by_domain(domain)
        if ranges:
            print(f"    ASN: found {len(ranges)} CIDR ranges")
            # Не сканируем все IP — слишком много, просто сохраняем CIDR
            print(f"    Ranges: {ranges[:5]}...")
    
    return targets


def run_full_scan(args: argparse.Namespace) -> List[Dict]:
    """Полный цикл: сбор целей → скан → relay check → экспорт."""
    all_results = []
    targets = []
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir) / f"scan_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # === Этап 1: Сбор целей ===
    print("\n" + "="*60)
    print("[PHASE 1] Target Collection")
    print("="*60)
    
    if args.domain:
        targets = resolve_domain(args.domain)
    
    if args.targets:
        file_targets = load_targets(args.targets)
        targets.extend(file_targets)
    
    if args.shodan_api:
        print("[*] Searching Shodan...")
        shodan_results = search_smtp_servers_shodan(args.shodan_api)
        for r in shodan_results:
            targets.append((r['ip'], r.get('port', 25)))
    
    if args.censys_id and args.censys_secret:
        print("[*] Searching Censys...")
        censys_results = search_smtp_servers_censys(args.censys_id, args.censys_secret)
        for r in censys_results:
            targets.append((r['ip'], r.get('port', 25)))
    
    # Убираем дубликаты
    targets = list(set(targets))
    print(f"[+] Total unique targets: {len(targets)}")
    
    if not targets:
        print("[-] No targets found. Use --domain, --targets, or --shodan-api.")
        return []
    
    # === Этап 2: Сканирование портов ===
    print("\n" + "="*60)
    print("[PHASE 2] Port Scanning")
    print("="*60)
    
    # Извлекаем IP адреса из targets (убираем порты — будут сканироваться отдельно)
    unique_ips = list(set(ip for ip, port in targets))
    ports = [int(p) for p in args.scan_ports.split(',')]
    
    if not unique_ips:
        print("[-] No IPs to scan.")
        return []
    
    print(f"[*] Scanning {len(unique_ips)} unique IPs on ports {ports}...")
    scanned = scan_hosts(unique_ips, ports, use_async=True, concurrency=args.threads)
    
    if not scanned:
        print("[-] No open ports found during scanning.")
        return []
    
    print(f"[+] Found {len(scanned)} open ports")
    
    # === Этап 3: Живые хосты ===
    print("\n" + "="*60)
    print("[PHASE 3] Live Host Check")
    print("="*60)
    
    live_hosts = bulk_check(scanned, max_workers=args.threads)
    
    if not live_hosts:
        print("[-] No live SMTP hosts found.")
        return []
    
    print(f"[+] Live hosts: {len(live_hosts)}")
    
    # === Этап 4: Relay Check ===
    print("\n" + "="*60)
    print("[PHASE 4] Open Relay Testing")
    print("="*60)
    
    relay_targets = [(h['ip'], h['port']) for h in live_hosts]
    
    # Загружаем credentials если есть
    creds_map = {}
    if args.targets:
        file_creds = load_creds_from_file(args.targets)
        for host, port, user, pwd in file_creds:
            creds_map[(host, port)] = (user, pwd)
    
    results = bulk_relay_check(relay_targets, max_workers=args.threads, creds_map=creds_map)
    
    # === Этап 5: Дополнительные проверки ===
    if args.preflight:
        print("\n" + "="*60)
        print("[PHASE 5a] Pre-flight Checks")
        print("="*60)
        for r in results:
            pf = preflight_check(r['ip'], r['port'])
            print(print_preflight_report(pf))
    
    if args.vrfy:
        print("\n" + "="*60)
        print("[PHASE 5b] User Enumeration (VRFY/RCPT)")
        print("="*60)
        for r in results[:5]:  # Только первые 5 для демо
            users = enum_users(r['ip'], r['port'], 
                              ["admin", "root", "info", "support", "test"])
            valid = filter_valid_users(users)
            if valid:
                print(f"    {r['ip']}:{r['port']} — valid users: {valid}")
    
    if args.spf:
        print("\n" + "="*60)
        print("[PHASE 5c] SPF Enforcement Check")
        print("="*60)
        for r in results:
            if r.get('relay_level') in ('OPEN', 'PARTIAL'):
                spf = test_spf_enforcement(r['ip'], r['port'], 
                                           args.domain or 'example.com')
                print(f"    {r['ip']}:{r['port']} — {spf['summary']}")
    
    if args.smuggling:
        print("\n" + "="*60)
        print("[PHASE 5d] SMTP Smuggling Check")
        print("="*60)
        for r in results:
            smug = test_smtp_smuggling(r['ip'], r['port'])
            if smug.get('vulnerable'):
                print(f"    [!] {r['ip']}:{r['port']} — {smug['summary']}")
    
    # === Этап 6: Экспорт ===
    print("\n" + "="*60)
    print("[PHASE 6] Export Results")
    print("="*60)
    
    if args.json:
        export_json(results, output_dir / "full_report.json")
        if args.relays_only:
            export_relays_only(results, output_dir / "relays.json")
    if args.csv:
        export_csv(results, output_dir / "report.csv")
        if args.relays_only:
            export_relays_csv(results, output_dir / "relays.csv")
    if args.html:
        export_html(results, output_dir / "report.html")
    
    # Всегда сохраняем простой список relay
    export_plain_relays(results, output_dir / "found_relays.txt")
    
    print(f"\n[+] All results saved to: {output_dir}")
    
    return results


def check_single_relay(host: str) -> Dict:
    """Проверяет один хост на relay."""
    if ':' in host:
        ip, port = host.rsplit(':', 1)
        port = int(port)
    else:
        ip, port = host, 25
    
    print(f"[*] Checking single host: {ip}:{port}")
    
    # Pre-flight
    pf = preflight_check(ip, port)
    print(print_preflight_report(pf))
    
    # Relay test
    result = check_open_relay(ip, port)
    
    return result


def send_campaign_mode(args: argparse.Namespace):
    """Режим массовой рассылки через найденные relay."""
    print("\n" + "="*60)
    print("[CAMPAIGN MODE] Mass Mailing via Open Relays")
    print("="*60)
    
    if not args.relays_only and not args.targets:
        print("[-] Need relay list (--relays-only <file> or --targets <file>)")
        return
    
    # Загружаем relay серверы
    relay_file = args.relays_only if args.relays_only else args.targets
    relays = load_targets(relay_file)
    
    if not relays:
        print("[-] No relay servers loaded.")
        return
    
    # Загружаем получателей
    if not args.to:
        print("[-] Need recipient list (--to <file>)")
        return
    
    recipients = load_recipients(args.to)
    if not recipients:
        print("[-] No recipients loaded.")
        return
    
    from_addr = args.from_addr or "admin@test.com"
    subject = args.subject
    
    # Загружаем тело письма
    body = args.body or "Test message from SMTP Relay Scanner."
    if args.body and os.path.isfile(args.body):
        with open(args.body, 'r') as f:
            body = f.read()
    
    html_body = None
    if args.html_body:
        if os.path.isfile(args.html_body):
            with open(args.html_body, 'r') as f:
                html_body = f.read()
        else:
            html_body = args.html_body
    
    print(f"[*] Sending {len(recipients)} emails via {len(relays)} relay servers...")
    print(f"    From: {from_addr}")
    print(f"    Subject: {subject}")
    
    results = send_mail_bulk(
        smtp_servers=relays,
        from_addr=from_addr,
        to_addrs=recipients,
        subject=subject,
        body=body,
        html_body=html_body,
        max_workers=args.threads,
        rate_limit_ms=args.rate_limit
    )
    
    sent = sum(1 for r in results if r.get("success"))
    failed = sum(1 for r in results if not r.get("success"))
    print(f"\n[+] Campaign complete: {sent} sent, {failed} failed")


def main():
    """Точка входа."""
    args = parse_args()
    
    print(r"""
  ____  __  __ _____ ____  
 / ___||  \/  |_   _|  _ \ 
 \___ \| |\/| | | | | |_) |
  ___) | |  | | | | |  __/ 
 |____/|_|  |_| |_| |_|    
                            
  SMTP Relay Scanner v1.0
  For authorized security testing only
""")
    
    try:
        if args.send_campaign:
            send_campaign_mode(args)
        elif args.check_relay:
            check_single_relay(args.check_relay)
        elif args.full_scan or args.domain or args.targets:
            run_full_scan(args)
        else:
            print("[!] No mode specified. Use one of:")
            print("    --domain <domain>     Scan by domain")
            print("    --targets <file>      Scan targets from file")
            print("    --check-relay <host>  Check single host")
            print("    --send-campaign       Mass mailing mode")
            print("    --full-scan           Full automatic scan")
            print("\nUse --help for full list of options.")
    
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()