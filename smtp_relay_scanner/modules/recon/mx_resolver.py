# smtp_relay_scanner/modules/recon/mx_resolver.py

import dns.resolver
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

def resolve_mx_records(domain: str) -> List[str]:
    """
    Получает список MX серверов для домена.
    Возвращает список хостов (приоритет сортирует).
    """
    mx_servers = []
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        # Сортируем по приоритету (меньше = выше приоритет)
        mx_records = sorted(answers, key=lambda r: r.preference)
        for r in mx_records:
            mx_servers.append(str(r.exchange).rstrip('.'))
        return mx_servers
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        print(f"[-] MX resolve error for {domain}: {e}")
        return []

def resolve_a_record(hostname: str) -> List[str]:
    """
    Резолвит A-запись для хоста.
    """
    try:
        answers = dns.resolver.resolve(hostname, 'A', lifetime=5)
        return [str(r) for r in answers]
    except:
        return []

def bulk_mx_resolve(domains: List[str], max_workers: int = 50) -> Dict[str, List[str]]:
    """
    Массовый MX резолв для списка доменов.
    
    Returns:
        dict: {domain: [ip1, ip2, ...]}
    """
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(resolve_mx_records, domain): domain
            for domain in domains
        }
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                mx_hosts = future.result()
                if mx_hosts:
                    # Резолвим каждый MX хост в IP
                    all_ips = set()
                    for mx in mx_hosts:
                        ips = resolve_a_record(mx)
                        all_ips.update(ips)
                    results[domain] = list(all_ips)
            except:
                pass
    
    print(f"[+] MX resolver: resolved {len(results)} domains")
    return results

def get_ips_from_domain(domain: str) -> List[str]:
    """
    Получает IP адреса MX серверов для одного домена.
    """
    ips = []
    mx_hosts = resolve_mx_records(domain)
    for mx in mx_hosts:
        ips.extend(resolve_a_record(mx))
    return ips