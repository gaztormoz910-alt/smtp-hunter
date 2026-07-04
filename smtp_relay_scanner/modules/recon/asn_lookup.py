# smtp_relay_scanner/modules/recon/asn_lookup.py

import ipwhois
import requests
import re
from typing import List

def get_asn_from_domain(domain: str) -> str:
    """
    Получает номер ASN по домену через DNS + whois.
    """
    import dns.resolver
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip = str(answers[0])
        obj = ipwhois.IPWhois(ip)
        result = obj.lookup_whois()
        asn = result.get('asn', '')
        return asn
    except Exception as e:
        print(f"[-] ASN lookup error for {domain}: {e}")
        return ""

def get_ranges_from_asn(asn: str) -> List[str]:
    """
    Получает список CIDR диапазонов по ASN.
    """
    ranges = []
    try:
        obj = ipwhois.IPWhois(asn)
        result = obj.lookup_whois()
        for net in result.get('nets', []):
            cidr = net.get('cidr', '')
            if cidr:
                ranges.append(cidr)
    except:
        pass
    return ranges

def get_ranges_from_hackertarget(domain: str) -> List[str]:
    """
    Альтернативный метод через Hackertarget API.
    """
    url = f"https://api.hackertarget.com/aslookup/?q={domain}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            lines = resp.text.strip().split('\n')
            ranges = [line.split(',')[0] for line in lines if '/' in line]
            return ranges
    except:
        pass
    return []

def get_ranges_by_domain(domain: str) -> List[str]:
    """
    Комбинированный метод: пробует whois, затем hackertarget.
    """
    ranges = get_ranges_from_asn(get_asn_from_domain(domain))
    if not ranges:
        ranges = get_ranges_from_hackertarget(domain)
    return ranges

def expand_ranges_to_ips(cidr_list: List[str]) -> List[str]:
    """
    Конвертирует CIDR в список IP для сканирования.
    Для /24 и выше просто возвращает CIDR, для меньших раскрывает.
    """
    from ipaddress import ip_network
    ips = []
    for cidr in cidr_list:
        try:
            net = ip_network(cidr, strict=False)
            if net.prefixlen >= 24:
                # Слишком много хостов — возвращаем CIDR как есть
                ips.append(cidr)
            else:
                for host in net.hosts():
                    ips.append(str(host))
        except:
            pass
    return ips