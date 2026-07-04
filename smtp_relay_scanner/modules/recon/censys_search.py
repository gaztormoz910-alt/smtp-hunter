# smtp_relay_scanner/modules/recon/censys_search.py

from typing import List, Dict, Optional

def search_smtp_servers_censys(
    api_id: str,
    api_secret: str,
    query: str = "services.port:25 and services.service_name:SMTP",
    limit: int = 100
) -> List[Dict[str, any]]:
    """
    Ищет SMTP серверы через Censys API (Censys Search v2).
    
    Args:
        api_id: Censys API ID
        api_secret: Censys API Secret
        query: Поисковый запрос в формате Censys Search
        limit: Максимум результатов
    
    Returns:
        Список словарей с ip, port, hostnames, org, location
    """
    if not api_id or not api_secret:
        print("[!] Censys API credentials not provided. Skipping Censys search.")
        return []
    
    try:
        from censys.search import CensysHosts
        c = CensysHosts(api_id=api_id, api_secret=api_secret)
        results = []
        
        query = f"services.service_name: SMTP AND services.port: 25"
        
        try:
            hosts = c.search(
                query,
                per_page=min(limit, 100),
                pages=1
            )
            
            for host in hosts:
                ip = host.get('ip', '')
                services = host.get('services', [])
                
                for svc in services:
                    if svc.get('port') in [25, 465, 587, 2525]:
                        results.append({
                            'ip': ip,
                            'port': svc.get('port', 25),
                            'transport': svc.get('transport_protocol', 'TCP'),
                            'service_name': svc.get('service_name', 'SMTP'),
                            'banner': str(svc.get('banner', ''))[:300],
                            'country': host.get('location', {}).get('country', ''),
                            'city': host.get('location', {}).get('city', ''),
                            'asn': host.get('asn', ''),
                            'org': host.get('autonomous_system', {}).get('organization', '')
                        })
                        break  # один IP — один порт
            
            print(f"[+] Censys: found {len(results)} SMTP servers")
            return results
            
        except Exception as e:
            print(f"[-] Censys search error: {e}")
            return []
    
    except ImportError:
        print("[!] censys library not installed. Install with: pip install censys")
        return []
    except Exception as e:
        print(f"[-] Censys import error: {e}")
        return []

def search_censys_open_relay(
    api_id: str,
    api_secret: str,
    limit: int = 50
) -> List[Dict[str, any]]:
    """
    Специализированный поиск Censys для open relay.
    """
    queries = [
        "services.service_name: SMTP AND services.port: 25",
        "services.service_name: SMTP AND services.port: 587",
        "services.service_name: SMTP AND services.port: 2525"
    ]
    
    all_results = []
    for q in queries:
        results = search_smtp_servers_censys(api_id, api_secret, q, limit // len(queries))
        all_results.extend(results)
    
    return all_results