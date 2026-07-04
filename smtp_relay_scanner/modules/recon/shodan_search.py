# smtp_relay_scanner/modules/recon/shodan_search.py

from typing import List, Dict, Optional
import os

def search_smtp_servers_shodan(
    api_key: str,
    query: str = "port:25 product:SMTP",
    limit: int = 100
) -> List[Dict[str, any]]:
    """
    Ищет SMTP серверы через Shodan API.
    
    Args:
        api_key: Shodan API ключ
        query: Shodan поисковый запрос
        limit: Максимум результатов
    
    Returns:
        Список словарей с ip, port, hostnames, org, country
    """
    if not api_key:
        print("[!] Shodan API key not provided. Skipping Shodan search.")
        return []
    
    try:
        import shodan
        api = shodan.Shodan(api_key)
        results = []
        
        # Shodan отдаёт страницами по 100
        page = 1
        while len(results) < limit:
            try:
                response = api.search(query, page=page)
                for match in response.get('matches', []):
                    results.append({
                        'ip': match.get('ip_str', ''),
                        'port': match.get('port', 25),
                        'hostnames': match.get('hostnames', []),
                        'org': match.get('org', ''),
                        'country': match.get('country', ''),
                        'city': match.get('city', ''),
                        'banner': match.get('data', '')[:200],
                        'timestamp': match.get('timestamp', '')
                    })
                    if len(results) >= limit:
                        break
                
                total = response.get('total', 0)
                if page * 100 >= total or page * 100 >= limit:
                    break
                page += 1
                
            except shodan.APIError as e:
                print(f"[-] Shodan API error: {e}")
                break
        
        print(f"[+] Shodan: found {len(results)} SMTP servers")
        return results
    
    except ImportError:
        print("[!] shodan library not installed. Install with: pip install shodan")
        return []
    except Exception as e:
        print(f"[-] Shodan search error: {e}")
        return []

def search_smtp_relays_shodan(api_key: str, limit: int = 50) -> List[Dict[str, any]]:
    """
    Специализированный поиск Shodan для open relay.
    """
    queries = [
        "port:25 '220' 'ESMTP' '250-AUTH'",
        "port:25 product:Postfix smtp",
        "port:25 product:Exim smtp",
        "port:587 product:SMTP",
        "port:2525 product:SMTP"
    ]
    
    all_results = []
    for q in queries:
        results = search_smtp_servers_shodan(api_key, q, limit // len(queries))
        all_results.extend(results)
    
    return all_results

def shodan_smtp_stats(api_key: str) -> Dict[str, int]:
    """
    Получает статистику по SMTP портам через Shodan.
    """
    if not api_key:
        return {}
    
    try:
        import shodan
        api = shodan.Shodan(api_key)
        stats = {}
        
        for port in [25, 465, 587, 2525]:
            try:
                result = api.count(f"port:{port}")
                stats[str(port)] = result.get('total', 0)
            except:
                stats[str(port)] = 0
        
        print(f"[+] Shodan stats: {stats}")
        return stats
    
    except Exception as e:
        print(f"[-] Shodan stats error: {e}")
        return {}