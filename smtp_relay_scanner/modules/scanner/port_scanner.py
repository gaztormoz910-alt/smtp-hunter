# smtp_relay_scanner/modules/scanner/port_scanner.py

import asyncio
import socket
from typing import List, Tuple, Set
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_network, IPv4Network

from smtp_relay_scanner.config import (
    DEFAULT_PORTS, TIMEOUT_CONNECT, TIMEOUT_READ,
    DEFAULT_THREADS, MAX_THREADS
)

def tcp_connect(ip: str, port: int, timeout: int = TIMEOUT_CONNECT) -> bool:
    """TCP connect scan для одного IP:port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_ip_ports(ip: str, ports: List[int] = None) -> List[int]:
    """Сканирует один IP на список портов. Возвращает открытые порты."""
    if ports is None:
        ports = DEFAULT_PORTS
    
    open_ports = []
    for port in ports:
        if tcp_connect(ip, port):
            open_ports.append(port)
    return open_ports

def expand_cidr(cidr: str) -> List[str]:
    """Раскрывает CIDR в список IP адресов. Для /24+ возвращает CIDR."""
    try:
        net = ip_network(cidr, strict=False)
        if net.prefixlen >= 24:
            return [cidr]  # слишком большой диапазон
        return [str(ip) for ip in net.hosts()]
    except:
        return []

def expand_cidr_to_ips(cidr: str) -> List[str]:
    """Раскрывает CIDR в IP имена. Для /24 только первые 256."""
    try:
        net = ip_network(cidr, strict=False)
        return [str(ip) for ip in net.hosts()]
    except:
        return []

def mass_scan(cidr_list: List[str], ports: List[int] = None, 
              max_workers: int = None) -> List[Tuple[str, int]]:
    """
    Массовое сканирование CIDR диапазонов на SMTP порты.
    
    Returns:
        List of (ip, port) tuples для живых серверов
    """
    if ports is None:
        ports = DEFAULT_PORTS
    if max_workers is None:
        max_workers = min(DEFAULT_THREADS, MAX_THREADS)
    
    # Собираем все IP
    all_ips = []
    for cidr in cidr_list:
        ips = expand_cidr_to_ips(cidr)
        all_ips.extend(ips)
    
    print(f"[*] Scanning {len(all_ips)} IPs on ports {ports}...")
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(scan_ip_ports, ip, ports): ip
            for ip in all_ips
        }
        
        from concurrent.futures import as_completed
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                open_ports = future.result()
                for port in open_ports:
                    results.append((ip, port))
            except:
                pass
    
    print(f"[+] Found {len(results)} open SMTP ports")
    return results

def scan_single_ip(ip: str, ports: List[int] = None) -> List[int]:
    """Сканирует один IP."""
    return scan_ip_ports(ip, ports)

# === Асинхронная версия (более быстрая) ===

async def async_tcp_connect(ip: str, port: int, timeout: int = TIMEOUT_CONNECT) -> bool:
    """Асинхронный TCP connect."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

async def async_scan_ip(ip: str, ports: List[int], semaphore: asyncio.Semaphore) -> List[int]:
    """Асинхронный скан одного IP на несколько портов."""
    open_ports = []
    async with semaphore:
        for port in ports:
            if await async_tcp_connect(ip, port):
                open_ports.append(port)
    return open_ports

async def async_mass_scan(ip_list: List[str], ports: List[int] = None,
                           concurrency: int = 500) -> List[Tuple[str, int]]:
    """Асинхронный масс-скан."""
    if ports is None:
        ports = DEFAULT_PORTS
    
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [async_scan_ip(ip, ports, semaphore) for ip in ip_list]
    
    results = []
    for ip, task in zip(ip_list, asyncio.as_completed(tasks)):
        open_ports = await task
        for port in open_ports:
            results.append((ip, port))
    
    return results