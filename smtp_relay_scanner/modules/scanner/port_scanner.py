# smtp_relay_scanner/modules/scanner/port_scanner.py
# Async TCP connect scanner — ~100+ hosts/sec on Windows

import asyncio
import socket
import logging
from typing import List, Tuple, Set, Optional
from ipaddress import ip_network, IPv4Network

from smtp_relay_scanner.config import (
    DEFAULT_PORTS, TIMEOUT_CONNECT, TIMEOUT_READ,
    DEFAULT_THREADS, MAX_THREADS
)

log = logging.getLogger(__name__)


async def async_tcp_connect(
    ip: str,
    port: int,
    timeout: int = TIMEOUT_CONNECT
) -> bool:
    """
    Асинхронный TCP connect к одному порту.
    Использует asyncio.open_connection с таймаутом.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError,
            OSError, socket.gaierror):
        return False
    except Exception as e:
        log.debug(f"async_tcp_connect error {ip}:{port} — {e}")
        return False


async def async_scan_ip_ports(
    ip: str,
    ports: List[int],
    semaphore: asyncio.Semaphore,
    timeout: int = TIMEOUT_CONNECT
) -> List[int]:
    """
    Асинхронно сканирует один IP на список портов.
    Все порты проверяются параллельно внутри одного IP.
    """
    async with semaphore:
        tasks = [async_tcp_connect(ip, p, timeout) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        for port, is_open in zip(ports, results):
            if is_open is True:
                open_ports.append(port)
        return open_ports


async def async_mass_scan(
    ip_list: List[str],
    ports: Optional[List[int]] = None,
    concurrency: int = 200,
    timeout: int = TIMEOUT_CONNECT
) -> List[Tuple[str, int]]:
    """
    Массовое асинхронное сканирование списка IP на SMTP порты.
    
    Args:
        ip_list: Список IP адресов для сканирования
        ports: Список портов (по умолчанию DEFAULT_PORTS)
        concurrency: Максимум одновременных соединений
        timeout: Таймаут на одно соединение
    
    Returns:
        List of (ip, port) для открытых портов
    """
    if ports is None:
        ports = DEFAULT_PORTS

    log.info(f"Async mass scan: {len(ip_list)} IPs, ports={ports}, concurrency={concurrency}")

    semaphore = asyncio.Semaphore(concurrency)

    # Создаём задачи для каждого IP
    tasks = [async_scan_ip_ports(ip, ports, semaphore, timeout) for ip in ip_list]

    results = []
    # Используем as_completed для прогрессивного вывода
    for ip, coro in zip(ip_list, asyncio.as_completed(tasks)):
        try:
            open_ports = await coro
            for port in open_ports:
                results.append((ip, port))
        except Exception as e:
            log.debug(f"Scan error for {ip}: {e}")

    log.info(f"Async scan complete: found {len(results)} open ports")
    return results


def run_async_scan(
    ip_list: List[str],
    ports: Optional[List[int]] = None,
    concurrency: int = 200,
    timeout: int = TIMEOUT_CONNECT
) -> List[Tuple[str, int]]:
    """
    Синхронная обёртка для async_mass_scan.
    Запускает asyncio event loop и возвращает результаты.
    """
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(
            async_mass_scan(ip_list, ports, concurrency, timeout)
        )
        loop.close()
        return results
    except Exception as e:
        log.error(f"Async scan runner error: {e}")
        return []


# === Fallback: синхронный TCP connect (на случай если asyncio не работает) ===

def tcp_connect_sync(ip: str, port: int, timeout: int = TIMEOUT_CONNECT) -> bool:
    """Синхронный TCP connect — fallback."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def scan_ip_ports_sync(ip: str, ports: Optional[List[int]] = None) -> List[int]:
    """Синхронный скан одного IP — fallback."""
    if ports is None:
        ports = DEFAULT_PORTS
    open_ports = []
    for port in ports:
        if tcp_connect_sync(ip, port):
            open_ports.append(port)
    return open_ports


# === Вспомогательные функции для CIDR ===

def expand_cidr(cidr: str) -> List[str]:
    """Раскрывает CIDR в список IP адресов. Для /24+ возвращает CIDR."""
    try:
        net = ip_network(cidr, strict=False)
        if net.prefixlen >= 24:
            return [cidr]
        return [str(ip) for ip in net.hosts()]
    except:
        return []


def expand_cidr_to_ips(cidr: str) -> List[str]:
    """Раскрывает CIDR в IP имена."""
    try:
        net = ip_network(cidr, strict=False)
        return [str(ip) for ip in net.hosts()]
    except:
        return []


# === Универсальная точка входа ===

def scan_hosts(
    ip_list: List[str],
    ports: Optional[List[int]] = None,
    use_async: bool = True,
    concurrency: int = 200,
    timeout: int = TIMEOUT_CONNECT
) -> List[Tuple[str, int]]:
    """
    Универсальная функция сканирования.
    Автоматически выбирает async или sync.
    
    Returns:
        List of (ip, port)
    """
    if not ip_list:
        return []

    if use_async:
        try:
            return run_async_scan(ip_list, ports, concurrency, timeout)
        except Exception as e:
            log.warning(f"Async scan failed, falling back to sync: {e}")

    # Sync fallback
    from concurrent.futures import ThreadPoolExecutor, as_completed
    results = []
    with ThreadPoolExecutor(max_workers=min(concurrency, 100)) as executor:
        future_to_ip = {
            executor.submit(scan_ip_ports_sync, ip, ports): ip
            for ip in ip_list
        }
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                open_ports = future.result()
                for port in open_ports:
                    results.append((ip, port))
            except:
                pass
    return results