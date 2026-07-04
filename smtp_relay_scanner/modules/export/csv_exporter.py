# smtp_relay_scanner/modules/export/csv_exporter.py

import csv
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path


def export_csv(results: List[Dict[str, Any]], output_path: Path) -> Path:
    """
    Экспортирует результаты в CSV файл.
    
    Формат: IP, Port, MTA, Level, STARTTLS, AUTH, TestsPassed, TotalTests, Timestamp
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    fieldnames = [
        "ip", "port", "mta", "relay_level", "banner",
        "starttls", "auth_required", "auth_methods",
        "tests_passed", "total_tests", "timestamp"
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for r in results:
            tests = r.get("tests", [])
            passed = sum(1 for t in tests if t.get("success"))
            
            writer.writerow({
                "ip": r.get("ip", ""),
                "port": r.get("port", ""),
                "mta": r.get("mta", "Unknown"),
                "relay_level": r.get("relay_level", "UNKNOWN"),
                "banner": r.get("banner", "")[:100],
                "starttls": r.get("starttls", False),
                "auth_required": r.get("auth_required", False),
                "auth_methods": ", ".join(r.get("auth_methods", [])),
                "tests_passed": passed,
                "total_tests": len(tests),
                "timestamp": r.get("timestamp", "")
            })
    
    print(f"[+] CSV report saved to: {output_path}")
    return output_path


def export_relays_csv(results: List[Dict[str, Any]], output_path: Path) -> Path:
    """
    Экспортирует только relay серверы в CSV с детальной информацией.
    """
    relays = [r for r in results if r.get("relay_level") != "CLOSED"]
    
    fieldnames = [
        "ip", "port", "relay_level", "mta",
        "ext_ext", "int_ext", "null_ext",
        "source_percent", "source_at", "auth_bypass"
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for r in relays:
            test_map = {}
            for t in r.get("tests", []):
                test_map[t.get("test_id", "")] = "OPEN" if t.get("success") else "CLOSED"
            
            writer.writerow({
                "ip": r.get("ip", ""),
                "port": r.get("port", ""),
                "relay_level": r.get("relay_level", ""),
                "mta": r.get("mta", "Unknown"),
                "ext_ext": test_map.get("ext_ext", "N/A"),
                "int_ext": test_map.get("int_ext", "N/A"),
                "null_ext": test_map.get("null_ext", "N/A"),
                "source_percent": test_map.get("source_percent", "N/A"),
                "source_at": test_map.get("source_at", "N/A"),
                "auth_bypass": test_map.get("auth_bypass", "N/A")
            })
    
    print(f"[+] Relay details CSV saved to: {output_path}")
    return output_path