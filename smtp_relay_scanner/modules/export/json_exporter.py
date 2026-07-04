# smtp_relay_scanner/modules/export/json_exporter.py

import json
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path


def export_json(results: List[Dict[str, Any]], output_path: Path) -> Path:
    """
    Экспортирует результаты в JSON файл.
    
    Args:
        results: Список результатов сканирования
        output_path: Путь к файлу вывода
    
    Returns:
        Path к созданному файлу
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    output = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_hosts": len(results),
        "results": results
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"[+] JSON report saved to: {output_path}")
    return output_path


def export_relays_only(results: List[Dict[str, Any]], output_path: Path) -> Path:
    """
    Экспортирует только open relay серверы в JSON.
    """
    relays = [r for r in results if r.get("relay_level") in ("OPEN", "PARTIAL", "SOURCE_ROUTE")]
    
    output = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_relays": len(relays),
        "open_relays": len([r for r in relays if r.get("relay_level") == "OPEN"]),
        "partial_relays": len([r for r in relays if r.get("relay_level") == "PARTIAL"]),
        "source_route_relays": len([r for r in relays if r.get("relay_level") == "SOURCE_ROUTE"]),
        "relays": [
            {
                "ip": r.get("ip"),
                "port": r.get("port"),
                "level": r.get("relay_level"),
                "mta": r.get("mta", "Unknown"),
                "tests_passed": [
                    t.get("test_name") for t in r.get("tests", [])
                    if t.get("success")
                ]
            }
            for r in relays
        ]
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"[+] Relays only JSON saved to: {output_path}")
    return output_path


def export_plain_relays(results: List[Dict[str, Any]], output_path: Path) -> Path:
    """
    Экспортирует IP:PORT открытых релеев в текстовый файл.
    """
    relays = [r for r in results if r.get("relay_level") in ("OPEN", "PARTIAL", "SOURCE_ROUTE")]
    
    with open(output_path, 'w') as f:
        for r in relays:
            f.write(f"{r['ip']}:{r['port']}\n")
    
    print(f"[+] Plain relay list saved to: {output_path} ({len(relays)} relays)")
    return output_path