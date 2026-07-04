# smtp_relay_scanner/modules/export/html_report.py

from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path


def export_html(results: List[Dict[str, Any]], output_path: Path) -> Path:
    """
    Экспортирует результаты в HTML-отчёт с цветовой индикацией.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    open_count = sum(1 for r in results if r.get("relay_level") == "OPEN")
    partial_count = sum(1 for r in results if r.get("relay_level") == "PARTIAL")
    src_count = sum(1 for r in results if r.get("relay_level") == "SOURCE_ROUTE")
    closed_count = sum(1 for r in results if r.get("relay_level") == "CLOSED")
    
    rows_html = ""
    for r in results:
        level = r.get("relay_level", "UNKNOWN")
        level_colors = {
            "OPEN": "#ff4444",
            "PARTIAL": "#ff8800",
            "SOURCE_ROUTE": "#ffaa00",
            "CLOSED": "#44cc44"
        }
        color = level_colors.get(level, "#888888")
        
        mta = r.get("mta", "Unknown")
        ip = r.get("ip", "")
        port = r.get("port", "")
        banner = r.get("banner", "")[:80]
        starttls = "✓" if r.get("starttls") else "✗"
        auth = "✓" if r.get("auth_required") else "✗"
        
        tests = r.get("tests", [])
        tests_html = ""
        for t in tests:
            status = "OPEN" if t.get("success") else "CLOSED"
            status_color = "#ff4444" if t.get("success") else "#44cc44"
            tests_html += f'<span style="color:{status_color};font-weight:bold;">{status}</span> '
            tests_html += f'{t.get("test_name", "")}<br>'
        
        rows_html += f"""
        <tr>
            <td>{ip}:{port}</td>
            <td style="color:{color};font-weight:bold;">{level}</td>
            <td>{mta}</td>
            <td>{starttls}</td>
            <td>{auth}</td>
            <td style="font-size:12px;">{banner}</td>
            <td style="font-size:12px;">{tests_html}</td>
        </tr>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>SMTP Relay Scanner Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                background: #1a1a2e;
                color: #e0e0e0;
                padding: 20px;
            }}
            h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
            h2 {{ color: #0f3460; }}
            .stats {{
                display: flex; gap: 20px; margin: 20px 0;
            }}
            .stat-box {{
                padding: 15px 25px; border-radius: 8px; font-weight: bold; font-size: 18px;
            }}
            .stat-open {{ background: #ff4444; color: white; }}
            .stat-partial {{ background: #ff8800; color: white; }}
            .stat-src {{ background: #ffaa00; color: black; }}
            .stat-closed {{ background: #44cc44; color: white; }}
            .stat-total {{ background: #16213e; color: white; border: 1px solid #0f3460; }}
            
            table {{
                width: 100%; border-collapse: collapse; margin-top: 20px;
                background: #16213e; border-radius: 8px; overflow: hidden;
            }}
            th {{
                background: #0f3460; color: #e94560; padding: 12px 8px;
                text-align: left; font-size: 13px; text-transform: uppercase;
            }}
            td {{
                padding: 10px 8px; border-bottom: 1px solid #1a1a2e;
                font-size: 14px;
            }}
            tr:hover {{ background: #1a1a3e; }}
            .footer {{
                margin-top: 30px; font-size: 12px; color: #666;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <h1>📧 SMTP Relay Scanner Report</h1>
        <p>Generated: {now}</p>
        
        <div class="stats">
            <div class="stat-box stat-total">Total: {len(results)}</div>
            <div class="stat-box stat-open">OPEN: {open_count}</div>
            <div class="stat-box stat-partial">PARTIAL: {partial_count}</div>
            <div class="stat-box stat-src">SRC ROUTE: {src_count}</div>
            <div class="stat-box stat-closed">CLOSED: {closed_count}</div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Level</th>
                    <th>MTA</th>
                    <th>TLS</th>
                    <th>AUTH</th>
                    <th>Banner</th>
                    <th>Tests</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
        
        <div class="footer">
            SMTP Relay Scanner v1.0 — For authorized security testing only
        </div>
    </body>
    </html>
    """
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[+] HTML report saved to: {output_path}")
    return output_path