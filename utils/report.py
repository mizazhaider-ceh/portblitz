
from datetime import datetime
from pathlib import Path
from typing import List, Dict

def generate_report(target: str, open_ports: List[Dict], output_dir: str = "reports") -> str:
    """
    Generate a simple HTML report for PortBlitz v1.0.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    out_path = Path(output_dir) / filename
    
    # Ensure reports dir exists
    out_path.parent.mkdir(exist_ok=True)

    rows = ""
    for p in open_ports:
        # Prepare Intelligence Data
        intel_html = ""
        
        # CVEs
        if 'cves' in p and p['cves']:
            for cve in p['cves']:
                intel_html += f'<div class="tag cve">{cve}</div>'
                
        # Scripts
        if 'scripts' in p and p['scripts']:
            for s in p['scripts']:
                intel_html += f'<div class="intel-block"><span class="intel-label">⚡ {s["script"]}</span>: {s["output"]}</div>'
        
        # Bridge (Nmap/Nuclei)
        if 'nmap' in p:
             intel_html += f'<div class="intel-block"><span class="intel-label">🌉 Nmap</span>: <pre>{p["nmap"][:200]}...</pre></div>'
        if 'nuclei' in p:
             intel_html += f'<div class="intel-block"><span class="intel-label">☢️ Nuclei</span>: <pre>{p["nuclei"][:200]}...</pre></div>'

        if not intel_html:
            intel_html = '<span class="dim">-</span>'

        # Banner/Extra Info
        banner = p.get('banner', '')
        if not banner:
            # Try to construct from other fields if banner empty
            banner = p.get('service_detail', '') # Fallback

        rows += f"""
        <tr>
            <td class="font-mono">{p['port']}</td>
            <td><span class="badge open">OPEN</span></td>
            <td class="font-mono">{p.get('service', 'unknown')}</td>
            <td class="detail-cell">{banner if banner else '<span class="dim">-</span>'}</td>
            <td class="intel-cell">{intel_html}</td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PortBlitz Report - {target}</title>
        <style>
            :root {{
                --bg: #0f172a;
                --card: #1e293b;
                --text: #f8fafc;
                --accent: #38bdf8;
                --success: #22c55e;
                --danger: #ef4444;
                --warning: #eab308;
                --dim: #94a3b8;
            }}
            body {{
                font-family: 'Segoe UI', system-ui, sans-serif;
                background-color: var(--bg);
                color: var(--text);
                margin: 0;
                padding: 2rem;
                line-height: 1.5;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            .header {{
                text-align: center;
                margin-bottom: 3rem;
                padding: 2rem;
                background: var(--card);
                border-radius: 12px;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);
                border: 1px solid #334155;
            }}
            h1 {{ margin: 0; color: var(--accent); font-size: 2.5rem; letter-spacing: -0.05em; }}
            .meta {{ color: var(--dim); margin-top: 1rem; font-size: 1.1rem; }}
            
            table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 0;
                background: var(--card);
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            }}
            th, td {{
                padding: 1.25rem 1.5rem;
                text-align: left;
                border-bottom: 1px solid #334155;
                vertical-align: top;
            }}
            th {{
                background: #0f172a;
                color: var(--accent);
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                font-size: 0.9rem;
            }}
            tr:last-child td {{ border-bottom: none; }}
            tr:hover {{ background: #263346; }}
            
            .badge {{
                padding: 0.25rem 0.75rem;
                border-radius: 9999px;
                font-size: 0.75rem;
                font-weight: 700;
                letter-spacing: 0.05em;
            }}
            .open {{ background: rgba(34, 197, 94, 0.15); color: var(--success); border: 1px solid rgba(34, 197, 94, 0.3); }}
            
            .font-mono {{ font-family: 'Consolas', 'Monaco', monospace; }}
            .dim {{ color: var(--dim); font-style: italic; }}
            
            /* Intelligence Styles */
            .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 5px; margin-bottom: 5px; }}
            .cve {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.4); }}
            
            .intel-block {{ margin-bottom: 0.5rem; font-size: 0.9rem; }}
            .intel-label {{ color: var(--warning); font-weight: 600; }}
            pre {{ margin: 5px 0 0 0; background: #0f172a; padding: 8px; border-radius: 6px; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; color: #cbd5e1; border: 1px solid #334155; }}

            .footer {{
                text-align: center;
                margin-top: 4rem;
                color: var(--dim);
                font-size: 0.9rem;
                border-top: 1px solid #334155;
                padding-top: 2rem;
            }}
            .branding {{ color: var(--accent); font-weight: bold; }}
            
            /* Column Widths */
            th:nth-child(1) {{ width: 80px; }}  /* Port */
            th:nth-child(2) {{ width: 100px; }} /* Status */
            th:nth-child(3) {{ width: 150px; }} /* Service */
            th:nth-child(4) {{ width: 30%; }}   /* Banner */
            /* Remaining for Intelligence */
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>⚡ PortBlitz Report</h1>
                <div class="meta">Target: <strong style="color:white">{target}</strong> &bull; Scan Time: {timestamp}</div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Status</th>
                        <th>Service</th>
                        <th>Banner / Header</th>
                        <th>Intelligence (CVEs, Scripts, Bridge)</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>

            <div class="footer">
                Built with 💙 by <span class="branding">MIHx0</span> (Mizaz Haider) for <span class="branding">The PenTrix</span>
                <br><br>
                <small>Generated by PortBlitz v5.0</small>
            </div>
        </div>
    </body>
    </html>
    """
    
    out_path.write_text(html, encoding="utf-8")
    return str(out_path)
