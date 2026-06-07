#!/usr/bin/env python3
"""
Network Traffic Analyzer
Detects suspicious traffic: port scans, ARP spoofing, unusual protocols
Author: [med achraf htiwech] 
"""

from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, wrpcap
from collections import defaultdict
from datetime import datetime
import argparse
import json
import os

# ── Threat detection state ──
port_scan_tracker = defaultdict(set)   # src_ip -> set of dst_ports
arp_table = {}                          # ip -> mac (for spoofing detection)
alerts = []
packet_log = []

COLORS = {
    "RED": "\033[91m", "GREEN": "\033[92m",
    "YELLOW": "\033[93m", "CYAN": "\033[96m",
    "RESET": "\033[0m", "BOLD": "\033[1m"
}

def c(color, text):
    return f"{COLORS[color]}{text}{COLORS['RESET']}"

def alert(level, msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    color = "RED" if level == "HIGH" else "YELLOW"
    entry = {"time": timestamp, "level": level, "message": msg}
    alerts.append(entry)
    print(f"[{timestamp}] {c(color, f'[{level}]')} {msg}")

def analyze_packet(pkt):
    timestamp = datetime.now().strftime("%H:%M:%S")

    # ── ARP Spoofing Detection ──
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        src_ip  = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        if src_ip in arp_table and arp_table[src_ip] != src_mac:
            alert("HIGH",
                f"ARP SPOOFING detected! IP {src_ip} changed MAC "
                f"{arp_table[src_ip]} → {src_mac}")
        arp_table[src_ip] = src_mac

    # ── Port Scan Detection ──
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        src = pkt[IP].src
        dst_port = pkt[TCP].dport
        flags = pkt[TCP].flags

        port_scan_tracker[src].add(dst_port)
        if len(port_scan_tracker[src]) > 20:
            alert("HIGH",
                f"PORT SCAN detected from {src} "
                f"({len(port_scan_tracker[src])} ports probed)")
            port_scan_tracker[src].clear()

        # SYN scan (stealth)
        if flags == 0x002:
            packet_log.append({
                "time": timestamp, "type": "SYN",
                "src": src, "dst_port": dst_port
            })

    # ── ICMP Flood Detection ──
    if pkt.haslayer(ICMP) and pkt.haslayer(IP):
        src = pkt[IP].src
        port_scan_tracker[f"icmp_{src}"].add(datetime.now().microsecond)
        if len(port_scan_tracker[f"icmp_{src}"]) > 50:
            alert("MEDIUM", f"ICMP FLOOD suspected from {src}")
            port_scan_tracker[f"icmp_{src}"].clear()

    # ── Live display ──
    if pkt.haslayer(IP):
        proto = "TCP" if pkt.haslayer(TCP) else \
                "UDP" if pkt.haslayer(UDP) else \
                "ICMP" if pkt.haslayer(ICMP) else "OTHER"
        src = pkt[IP].src
        dst = pkt[IP].dst
        print(f"  {c('CYAN', timestamp)} {c('GREEN', proto):15} {src:18} → {dst}")

def save_report():
    report = {
        "generated": datetime.now().isoformat(),
        "total_alerts": len(alerts),
        "alerts": alerts,
        "arp_table": arp_table,
        "packets_logged": len(packet_log)
    }
    with open("report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(c("GREEN", f"\n✅ Report saved to report.json ({len(alerts)} alerts)"))
    generate_html_dashboard(report)

def generate_html_dashboard(report):
    """Generate a clean white HTML dashboard from the report data"""
    import json as _json

    sev_colors = {
        "HIGH":   ("#FEE2E2", "#DC2626", "#B91C1C"),
        "MEDIUM": ("#FEF9C3", "#D97706", "#B45309"),
        "LOW":    ("#DBEAFE", "#2563EB", "#1D4ED8"),
    }

    # ── Alert rows ──
    rows = ""
    for a in reversed(report["alerts"]):
        bg, text, _ = sev_colors.get(a["level"], ("#F3F4F6","#374151","#374151"))
        rows += f"""
        <tr>
          <td>{a['time']}</td>
          <td><span class="badge" style="background:{bg};color:{text};border:1px solid {text}">{a['level']}</span></td>
          <td>{a['message']}</td>
        </tr>"""

    # ── ARP table rows ──
    arp_rows = ""
    for ip, mac in report["arp_table"].items():
        arp_rows += f"<tr><td>{ip}</td><td>{mac}</td></tr>"
    if not arp_rows:
        arp_rows = "<tr><td colspan='2' style='color:#9CA3AF;text-align:center'>No ARP entries recorded</td></tr>"

    # ── Severity counts ──
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in report["alerts"]:
        counts[a["level"]] = counts.get(a["level"], 0) + 1

    generated = report["generated"][:19].replace("T", " ")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Network Analyzer Report</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', Arial, sans-serif;
      background: #F9FAFB;
      color: #111827;
      min-height: 100vh;
    }}

    /* ── Header ── */
    .header {{
      background: #fff;
      border-bottom: 2px solid #E5E7EB;
      padding: 20px 36px;
      display: flex;
      align-items: center;
      gap: 14px;
      box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    }}
    .header-icon {{
      width: 42px; height: 42px;
      background: #EFF6FF;
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      font-size: 22px;
    }}
    .header h1 {{ font-size: 20px; color: #111827; font-weight: 700; }}
    .header .sub {{ font-size: 12px; color: #6B7280; margin-top: 2px; }}
    .status-dot {{
      width: 9px; height: 9px; border-radius: 50%;
      background: #22C55E;
      box-shadow: 0 0 6px #22C55E;
      margin-left: auto;
      animation: pulse 1.8s infinite;
    }}
    @keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:0.3}} }}

    /* ── Layout ── */
    .container {{ padding: 28px 36px; max-width: 1300px; margin: 0 auto; }}

    /* ── Stat Cards ── */
    .stats {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 28px;
    }}
    .stat-card {{
      background: #fff;
      border: 1px solid #E5E7EB;
      border-radius: 12px;
      padding: 20px 22px;
      display: flex;
      align-items: center;
      gap: 14px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
      transition: box-shadow 0.2s;
    }}
    .stat-card:hover {{ box-shadow: 0 4px 12px rgba(0,0,0,0.08); }}
    .stat-icon {{
      width: 46px; height: 46px; border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 22px; flex-shrink: 0;
    }}
    .stat-val {{ font-size: 28px; font-weight: 700; color: #111827; line-height: 1; }}
    .stat-lbl {{ font-size: 12px; color: #6B7280; margin-top: 4px; }}

    /* ── Charts row ── */
    .charts {{
      display: grid;
      grid-template-columns: 340px 1fr;
      gap: 16px;
      margin-bottom: 28px;
    }}

    /* ── Card ── */
    .card {{
      background: #fff;
      border: 1px solid #E5E7EB;
      border-radius: 12px;
      padding: 22px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }}
    .card-title {{
      font-size: 13px;
      font-weight: 600;
      color: #374151;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      padding-bottom: 14px;
      border-bottom: 1px solid #F3F4F6;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    /* ── Table ── */
    table {{ width: 100%; border-collapse: collapse; }}
    th {{
      background: #F9FAFB;
      color: #6B7280;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      padding: 10px 14px;
      text-align: left;
      border-bottom: 1px solid #E5E7EB;
    }}
    td {{
      padding: 11px 14px;
      font-size: 13px;
      color: #374151;
      border-bottom: 1px solid #F3F4F6;
      vertical-align: middle;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tbody tr:hover td {{ background: #F9FAFB; }}

    /* ── Badge ── */
    .badge {{
      padding: 3px 10px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
      display: inline-block;
      white-space: nowrap;
    }}

    /* ── Severity bars ── */
    .sev-row {{
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 14px;
    }}
    .sev-label {{ width: 70px; font-size: 12px; font-weight: 600; color: #374151; }}
    .sev-track {{
      flex: 1; height: 10px; background: #F3F4F6;
      border-radius: 6px; overflow: hidden;
    }}
    .sev-fill {{ height: 100%; border-radius: 6px; }}
    .sev-count {{ width: 28px; text-align: right; font-size: 12px; color: #6B7280; }}

    /* ── ARP table ── */
    .arp-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-bottom: 28px;
    }}

    /* ── Footer ── */
    .footer {{
      text-align: center;
      color: #9CA3AF;
      font-size: 12px;
      padding: 20px 0 8px;
      border-top: 1px solid #E5E7EB;
      margin-top: 8px;
    }}

    canvas {{ max-height: 230px; }}
  </style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="header-icon">&#128269;</div>
  <div>
    <h1>Network Traffic Analyzer — Report</h1>
    <div class="sub">Generated: {generated} &nbsp;&#183;&nbsp; Author: [Your Name]</div>
  </div>
  <div class="status-dot" title="Scan complete"></div>
</div>

<div class="container">

  <!-- Stat Cards -->
  <div class="stats">
    <div class="stat-card">
      <div class="stat-icon" style="background:#EFF6FF">&#128225;</div>
      <div>
        <div class="stat-val">{report['packets_logged']}</div>
        <div class="stat-lbl">Packets Logged</div>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-icon" style="background:#FEF2F2">&#9888;</div>
      <div>
        <div class="stat-val" style="color:#DC2626">{report['total_alerts']}</div>
        <div class="stat-lbl">Total Alerts</div>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-icon" style="background:#FEF9C3">&#128272;</div>
      <div>
        <div class="stat-val" style="color:#D97706">{counts.get('HIGH',0)}</div>
        <div class="stat-lbl">High Severity</div>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-icon" style="background:#F0FDF4">&#128737;</div>
      <div>
        <div class="stat-val" style="color:#16A34A">{len(report['arp_table'])}</div>
        <div class="stat-lbl">ARP Entries</div>
      </div>
    </div>
  </div>

  <!-- Charts -->
  <div class="charts">
    <div class="card">
      <div class="card-title">&#127378; Alert Breakdown</div>
      <canvas id="pieChart"></canvas>
    </div>
    <div class="card">
      <div class="card-title">&#128200; Severity Distribution</div>
      <div style="margin-top:8px">
        <div class="sev-row">
          <div class="sev-label">HIGH</div>
          <div class="sev-track"><div class="sev-fill" style="width:{min(counts.get('HIGH',0)*20,100)}%;background:#DC2626"></div></div>
          <div class="sev-count">{counts.get('HIGH',0)}</div>
        </div>
        <div class="sev-row">
          <div class="sev-label">MEDIUM</div>
          <div class="sev-track"><div class="sev-fill" style="width:{min(counts.get('MEDIUM',0)*20,100)}%;background:#D97706"></div></div>
          <div class="sev-count">{counts.get('MEDIUM',0)}</div>
        </div>
        <div class="sev-row">
          <div class="sev-label">LOW</div>
          <div class="sev-track"><div class="sev-fill" style="width:{min(counts.get('LOW',0)*20,100)}%;background:#2563EB"></div></div>
          <div class="sev-count">{counts.get('LOW',0)}</div>
        </div>
      </div>
      <hr style="border:none;border-top:1px solid #F3F4F6;margin:18px 0">
      <div class="card-title" style="border:none;padding:0;margin-bottom:12px">&#128205; ARP Table Snapshot</div>
      <table>
        <tr><th>IP Address</th><th>MAC Address</th></tr>
        {arp_rows}
      </table>
    </div>
  </div>

  <!-- Alert Log -->
  <div class="card">
    <div class="card-title">&#128204; Alert Log</div>
    <table>
      <thead>
        <tr><th>Time</th><th>Severity</th><th>Details</th></tr>
      </thead>
      <tbody>
        {rows if rows else '<tr><td colspan="3" style="color:#9CA3AF;text-align:center;padding:20px">No alerts recorded</td></tr>'}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Network Traffic Analyzer &nbsp;&#183;&nbsp; Python + Scapy &nbsp;&#183;&nbsp;
    For authorized security testing only
  </div>
</div>

<script>
const counts = {_json.dumps(counts)};
new Chart(document.getElementById('pieChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['HIGH', 'MEDIUM', 'LOW'],
    datasets: [{{
      data: [counts.HIGH || 0, counts.MEDIUM || 0, counts.LOW || 0],
      backgroundColor: ['#FCA5A5', '#FCD34D', '#93C5FD'],
      borderColor:     ['#DC2626', '#D97706', '#2563EB'],
      borderWidth: 2
    }}]
  }},
  options: {{
    plugins: {{
      legend: {{
        position: 'bottom',
        labels: {{ color: '#374151', font: {{ size: 12 }}, padding: 16 }}
      }}
    }},
    cutout: '62%'
  }}
}});
</script>
</body>
</html>"""

    with open("report_dashboard.html", "w") as f:
        f.write(html)
    print(c("GREEN", "✅ White dashboard saved → report_dashboard.html"))

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("-i", "--iface", default=None, help="Network interface")
    parser.add_argument("-c", "--count", type=int, default=100, help="Packets to capture")
    parser.add_argument("-o", "--output", default="capture.pcap", help="PCAP output file")
    args = parser.parse_args()

    print(c("BOLD", """
╔══════════════════════════════════════════╗
║      🔍 Network Traffic Analyzer         ║
║      Detects ARP Spoofing & Port Scans   ║
╚══════════════════════════════════════════╝
    """))
    print(c("YELLOW", f"[*] Capturing {args.count} packets on {args.iface or 'default interface'}...\n"))

    try:
        packets = sniff(iface=args.iface, count=args.count, prn=analyze_packet)
        wrpcap(args.output, packets)
        print(c("GREEN", f"\n✅ Captured {len(packets)} packets → {args.output}"))
    except PermissionError:
        print(c("RED", "[!] Run as root/sudo for packet capture"))
    finally:
        save_report()

if __name__ == "__main__":
    main()
