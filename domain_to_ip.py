import csv
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from pymisp import PyMISP
import copy
import subprocess

DOMAIN_RE = re.compile(r'^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\.?$', re.I)

def split_c2(s):
    text = str(s).strip()

    # 1) http:// https:// 떼기
    if text.lower().startswith("http://"):
        text = text[7:]
    elif text.lower().startswith("https://"):
        text = text[8:]

    # 2) 경로(/...) 떼기
    if "/" in text:
        text = text.split("/")[0]

    # 3) 포트 떼기 (마지막 ':' 뒤가 숫자일 때만)
    host = text
    port = ""
    if ":" in text:
        left, right = text.rsplit(":", 1)
        if right.isdigit():
            host = left
            port = right

    # 4) [IPv6] 괄호 떼기
    host = host.strip("[]").lower()

    # 5) IP인지 확인
    try:
        ipaddress.ip_address(host)
        return None, host, port
    except ValueError:
        pass

    # 6) 도메인인지 확인
    if DOMAIN_RE.match(host):
        return host.rstrip("."), None, port

    return None, None, port


def collect_domains(week, outdir):
    domains = set()
    tf = json.loads((outdir / f"{week}_remcos_ioc_TF.json").read_text(encoding="utf-8"))
    for i in tf:
        domain, ip, port = split_c2(i.get("ioc"))
        if domain:
            domains.add(domain)
    mb = json.loads((outdir / f"{week}_remcos_ioc_MB.json").read_text(encoding="utf-8"))
    for s in mb:
        triage = (s.get("vendor_intel") or {}).get("Triage") or {}
        for c in triage.get("malware_config") or []:
            domain, ip, port = split_c2(c.get("c2"))
            if domain:
                domains.add(domain)
    return sorted(domains)


def resolve(domain):
    command = (
        f"try {{ Resolve-DnsName -Server 8.8.8.8 -Type A {domain} -ErrorAction Stop "
        f"| Where-Object {{ $_.Type -eq 'A' }} | Select-Object -ExpandProperty IPAddress }} "
        f"catch {{ if ($_.FullyQualifiedErrorId -like 'DNS_ERROR_RCODE_NAME_ERROR*') "
        f"{{ 'STATUS:NXDOMAIN' }} else {{ 'STATUS:ERROR' }} }}"
    )
    r = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    ips = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if line == "STATUS:NXDOMAIN":
            return [], "NXDOMAIN"
        if line == "STATUS:ERROR":
            return [], "ERROR"
        if line:
            ips.append(line)
    if ips:
        return ips, "OK"
    return [], "NO_A_RECORD" 


def main():
    with open("config.json", "r", encoding="utf-8") as f:
        config = json.load(f)
    outdir = Path(config.get("outdir", "."))
    iso = datetime.now(timezone.utc).isocalendar()
    week = f"{iso[0]}-W{iso[1]:02d}"
    domains = collect_domains(week, outdir)
    print(f"[*] resolve 대상 도메인 {len(domains)}개")
    out = outdir / f"{week}_resolve.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "resolved_ip", "status", "resolved_at_utc"])
        for d in domains:
            ips, status = resolve(d)
            w.writerow([d, ";".join(ips), status, datetime.now(timezone.utc).isoformat()])
            print(f"  {d} -> {';'.join(ips) or status}")
    print(f"[+] {out}")


if __name__ == "__main__":
    main()
