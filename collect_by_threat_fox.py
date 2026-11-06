import argparse
import requests
import json
from datetime import datetime, timezone, timedelta
from misp_add import MispSink
import urllib3
from pathlib import Path


def main():
    
    ap = argparse.ArgumentParser(description="주간 악성코드 수집 후 misp적재 by Malware Bazaar")
    ap.add_argument("-f", "--family", type=str, required=True,help="수집할 악성코드 family")
    ap.add_argument("--outdir", type=Path,default=None, help="결과 저장 디렉토리")
    args = ap.parse_args()
    family = args.family
    if not family:
        ap.error("추적할 악성코드 패밀리를 입력하십시오.")  
    with open("config.json", "r") as f:
        config = json.load(f)
    source = "TF"
    API_KEY = config.get("API_KEY")
    misp_url = config.get("misp_url")
    misp_key = config.get("misp_key")
    outdir = Path(config.get("outdir"))
    iso = datetime.now(timezone.utc).isocalendar()
    week = f"{iso[0]}-W{iso[1]:02d}"
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    url = "https://threatfox-api.abuse.ch/api/v1/"
    result = {}
    data = []
    headers = {
        "Auth-Key": API_KEY
    }
    remcos_ioc = []
    Payload_post = {
        'query': 'get_iocs',
        'days': 1 #7
    }
    try:
        response = requests.post(url, json=Payload_post, headers=headers, timeout=120)
        result = response.json()
        data = result.get('data', [])
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")
    if result.get("query_status") != "ok":
        print("ThreatFox error:", result.get("query_status"), result.get("data"))
        data = []
    else:
        if not isinstance(data, list):      # 에러 시 data가 str인 경우 방어
            data = []
    for i in data:
        tag_malware = config.get(f"{args.family.lower()}", {}).get("tf")
        if (i.get("malware") == f"win.{tag_malware}") and (i.get("ioc_type") in ["ip:port", "domain"]):
            remcos_ioc.append(i)
    print(f"[+] matched {len(remcos_ioc)} {family} IOCs")
    with open(f"{outdir}\\{week}_{family}_ioc_TF.json", "w", encoding="utf-8") as f:
        json.dump(remcos_ioc, f, indent=2)
    sink = MispSink(misp_url, misp_key)
    malpedia_family = config.get(f"{args.family.lower()}", {}).get("malpedia")
    ev   = sink.get_tracker_event(malpedia_family,week, source)
    seen = sink.existing_values(ev)                 # 런 중 메모리 dedup
    for i in remcos_ioc:                         # 네 fetch 결과
        sink.add_c2_TF(ev, i["ioc"], malpedia_family, seen,
                    confidence=i.get("confidence_level"),
                    tf_tags=i.get("tags"), reference=i.get("reference"),
                    first_seen_epoch=sink.to_epoch(i.get("first_seen")),tf_id=i.get("id"))

if __name__ == "__main__":
    main()

