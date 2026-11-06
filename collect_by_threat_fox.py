import requests
import json
from datetime import datetime, timezone, timedelta
from misp_add import MispSink
import urllib3
from pathlib import Path


def main():
    with open("config.json", "r") as f:
        config = json.load(f)
    API_KEY = config.get("API_KEY")
    misp_url = config.get("misp_url")
    misp_key = config.get("misp_key")
    outdir = Path(config.get("outdir"))
    iso = datetime.now(timezone.utc).isocalendar()
    week = f"{iso[0]}-W{iso[1]:02d}"
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    url = "https://threatfox-api.abuse.ch/api/v1/"
    source = "TF"
    result = {}
    data = []
    headers = {
        "Auth-Key": API_KEY
    }
    remcos_ioc = []
    Payload_post = {
        'query': 'get_iocs',
        'days': 7
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
        if (i.get("malware") == "win.remcos") and (i.get("ioc_type") in ["ip:port", "domain"]):
            remcos_ioc.append(i)
    print(f"[+] matched {len(remcos_ioc)} Remcos IOCs")
    with open(f"{outdir}\\{week}_remcos_ioc_TF.json", "w", encoding="utf-8") as f:
        json.dump(remcos_ioc, f, indent=2)
    sink = MispSink(misp_url, misp_key)
    ev   = sink.get_tracker_event("Remcos",week, source)
    seen = sink.existing_values(ev)                 # 런 중 메모리 dedup
    for i in remcos_ioc:                         # 네 fetch 결과
        sink.add_c2_TF(ev, i["ioc"], "Remcos", seen,
                    confidence=i.get("confidence_level"),
                    tf_tags=i.get("tags"), reference=i.get("reference"),
                    first_seen_epoch=sink.to_epoch(i.get("first_seen")),tf_id=i.get("id"))

if __name__ == "__main__":
    main()

