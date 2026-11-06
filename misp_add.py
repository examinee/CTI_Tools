# misp_sink.py  —  ThreatFox 시드 + config enrichment을 MISP에 밀어넣는 처리부
# pip install pymisp
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPSighting, MISPObject
from datetime import datetime, timezone, timedelta
import ipaddress
import json
import re

class MispSink:
    def __init__(self, url, key, verifycert=False):
        self.misp = PyMISP(url, key, ssl=verifycert)

    # 패밀리별 고정 이벤트 (고유 태그로 get-or-create)
    def get_tracker_event(self, family, week, source):
        marker = f'tracker:ingest={source}-{family.lower()}-{week}'
        hits = self.misp.search(controller="events", tags=[marker], limit=1, pythonify=True)
        if hits:
            return self.misp.get_event(hits[0].id, pythonify=True)  # 속성까지 받아 dedup
        ev = MISPEvent()
        ev.info = f"[ingest] {source} — {family} - {week}"
        ev.distribution = 0        # this org only
        ev.analysis = 1            # ongoing
        ev.add_tag(marker)
        ev.add_tag(f'misp-galaxy:malpedia="{family}"')   # ※ 정확한 클러스터명 확인
        return self.misp.add_event(ev, pythonify=True)
    
    @staticmethod
    def existing_values(event):
        return {a.value for a in (event.attributes or [])}

    @staticmethod
    def to_epoch(ts: str):
            if not ts:
                return None
            ts = ts.replace(" UTC", "").strip()
            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
    # ThreatFox C2 시드 1건
    def add_c2_TF(self, event, ioc, family, seen, confidence=None,
                  tf_tags=None, reference=None, first_seen_epoch=None, tf_id=None):
        atype, value = self._parse_ioc(ioc)
        if value in seen:
            return
        m = re.search(r"[a-fA-F0-9]{64}", str(reference or ""))
        if m and m.group(0).lower() not in seen:
            h = MISPAttribute()
            h.type, h.value, h.to_ids = "sha256", m.group(0).lower(), False
            h.comment = f"tf_id={tf_id}; reference sample of {value}"
            self.misp.add_attribute(event.id, h)
            seen.add(m.group(0).lower())
        a = MISPAttribute()
        a.type, a.value, a.to_ids = atype, value, True
        if first_seen_epoch:
            a.first_seen = datetime.fromtimestamp(first_seen_epoch, timezone.utc)
        a.comment = f"tf_id={tf_id}; conf={confidence}; ref={reference}"
        if confidence is not None:
            a.add_tag(f'threatfox:confidence="{confidence}"')
        for t in (tf_tags or []):
            a.add_tag(f'threatfox:tag="{t}"')
        self.misp.add_attribute(event.id, a)
        seen.add(value)
    

    # config enrichment (네 extractor dict) — 공유 태그로 같은 샘플 묶음
     # ---------- 공통 파서 (domain:port 대응) ----------
    @staticmethod
    def _parse_ioc(ioc):
        ioc = str(ioc).strip()
        if ioc.startswith(("http://", "https://")):
            return "url", ioc
        host, sep, port = ioc.rpartition(":")
        if sep and port.isdigit() and host:
            host = host.strip("[]")                      # [IPv6]:port 대응
            try:
                ipaddress.ip_address(host)
                return "ip-dst|port", f"{host}|{port}"
            except ValueError:
                return "hostname|port", f"{host}|{port}"
        try:
            ipaddress.ip_address(ioc)
            return "ip-dst", ioc
        except ValueError:
            return "domain", ioc

    # ---------- MB vendor_intel.Triage -> config dict ----------
    @staticmethod
    def parse_triage_vi(sample):
        """MB get_info 항목 하나에서 Triage config를 extractor와 같은 dict 형태로 반환."""
        t = (sample.get("vendor_intel") or {}).get("Triage") or {}
        tags = t.get("tags") or []
        c2 = [m["c2"] for m in (t.get("malware_config") or []) if m.get("c2")]
        botnet = [x.split(":", 1)[1] for x in tags if x.startswith("botnet:")]
        families = [x.split(":", 1)[1] for x in tags if x.startswith("family:")]
        return {
            "c2": c2,
            "botnet": botnet,
            "loader": [f for f in families if f.lower() != "remcos"],
            "triage_link": t.get("link"),
        }

    # ---------- 이벤트 안 기존 샘플 목록 (샘플 단위 dedup) ----------
    @staticmethod
    def existing_samples(event):
        out = set()
        for o in (event.objects or []):
            if o.name == "file":
                for a in o.attributes:
                    if a.object_relation == "sha256":
                        out.add(a.value.lower())
        return out

    # ---------- 샘플 1개 = file 객체 + malware-config 객체 ----------
    def add_config_MB(self, event, sha256, config, family, seen_samples,
                      file_meta=None, source="mb-triage-vi"):
        """
        sha256      : 샘플 해시
        config      : parse_triage_vi() 결과 또는 extractor dict (값은 단일/리스트 모두 허용)
        seen_samples: existing_samples(event) 결과 (런 중 갱신)
        file_meta   : MB get_info 항목 (file_name, file_type_mime, first_seen 등)
        source      : config 출처 (mb-triage-vi / own-extractor / manual-triage)
        """
        sha256 = sha256.lower()
        if sha256 in seen_samples:
            return None                                  # 같은 샘플만 건너뜀 (값 단위 dedup 아님)
        file_meta = file_meta or {}
        config = config or {}

        # 1) file 객체
        fobj = MISPObject("file")
        fobj.add_attribute("sha256", value=sha256, to_ids=False)
        if file_meta.get("file_name"):
            fobj.add_attribute("filename", value=file_meta["file_name"], to_ids=False)
        if file_meta.get("file_type_mime"):
            fobj.add_attribute("mimetype", value=file_meta["file_type_mime"], to_ids=False,
                               disable_correlation=True)
        fs = file_meta.get("first_seen")
        if fs:
            fobj.first_seen = datetime.strptime(fs, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        fobj.comment = f"MalwareBazaar | {family} | type={file_meta.get('file_type', '')}"

        # 2) malware-config 객체 (샘플별로 값 전부 기록 -> 샘플 간 공유값이 남는다)
        cobj = MISPObject("malware-config")
        has_value = False

        def _vals(v):
            if v in (None, "", []):
                return []
            return v if isinstance(v, list) else [v]

        for v in _vals(config.get("c2")):
            atype, val = self._parse_ioc(v)
            cobj.add_attribute("c2", type=atype, value=val, to_ids=True)
            has_value = True
        for key, mtype in (("botnet", "text"), ("group", "text"), ("mutex", "mutex"),
                           ("version", "text"), ("rc4_key", "text"), ("key", "text"),
                           ("loader", "text")):
            for v in _vals(config.get(key)):
                cobj.add_attribute(key, type=mtype, value=str(v), to_ids=False,
                                   disable_correlation=False)
                has_value = True

        if has_value:
            raw = {k: v for k, v in config.items() if v not in (None, "", [])}
            cobj.add_attribute("config", type="text",value=json.dumps(raw, ensure_ascii=False),disable_correlation=True)
            cobj.add_attribute("format", type="text", value="JSON",disable_correlation=True)
            cobj.comment = f"source={source}" + (f"; {config['triage_link']}" if config.get("triage_link") else "")
            cobj.add_reference(fobj.uuid, "extracted-from")

        # 3) 적재
        r = self.misp.add_object(event.id, fobj, pythonify=True)
        if isinstance(r, dict) and r.get("errors"):
            print(f"[!] file 객체 실패 {sha256[:12]}: {r['errors']}")
            return None
        if has_value:
            r2 = self.misp.add_object(event.id, cobj, pythonify=True)
            if isinstance(r2, dict) and r2.get("errors"):
                print(f"[!] config 객체 실패 {sha256[:12]}: {r2['errors']}")
            else:
                for ref in cobj.ObjectReference:
                    rr = self.misp.add_object_reference(ref)
                    if isinstance(rr, dict) and rr.get("errors"):
                        print(f"[!] reference 실패 {sha256[:12]}: {rr['errors']}")
        seen_samples.add(sha256)
        return fobj