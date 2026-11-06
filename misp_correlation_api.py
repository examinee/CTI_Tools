import argparse
import csv
import ipaddress
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
import urllib3
from pymisp import PyMISP

"""
build_groups.py - 이번 주 수집 이벤트(TF, MB)를 MISP에서 읽어 연결 구조(그룹 목록)를 만든다.

동작
  1) tracker:ingest=...-<week> 태그로 이번 주 수집 이벤트를 찾는다.
  2) 값을 노드로 만든다.
       domain:<도메인>  ip:<IP>  sample:<sha256>  botnet:<값>  net:<a.b.c.0/24>
  3) 엣지를 만든다.
       - MB  : 샘플 -> C2, 샘플 -> botnet   (malware-config 의 extracted-from 참조)
       - TF  : C2 -> reference 샘플        (comment 의 tf_id / 64자리 해시로 연결)
       - IP  : IP -> /24 대역               (약한 연결)
       - resolve CSV (선택) : 도메인 -> IP
  4) 흔한 값(common_values.txt)과 warninglist 값은 노드에서 뺀다.
  5) 연결된 덩어리마다 그룹을 만들고, 그룹의 값들을 MISP 전체에서 다시 검색해
     [cluster] 이벤트 / 이전 이벤트와 일치하는지 붙인다. (이번 주 이벤트는 제외)

출력 : <week>_groups.json  (AI 입력용, 주차별 스냅샷)

사용 : python build_groups.py --week 2026-W46 [--resolve resolve.csv] [--common common_values.txt]
"""

CHUNK = 50
SHA256_RE = re.compile(r"\b([a-fA-F0-9]{64})\b")
TFID_RE = re.compile(r"tf_id=(\d+)")
DDNS_SUFFIXES = ["duckdns.org", "ddns.net", "no-ip.org", "no-ip.biz", "hopto.org",
                 "zapto.org", "sytes.net", "freedynamicdns.net", "freeddns.org",
                 "dynu.net", "myftp.biz", "serveftp.com", "kozow.com"]

# =================================================================== 기본 도구
def iso_week_now():
    iso = datetime.now(timezone.utc).isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}"


def is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def is_ddns(domain):
    for suffix in DDNS_SUFFIXES:
        if domain == suffix or domain.endswith("." + suffix):
            return True
    return False


def net24(ip):
    """IPv4면 a.b.c.0/24 문자열, 아니면 None"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def host_from_value(value):
    """MISP 속성값에서 호스트만 꺼낸다.  'a.com|2404' -> ('a.com', '2404')"""
    text = str(value).strip().lower()
    port = ""
    if "|" in text:
        text, port = text.split("|", 1)
    if text.startswith("http://") or text.startswith("https://"):
        text = text.split("://", 1)[1].split("/")[0]
        if ":" in text and text.rsplit(":", 1)[1].isdigit():
            text, port = text.rsplit(":", 1)
    return text.strip("[]"), port


def host_node(host):
    if is_ip(host):
        return "ip:" + host
    return "domain:" + host


def load_common(path):
    values = set()
    if path is None or not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            values.add(line)
    return values


def tag_names(item):
    names = []
    for t in item.get("Tag") or []:
        names.append(t.get("name", ""))
    return names


# =================================================================== 그래프
class Graph:
    def __init__(self):
        self.nodes = {}          # 노드 이름 -> 메타 정보 dict
        self.edges = []          # (노드1, 노드2, 연결 종류)
        self.neighbors = {}      # 노드 이름 -> 이웃 노드 set

    def add_node(self, name, **meta):
        if name not in self.nodes:
            self.nodes[name] = {"ports": set(), "sources": set(), "file_names": set(),
                                "loaders": set(), "tf_conf": set(), "tf_ids": set()}
            self.neighbors[name] = set()
        node = self.nodes[name]
        for key in meta:
            value = meta[key]
            if value in (None, ""):
                continue
            node[key].add(str(value))

    def add_edge(self, a, b, kind):
        if a not in self.nodes or b not in self.nodes or a == b:
            return
        if b in self.neighbors[a]:          # 이미 연결돼 있으면 건너뜀
            return
        self.edges.append((a, b, kind))
        self.neighbors[a].add(b)
        self.neighbors[b].add(a)

    def components(self):
        """연결된 덩어리 목록 (BFS)"""
        seen = set()
        result = []
        for start in self.nodes:
            if start in seen:
                continue
            group = []
            queue = [start]
            seen.add(start)
            while queue:
                current = queue.pop(0)
                group.append(current)
                for nxt in self.neighbors[current]:
                    if nxt not in seen:
                        seen.add(nxt)
                        queue.append(nxt)
            result.append(group)
        return result


# =================================================================== MISP
def find_week_events(misp, week):
    res = misp.search(controller="events", tags=[f"tracker:ingest=%{week}"])
    events = []
    for item in res or []:
        ev = item.get("Event", item)
        events.append(ev)
    return events


def search_values(misp, values, skip_ids):
    """값 -> {'cluster': {id: info}, 'prev': {id: info}}  (이번 주 이벤트 제외)"""
    hits = {}
    for v in values:
        hits[v] = {"cluster": {}, "prev": {}}

    start = 0
    while start < len(values):
        chunk = values[start:start + CHUNK]
        try:
            res = misp.search(controller="attributes", value=chunk, include_context=True)
        except Exception as e:
            print("[!] MISP 검색 실패:", e)
            start = start + CHUNK
            continue

        attrs = []
        if isinstance(res, dict):
            attrs = res.get("Attribute", [])
        elif isinstance(res, list):
            attrs = res

        for a in attrs:
            ev = a.get("Event") or {}
            eid = str(ev.get("id") or a.get("event_id") or "")
            info = str(ev.get("info") or "")
            if eid in skip_ids:
                continue
            for part in str(a.get("value", "")).lower().split("|"):
                if part in hits:
                    if info.startswith("[cluster]"):
                        hits[part]["cluster"][eid] = info
                    else:
                        hits[part]["prev"][eid] = info
        start = start + CHUNK
    return hits


def check_warninglists(misp, values):
    found = {}
    start = 0
    while start < len(values):
        chunk = values[start:start + CHUNK]
        try:
            res = misp.values_in_warninglist(chunk)
        except Exception as e:
            print("[!] warninglist 조회 실패:", e)
            res = {}
        if isinstance(res, dict):
            for v in res:
                names = []
                for w in res[v] or []:
                    if isinstance(w, dict):
                        names.append(w.get("name", ""))
                if names:
                    found[v.lower()] = names
        start = start + CHUNK
    return found


# =================================================================== 이벤트 -> 그래프
def read_tf_event(graph, ev, skipped):
    """TF 이벤트: 객체 밖 속성.  C2와 reference 샘플을 tf_id 또는 comment 해시로 연결"""
    c2_by_tfid = {}
    sample_by_tfid = {}

    for a in ev.get("Attribute") or []:
        atype = a.get("type", "")
        value = a.get("value", "")
        comment = a.get("comment", "") or ""
        m = TFID_RE.search(comment)
        tf_id = m.group(1) if m else ""

        conf = ""
        for name in tag_names(a):
            if name.startswith("threatfox:confidence="):
                conf = name.split("=", 1)[1].strip('"')

        if atype == "sha256":
            node = "sample:" + value.lower()
            graph.add_node(node, sources="TF", tf_ids=tf_id)
            if tf_id:
                sample_by_tfid[tf_id] = node
            continue

        if atype not in ("ip-dst|port", "hostname|port", "domain", "ip-dst", "url", "hostname"):
            continue

        host, port = host_from_value(value)
        if not host:
            continue
        if host in skipped:
            continue
        node = host_node(host)
        graph.add_node(node, ports=port, sources="TF", tf_conf=conf, tf_ids=tf_id)
        if tf_id:
            c2_by_tfid[tf_id] = node

        # tf_id 가 없는 예전 적재분: comment 안 reference URL 의 해시로 연결
        h = SHA256_RE.search(comment)
        if h:
            s_node = "sample:" + h.group(1).lower()
            graph.add_node(s_node, sources="TF")
            graph.add_edge(node, s_node, "tf-reference")

    for tf_id in c2_by_tfid:
        if tf_id in sample_by_tfid:
            graph.add_edge(c2_by_tfid[tf_id], sample_by_tfid[tf_id], "tf-reference")


def read_mb_event(graph, ev, common, skipped):
    """MB 이벤트: file 객체 + malware-config 객체 (extracted-from 참조)"""
    sample_by_uuid = {}
    configs = []

    for obj in ev.get("Object") or []:
        name = obj.get("name")
        if name == "file":
            sha = ""
            fname = ""
            for a in obj.get("Attribute") or []:
                if a.get("object_relation") == "sha256":
                    sha = a.get("value", "").lower()
                elif a.get("object_relation") == "filename":
                    fname = a.get("value", "")
            if sha:
                node = "sample:" + sha
                graph.add_node(node, sources="MB", file_names=fname)
                sample_by_uuid[obj.get("uuid")] = node
        elif name == "malware-config":
            configs.append(obj)

    for obj in configs:
        # 이 config 가 가리키는 샘플 찾기
        sample = None
        for ref in obj.get("ObjectReference") or []:
            target = ref.get("referenced_uuid")
            if target in sample_by_uuid:
                sample = sample_by_uuid[target]
        if sample is None:
            continue

        for a in obj.get("Attribute") or []:
            rel = a.get("object_relation")
            value = str(a.get("value", ""))

            if rel == "c2":
                host, port = host_from_value(value)
                if not host or host in skipped:
                    continue
                node = host_node(host)
                graph.add_node(node, ports=port, sources="MB")
                graph.add_edge(sample, node, "config-c2")

            elif rel == "botnet":
                if value.lower() in common:
                    graph.nodes[sample].setdefault("common_values", set()).add("botnet=" + value)
                    continue
                node = "botnet:" + value.lower()
                graph.add_node(node, sources="MB")
                graph.add_edge(sample, node, "config-botnet")

            elif rel == "loader":
                graph.nodes[sample]["loaders"].add(value)


def add_resolve(graph, path, skipped):
    """resolve CSV (domain,resolved_ip) -> 도메인과 IP 연결"""
    with path.open(encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            domain = (row.get("domain") or "").strip().lower()
            d_node = "domain:" + domain
            if d_node not in graph.nodes:
                continue
            for ip in re.split(r"[;,\s]+", row.get("resolved_ip") or ""):
                if ip and is_ip(ip) and ip not in skipped:
                    i_node = "ip:" + ip
                    graph.add_node(i_node, sources="resolve")
                    graph.add_edge(d_node, i_node, "resolve")


def add_net24(graph):
    ip_nodes = []
    for name in graph.nodes:
        if name.startswith("ip:"):
            ip_nodes.append(name)
    for name in ip_nodes:
        cidr = net24(name[3:])
        if cidr:
            n_node = "net:" + cidr
            graph.add_node(n_node)
            graph.add_edge(name, n_node, "same-24 (weak)")


# =================================================================== 그룹 출력
def build_group(graph, members, hits, idx, week):
    group = {"group_id": f"G-{week}-{idx:03d}", "domains": [], "ips": [], "samples": [],
             "botnets": [], "nets": [], "links": [], "link_kinds": [],
             "cluster_hits": [], "prev_hits": [], "excluded_common": []}
    member_set = set(members)

    for name in sorted(members):
        meta = graph.nodes[name]
        kind, value = name.split(":", 1)
        if kind == "domain":
            group["domains"].append({"value": value, "ddns": is_ddns(value),
                                     "ports": sorted(meta["ports"]),
                                     "sources": sorted(meta["sources"]),
                                     "tf_conf": sorted(meta["tf_conf"]),
                                     "tf_ids": sorted(meta["tf_ids"])})
        elif kind == "ip":
            group["ips"].append({"value": value, "ports": sorted(meta["ports"]),
                                 "sources": sorted(meta["sources"]),
                                 "tf_conf": sorted(meta["tf_conf"]),
                                 "tf_ids": sorted(meta["tf_ids"])})
        elif kind == "sample":
            group["samples"].append({"sha256": value, "sources": sorted(meta["sources"]),
                                     "file_names": sorted(meta["file_names"]),
                                     "loaders": sorted(meta["loaders"])})
            for c in sorted(meta.get("common_values", set())):
                group["excluded_common"].append(f"{value[:12]}:{c}")
        elif kind == "botnet":
            group["botnets"].append(value)
        elif kind == "net":
            group["nets"].append(value)

        # 다른 이벤트와의 일치 (net 노드는 검색하지 않음)
        if kind != "net" and value in hits:
            for eid in sorted(hits[value]["cluster"]):
                group["cluster_hits"].append(f"{eid}:{hits[value]['cluster'][eid]} ({kind}={value})")
            for eid in sorted(hits[value]["prev"]):
                group["prev_hits"].append(f"{eid}:{hits[value]['prev'][eid]} ({kind}={value})")

    kinds = set()
    for a, b, kind in graph.edges:
        if a in member_set and b in member_set:
            group["links"].append(f"{a} -> {b} [{kind}]")
            kinds.add(kind)
    group["link_kinds"] = sorted(kinds)

    # 약한 연결(/24)만으로 묶였는지 표시
    strong = False
    for k in kinds:
        if "weak" not in k:
            strong = True
    group["strong_link"] = strong
    return group


# =================================================================== 메인
def main():
    iso = datetime.now(timezone.utc).isocalendar()
    week = f"{iso[0]}-W{iso[1]:02d}"
    logging.getLogger("pymisp").setLevel(logging.ERROR)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    ap = argparse.ArgumentParser(description="이번 주 수집 이벤트로 그룹 목록 만들기")
    ap.add_argument("--week", default=week, help="주차 (기본: 이번 주, YYYY-Www)")
    ap.add_argument("--resolve", type=Path, default=None,help="resolve CSV (기본: <outdir>/<week>_resolve.csv 자동 참조)")
    ap.add_argument("--common", type=Path, default=Path("common_values.txt"))
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--outdir", type=Path,default=None, help="결과 저장 디렉토리")
    args = ap.parse_args()
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    misp = PyMISP(cfg["misp_url"], cfg["misp_key"], ssl=cfg.get("misp_verify", False))
    common = load_common(args.common)
    if args.outdir is None:
        args.outdir = Path(cfg.get("outdir", "."))
    # 1) 이번 주 수집 이벤트
    events = find_week_events(misp, args.week)
    if not events:
        sys.exit(f"[x] {args.week} 수집 이벤트가 없습니다. (태그 tracker:ingest=...-{args.week})")
    week_ids = set()
    for ev in events:
        week_ids.add(str(ev.get("id")))
        print(f"[*] 이벤트 {ev.get('id')}: {ev.get('info')}")

    # 2) warninglist 대상 호스트 미리 확인
    hosts = set()
    for ev in events:
        for a in ev.get("Attribute") or []:
            hosts.add(host_from_value(a.get("value", ""))[0])
        for obj in ev.get("Object") or []:
            for a in obj.get("Attribute") or []:
                if a.get("object_relation") == "c2":
                    hosts.add(host_from_value(a.get("value", ""))[0])
    host_list = []
    for h in hosts:
        if h and (is_ip(h) or "." in h) and not SHA256_RE.fullmatch(h):
            host_list.append(h)
    warn = check_warninglists(misp, sorted(host_list))
    skipped = set(warn.keys())

    # 3) 그래프 만들기
    graph = Graph()
    for ev in events:
        info = str(ev.get("info", ""))
        has_objects = bool(ev.get("Object"))
        if has_objects:
            read_mb_event(graph, ev, common, skipped)
        if ev.get("Attribute"):
            read_tf_event(graph, ev, skipped)
        if not has_objects and not ev.get("Attribute"):
            print(f"[!] 빈 이벤트: {info}")
    resolve_path = args.resolve
    if resolve_path is None:
        resolve_path = args.outdir / f"{args.week}_resolve.csv"
    if resolve_path.exists():
        add_resolve(graph, resolve_path, skipped)
        print(f"[*] resolve 결과 반영: {resolve_path}")
    else:
        print(f"[*] resolve 파일 없음, 건너뜀: {resolve_path}")
    add_net24(graph)

    # 4) 다른 이벤트와 일치 검색
    values = []
    for name in graph.nodes:
        kind, value = name.split(":", 1)
        if kind != "net":
            values.append(value)
    hits = search_values(misp, sorted(values), week_ids)

    # 5) 그룹 만들기 (net 노드만 있는 덩어리는 버림)
    groups = []
    idx = 1
    for members in graph.components():
        real = []
        for m in members:
            if not m.startswith("net:"):
                real.append(m)
        if not real:
            continue
        groups.append(build_group(graph, members, hits, idx, args.week))
        idx = idx + 1

    # 정렬: 클러스터 일치 > 이전 일치 > 강한 연결 > 크기
    def sort_key(g):
        size = len(g["domains"]) + len(g["ips"]) + len(g["samples"])
        return (not g["cluster_hits"], not g["prev_hits"], not g["strong_link"], -size)
    groups.sort(key=sort_key)

    # 6) 저장
    stats = {"events": sorted(week_ids), "nodes": len(graph.nodes), "edges": len(graph.edges),
             "groups": len(groups),
             "multi_member_groups": len([g for g in groups
                                         if len(g["domains"]) + len(g["ips"]) + len(g["samples"]) > 1]),
             "cluster_hit_groups": len([g for g in groups if g["cluster_hits"]]),
             "prev_hit_groups": len([g for g in groups if g["prev_hits"]]),
             "warninglist_skipped": warn}
    out = args.outdir / f"{args.week}_groups.json"
    out.write_text(json.dumps({
        "meta": {"week": args.week, "run_at_utc": datetime.now(timezone.utc).isoformat(),
                 "common_values": sorted(common), "stats": stats},
        "groups": groups,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[+] 노드 {stats['nodes']} / 엣지 {stats['edges']} / 그룹 {stats['groups']} "
          f"(2개 이상 묶인 그룹 {stats['multi_member_groups']}, "
          f"클러스터 일치 {stats['cluster_hit_groups']}, 이전 일치 {stats['prev_hit_groups']})")
    print(f"[+] {out}")


if __name__ == "__main__":
    main()