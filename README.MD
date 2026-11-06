# Remcos C2 Tracker

Remcos RAT의 C2 인프라를 공개 위협 피드와 MISP를 활용해 주간 단위로 수집·enrichment·상관분석하는 자동화 파이프라인.

## 개요

```
ThreatFox ──┐                          ┌── groups.json
             ├── MISP ── DNS resolve ──┤
MalwareBazaar┘                          └── AI 피벗 프롬프트
```

1. **수집** — ThreatFox·MalwareBazaar API에서 Remcos IoC(C2 주소, 샘플 해시, config)를 가져와 JSON으로 저장하고, 소스·주차별 태그를 달아 MISP 이벤트에 적재.
2. **DNS Resolve** — 수집된 C2 도메인을 IP로 resolve.
3. **상관분석** — 해당 주의 MISP 이벤트를 읽어 그래프(샘플 ↔ C2 ↔ botnet ↔ /24 서브넷)를 만들고, warninglist·흔한 값을 필터링한 뒤 연결된 노드를 그룹으로 묶음. 기존 MISP 이벤트와 교차 검색해 클러스터 일치·재등장 여부를 확인.
4. **피벗 대상 선별 (선택)** — LLM 프롬프트(`claude.md`)로 그룹을 점수화·정렬해 심층 조사 대상을 선정.

## 파이프라인

```
collect_by_threat_fox.py    →  MISP [ingest] TF 이벤트
collect_by_malware_bazzar.py →  MISP [ingest] MB 이벤트
domain_to_ip.py             →  <week>_resolve.csv
misp_correlation_api.py     →  <week>_groups.json
claude.md                   →  (groups.json을 LLM에 입력해 피벗 대상 선별)
```


### 선택 파일

- `common_values.txt` — 한 줄에 하나씩. 상관분석에서 제외할 범용적인 botnet 이름(예: `remotehost`, `host`, `office`).

## 사용법

순서대로 실행:

```bash
# 1. ThreatFox에서 수집 (최근 7일)
python collect_by_threat_fox.py

# 2. MalwareBazaar에서 수집 (최근 7일)
python collect_by_malware_bazzar.py

# 3. 수집한 C2 도메인 DNS resolve
python domain_to_ip.py

# 4. 상관분석 그룹 생성
python misp_correlation_api.py --week 2026-W45
```

## 출력

### `<week>_groups.json`

각 그룹에 포함되는 필드:

| 필드 | 설명 |
|---|---|
| `domains` / `ips` | C2 지표. 포트, 소스(TF/MB), ThreatFox confidence 포함 |
| `samples` | SHA256 해시, 파일명, 로더 정보 |
| `botnets` | 멀웨어 config에서 추출한 botnet 식별자 |
| `links` | 노드 간 연결 근거 (config-c2, config-botnet, tf-reference, resolve, same-24) |
| `strong_link` | `false`면 /24 서브넷 근접성만으로 묶인 그룹 |
| `cluster_hits` | 기존 MISP `[cluster]` 이벤트와 일치한 값 |
| `prev_hits` | 이전 주 수집 이벤트와 일치한 값 |


## 참고

- DNS resolve는 현재 PowerShell(`Resolve-DnsName`)을 사용합니다. Windows 환경 전용.
- 파이프라인은 현재 Remcos 전용입니다. 다른 패밀리로의 확장을 계획 중.
- `claude.md`는 Claude용으로 작성되었지만, 구조화된 JSON을 입력받는 모든 LLM에서 사용 가능합니다.

## Disclaimer

이 프로젝트는 **인가된 위협 인텔리전스 연구 목적**으로만 사용해야 합니다. 공개 API(abuse.ch)와 본인의 MISP 인스턴스와만 상호작용합니다. 수집된 지표를 소유하지 않거나 테스트 권한이 없는 시스템에 사용하지 마세요.