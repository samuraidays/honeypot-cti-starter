#!/usr/bin/env python3
"""
Step 1: IP エンリッチ

入力: Cowrie JSON ログ (JSONL) または IP アドレステキストリスト (1行1IP)
出力: enriched.json (Step 2 への中間ファイル)

APIキー未設定時: sample_data/sample_cache.json をフォールバックとして使用
APIキー設定済み: AbuseIPDB v2 API を照会（ファイルキャッシュ付き、TTL 24h）
"""
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: requests がインストールされていません。pip install -r requirements.txt を実行してください。")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ------------------------------------------------------------------ 設定
API_KEY       = os.getenv("ABUSEIPDB_API_KEY", "")
CACHE_FILE    = Path("cache/abuseipdb_cache.json")
SAMPLE_CACHE  = Path("sample_data/sample_cache.json")
OUTPUT_FILE   = Path("enriched.json")
CACHE_TTL_H   = 24
RATE_WAIT_S   = 60
MAX_RETRY     = 3


# ------------------------------------------------------------------ キャッシュ
def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}

def load_cache() -> dict:
    return _load_json(CACHE_FILE)

def save_cache(cache: dict) -> None:
    CACHE_FILE.parent.mkdir(exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False, indent=2))

def is_fresh(entry: dict) -> bool:
    ts = entry.get("_cached_at")
    if not ts:
        return False
    return datetime.fromisoformat(ts) > datetime.now() - timedelta(hours=CACHE_TTL_H)


# ------------------------------------------------------------------ API 照会
def _call_api(ip: str) -> dict | None:
    for attempt in range(1, MAX_RETRY + 1):
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=8,
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                return {
                    "abuse_score":   d.get("abuseConfidenceScore", 0),
                    "abuse_isp":     d.get("isp", ""),
                    "abuse_country": d.get("countryCode", ""),
                    "abuse_reports": d.get("totalReports", 0),
                }
            if resp.status_code == 429:
                print(f"  ⚠️  レートリミット。{RATE_WAIT_S}秒待機中... (試行 {attempt}/{MAX_RETRY})")
                time.sleep(RATE_WAIT_S)
            else:
                print(f"  ⚠️  API エラー {resp.status_code} ({ip})")
                return None
        except Exception as e:
            print(f"  ⚠️  接続エラー ({ip}): {e}")
            return None
    return None

def enrich_ip(ip: str, cache: dict, sample_cache: dict) -> dict:
    # 1. ファイルキャッシュ（TTL内）
    if ip in cache and is_fresh(cache[ip]):
        return cache[ip]

    # 2. APIキーあり → API 照会
    if API_KEY:
        result = _call_api(ip)
        if result:
            result["_cached_at"] = datetime.now().isoformat()
            cache[ip] = result
            return result

    # 3. サンプルキャッシュ（APIキーなし or API失敗時のフォールバック）
    if ip in sample_cache:
        return sample_cache[ip]

    # 4. 情報なし
    return {"abuse_score": 0, "abuse_isp": "", "abuse_country": "", "abuse_reports": 0}


# ------------------------------------------------------------------ 入力パース
def parse_cowrie(path: Path) -> list[dict]:
    """Cowrie JSONL ログを読んで [{src_ip, count, events:[...]}] を返す。"""
    ip_events: dict[str, list] = {}
    errors = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                ip = ev.get("src_ip")
                if ip:
                    ip_events.setdefault(ip, []).append(ev)
            except json.JSONDecodeError:
                errors += 1
    if errors:
        print(f"  ⚠️  JSON パースエラー: {errors}行をスキップ")
    return [{"src_ip": ip, "count": len(evs), "events": evs} for ip, evs in ip_events.items()]

def parse_iplist(path: Path) -> list[dict]:
    """テキストリスト（1行1IP）を読んで [{src_ip, count}] を返す。"""
    ips = []
    with open(path) as f:
        for line in f:
            ip = line.strip()
            if ip and not ip.startswith("#"):
                ips.append({"src_ip": ip, "count": 1, "events": []})
    return ips

def detect_and_parse(path: Path) -> tuple[list[dict], str]:
    """入力ファイルの形式を自動判定してパースする。"""
    with open(path) as f:
        first = f.readline().strip()
    try:
        json.loads(first)
        return parse_cowrie(path), "cowrie"
    except json.JSONDecodeError:
        return parse_iplist(path), "iplist"


# ------------------------------------------------------------------ メイン
def main(input_path: str) -> None:
    path = Path(input_path)
    if not path.exists():
        print(f"Error: ファイルが見つかりません: {path}")
        sys.exit(1)

    print(f"\n{'='*50}")
    print(f"[Step 1] IP エンリッチ")
    print(f"{'='*50}")
    print(f"  入力: {path}")

    entries, fmt = detect_and_parse(path)
    print(f"  形式: {'Cowrie JSON' if fmt == 'cowrie' else 'IP テキストリスト'}")
    print(f"  ユニーク IP: {len(entries)}件")

    if not API_KEY:
        print(f"\n  ℹ️  ABUSEIPDB_API_KEY が未設定です。")
        print(f"     サンプルキャッシュ（sample_data/sample_cache.json）を使用します。")
        print(f"     本物データで試すには .env に API キーを設定してください。\n")

    cache       = load_cache()
    sample_cache = _load_json(SAMPLE_CACHE)

    results      = []
    api_calls    = 0
    cache_hits   = 0
    sample_hits  = 0

    for entry in entries:
        ip      = entry["src_ip"]
        count   = entry["count"]
        events  = entry.get("events", [])

        enrichment = enrich_ip(ip, cache, sample_cache)

        # どこから取得したか記録
        if ip in cache and is_fresh(cache.get(ip, {})):
            cache_hits += 1
            src = "cache"
        elif ip in sample_cache and not API_KEY:
            sample_hits += 1
            src = "sample"
        else:
            api_calls += 1
            src = "api"

        results.append({
            "src_ip":        ip,
            "count":         count,
            "enrichment":    enrichment,
            "events":        events,
            "_enrich_source": src,
        })

    save_cache(cache)

    OUTPUT_FILE.write_text(json.dumps(results, ensure_ascii=False, indent=2))

    summary_parts = []
    if cache_hits:   summary_parts.append(f"キャッシュ: {cache_hits}件")
    if sample_hits:  summary_parts.append(f"サンプル: {sample_hits}件")
    if api_calls:    summary_parts.append(f"API照会: {api_calls}件")
    print(f"  完了: {' / '.join(summary_parts)}")
    print(f"  出力: {OUTPUT_FILE}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使い方: python enrich.py <ログファイルまたはIPリスト>")
        print("例:     python enrich.py sample_data/cowrie_sample.json")
        print("        python enrich.py my_ips.txt")
        sys.exit(1)
    main(sys.argv[1])
