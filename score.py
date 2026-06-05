#!/usr/bin/env python3
"""
Step 2: スコアリング＆表示

入力: enriched.json (enrich.py の出力)
出力: ターミナルテーブル（カラー） + output.csv
"""
import csv
import json
import sys
from pathlib import Path

try:
    from tabulate import tabulate
except ImportError:
    print("Error: tabulate がインストールされていません。pip install -r requirements.txt を実行してください。")
    sys.exit(1)

INPUT_FILE  = Path("enriched.json")
OUTPUT_CSV  = Path("output.csv")

# ANSI カラー
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def calc_score(enrichment: dict, count: int) -> int:
    """
    abuse_score を主軸に、報告数・アクセス頻度で補正したスコアを返す。

    - abuse_score (0-100) が基本点
    - abuse_reports > 1000: +5pt ボーナス
    - count >= 10:          +3pt ボーナス（頻繁に試みているIP）
    上限は 100。
    """
    base    = int(enrichment.get("abuse_score", 0))
    reports = int(enrichment.get("abuse_reports", 0))
    bonus   = 0
    if reports >= 1000:
        bonus += 5
    if count >= 10:
        bonus += 3
    return min(base + bonus, 100)


def colorize_score(score: int) -> str:
    if score >= 80:
        return f"{RED}{BOLD}{score:>3}{RESET}"
    if score >= 40:
        return f"{YELLOW}{score:>3}{RESET}"
    if score == 0:
        return f"{GRAY}{score:>3}{RESET}"
    return f"{score:>3}"


def flag(country: str) -> str:
    """2文字国コード → 旗絵文字（ターミナルが対応していれば表示）。"""
    if not country or len(country) != 2:
        return "  "
    return chr(0x1F1E6 + ord(country[0]) - ord('A')) + chr(0x1F1E6 + ord(country[1]) - ord('A'))


def detect_shell_intrusion(events: list) -> str:
    for ev in events:
        if ev.get("eventid") in ("cowrie.login.success", "cowrie.command.input"):
            return f"{RED}⚠ シェル侵入{RESET}"
    return ""


def main() -> None:
    if not INPUT_FILE.exists():
        print(f"Error: {INPUT_FILE} が見つかりません。先に enrich.py を実行してください。")
        sys.exit(1)

    data = json.loads(INPUT_FILE.read_text())

    print(f"\n{'='*50}")
    print(f"[Step 2] スコアリング")
    print(f"{'='*50}")

    rows = []
    for entry in data:
        ip         = entry["src_ip"]
        count      = entry["count"]
        enrichment = entry.get("enrichment", {})
        events     = entry.get("events", [])

        score   = calc_score(enrichment, count)
        country = enrichment.get("abuse_country", "")
        isp     = enrichment.get("abuse_isp", "不明")
        reports = int(enrichment.get("abuse_reports", 0))
        alert   = detect_shell_intrusion(events)

        rows.append({
            "score":   score,
            "ip":      ip,
            "country": country,
            "isp":     isp[:30],
            "reports": reports,
            "count":   count,
            "alert":   alert,
        })

    rows.sort(key=lambda r: r["score"], reverse=True)

    # ターミナル表示
    table = []
    for r in rows:
        table.append([
            colorize_score(r["score"]),
            r["ip"],
            f"{flag(r['country'])} {r['country']}",
            r["isp"],
            f"{r['reports']:,}",
            r["count"],
            r["alert"],
        ])

    print()
    print(tabulate(
        table,
        headers=[f"{BOLD}Score{RESET}", "IP", "国", "ISP", "報告数", "件数", ""],
        tablefmt="rounded_outline",
    ))

    # 統計サマリー
    total  = len(rows)
    high   = sum(1 for r in rows if r["score"] >= 80)
    medium = sum(1 for r in rows if 40 <= r["score"] < 80)
    low    = sum(1 for r in rows if r["score"] < 40)
    shells = sum(1 for r in rows if r["alert"])

    print(f"\n  合計: {total}件  |  "
          f"{RED}高危険(80+): {high}件{RESET}  |  "
          f"{YELLOW}中(40-79): {medium}件{RESET}  |  "
          f"{GRAY}低(0-39): {low}件{RESET}")
    if shells:
        print(f"  {RED}⚠  シェル侵入検知: {shells}件 — 上位 IP を優先調査してください{RESET}")

    # CSV 出力
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["score","ip","country","isp","abuse_reports","count"])
        writer.writeheader()
        for r in rows:
            writer.writerow({
                "score":         r["score"],
                "ip":            r["ip"],
                "country":       r["country"],
                "isp":           r["isp"],
                "abuse_reports": r["reports"],
                "count":         r["count"],
            })

    print(f"\n  結果を {OUTPUT_CSV} に保存しました。\n")


if __name__ == "__main__":
    main()
