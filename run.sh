#!/bin/bash
# Cowrie ログまたは IP リストを受け取り、エンリッチ→スコアリングを順番に実行する。
#
# 使い方:
#   bash run.sh sample_data/cowrie_sample.json   # サンプルで試す（APIキー不要）
#   bash run.sh my_ips.txt                       # 自分のIPリスト
#   bash run.sh /path/to/cowrie.json             # 本物のCowrieログ

set -euo pipefail

if [ $# -eq 0 ]; then
  echo "使い方: bash run.sh <ログファイルまたはIPリスト>"
  echo "例:     bash run.sh sample_data/cowrie_sample.json"
  exit 1
fi

INPUT="$1"

python3 enrich.py "$INPUT"
python3 score.py
