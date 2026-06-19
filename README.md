# honeypot-cti-starter

Cowrie ハニーポットのログから **「見るべき攻撃者」** を絞り込む、2ステップの CTI 入門ツール。

```
生ログ（大量）→ [Step 1] エンリッチ → [Step 2] スコアリング → 優先調査リスト
```

> Hack Fes. 2026「1日86,000件のアラートから逃げるな」の登壇資料で紹介したパイプラインのスタンドアロン版。  
> Wazuh・ハニーポット・Redis は不要。Python が動けば今すぐ試せます。

**変えるのは「作業」ではなく「意思決定」です。** 大量のログを前に「どれから見るか」が決まらない——その状態を、① 文脈を与える（エンリッチ）→ ② 数値で並べる（スコアリング）の2ステップで「上位数件から見ればいい」に変える。脅威インテリジェンス（CTI）は、ツールではなくこの判断の置き換えそのものです。

📣 更新や、Step 3・Wazuh 連携の深掘りは X [@SamuraiCTI](https://x.com/SamuraiCTI) で発信していきます。

---

## まず動かす（API キー不要）

```bash
git clone https://github.com/samuraidays/honeypot-cti-starter
cd honeypot-cti-starter
pip install -r requirements.txt
bash run.sh sample_data/cowrie_sample.json
```

**出力イメージ:**

```
==================================================
[Step 1] IP エンリッチ
==================================================
  入力: sample_data/cowrie_sample.json
  形式: Cowrie JSON
  ユニーク IP: 9件

  ℹ️  ABUSEIPDB_API_KEY が未設定です。サンプルキャッシュを使用します。

  完了: サンプル: 9件

==================================================
[Step 2] スコアリング
==================================================

╭─────────┬────────────────┬───────┬────────────────────────────────┬─────────┬──────┬──────────────╮
│   Score │ IP             │ 国    │ ISP                            │    報告数 │  件数 │              │
├─────────┼────────────────┼───────┼────────────────────────────────┼─────────┼──────┼──────────────┤
│     100 │ 2.57.122.177   │ 🇷🇴 RO │ TECHOFF SRV LIMITED            │ 128,390 │    6 │              │
│     100 │ 103.89.136.111 │ 🇮🇳 IN │ Genesys International Corp     │     847 │    4 │ ⚠ シェル侵入 │
│     100 │ 130.12.180.51  │ 🇨🇦 CA │ DataCity                       │     412 │    4 │ ⚠ シェル侵入 │
│      75 │ 45.128.232.110 │ 🇳🇱 NL │ Aeza Group Ltd                 │      89 │    3 │              │
│       0 │ 194.165.16.11  │ 🇷🇺 RU │ Aeza International Ltd         │       0 │    2 │              │
│     ... │ ...            │  ...  │ ...                            │     ... │  ... │              │
╰─────────┴────────────────┴───────┴────────────────────────────────┴─────────┴──────┴──────────────╯

  合計: 9件  |  高危険(80+): 5件  |  中(40-79): 2件  |  低(0-39): 2件
  ⚠  シェル侵入検知: 2件 — 上位 IP を優先調査してください

  結果を output.csv に保存しました。
```

---

## 本物データで試す（API キー取得後）

AbuseIPDB の無料アカウント（1日 1,000 リクエスト）を取得して `.env` に設定するだけで、自分の環境のデータを解析できます。

```bash
# 1. AbuseIPDB でアカウント作成 → API キーを取得
#    https://www.abuseipdb.com/account/api

# 2. .env を作成してキーを設定
cp .env.example .env
# .env の ABUSEIPDB_API_KEY= に取得したキーを貼り付ける

# 3. 自分の Cowrie ログで実行
bash run.sh /path/to/cowrie.json

# IP アドレスのテキストリスト（1行1IP）でも動きます
bash run.sh my_suspicious_ips.txt
```

API 照会結果は `cache/abuseipdb_cache.json` に 24 時間キャッシュされます。  
同じ IP を何度調べても API リクエストは消費しません。

---

## 2ステップの概要

### Step 1: エンリッチ（`enrich.py`）

生 IP アドレスに「文脈」を付けます。

| Before | After |
|---|---|
| `2.57.122.177` | 国: Romania / ISP: TECHOFF SRV LIMITED / Score: 100 / 報告数: 128,390件 |

AbuseIPDB v2 API を使って `abuse_score`（危険度 0-100）、`abuse_isp`、`abuse_country`、`abuse_reports` を取得します。

### Step 2: スコアリング（`score.py`）

エンリッチ済みデータを **危険度スコア降順** で並べ直します。

- `abuse_score` を基本点に、報告数・アクセス頻度でボーナス補正
- スコア 80+ → 赤（即調査）
- スコア 40-79 → 黄（要確認）
- スコア 0（未報告）→ グレー（「未報告 ≠ 安全」に注意）
- Cowrie でシェル侵入が成功しているセッションは `⚠ シェル侵入` で強調表示

---

## ファイル構成

```
.
├── enrich.py                   # Step 1: エンリッチ
├── score.py                    # Step 2: スコアリング
├── run.sh                      # 2ステップをまとめて実行するラッパー
├── requirements.txt            # requests / tabulate / python-dotenv
├── .env.example                # API キー設定テンプレート
├── sample_data/
│   ├── cowrie_sample.json      # サンプルログ（APIキー不要で動作確認用）
│   └── sample_cache.json       # サンプル用エンリッチ済みキャッシュ
├── cache/                      # API 照会結果キャッシュ（自動生成）
├── enriched.json               # Step 1 の出力（自動生成）
└── output.csv                  # Step 2 の出力（自動生成）
```

---

## 対応する入力形式

| 形式 | 例 | 自動判定 |
|---|---|---|
| Cowrie JSON ログ（JSONL） | `cowrie.json` | ✅ |
| IP アドレステキストリスト | `ips.txt`（1行1IP） | ✅ |

---

## 動作要件

- Python 3.10 以上
- `requests` / `tabulate` / `python-dotenv`（`pip install -r requirements.txt` で一括インストール）
- AbuseIPDB API キー（任意。未設定でもサンプルデータで動作します）

---

## このツールに含まれないもの

| 機能 | 理由 |
|---|---|
| Step 3: ノイズ除去（GreyNoise 連携） | 無償枠の制限上、大量ログでの再現が困難 |
| Wazuh / OpenSearch 連携 | 本番環境依存のため別途 Zenn 記事で解説予定 |
| リアルタイム監視（デーモン動作） | 入門向けにバッチ実行に絞った |

Step 3 の GreyNoise 連携や Wazuh との統合は、**Zenn で中級者向け記事を公開予定**です。公開は X [@SamuraiCTI](https://x.com/SamuraiCTI) で告知します（フォローしておくと記事が届きます）。

---

## ライセンス

MIT
