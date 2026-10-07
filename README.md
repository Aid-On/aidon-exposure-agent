# Aid-On Exposure Agent

許可された外部公開資産の観測と、顧客が提供した設定・権限を照合し、**業務上重要な資産につながる経路の候補**を根拠付きで出す、オフライン検査エージェントの最小実装です。

「放置されたAI PoC → 過大なコネクタ権限 → 機密業務資産」を、単なる隣接グラフではなく、入口の認証・入力から操作への接続・主体・デプロイ・権限・稼働状態という前提条件で評価します。修正案を提示し、別の新しい設定スナップショットで同じ経路を再判定します。

これは新規のプロトタイプです。既存Aid-On製品の再現・互換性・同等性能を検証したものではありません。商用EASMへの優位性も主張しません。

## まず動かす

必要なのは Almide 0.67.0、対応するRustツールチェーン、Python 3.12以降です。Pythonの追加パッケージ、APIキー、クラウドアカウント、外部サービスは不要です。

```sh
# Almide / Rust が PATH にある環境
./build.sh
python3 -m aidon_exposure demo --out output/demo
python3 -m unittest discover -s tests -v
```

コンパイラを明示する場合:

```sh
ALMIDE=/path/to/almide ./build.sh
```

ソース配布です。ローカルで `bin/aidon-engine` をビルド済みなら、そのままデモを実行できます。ビルド時の一時領域は TMPDIR で指定できます。

デモは固定された合成時刻を使います。実在する顧客・サービスへの通信はありません。

- `output/demo/before.json` / `before.txt`: 判定・経路・条件・証拠・除外理由
- `output/demo/after.json` / `after.txt`: 修正後を模した独立したrevision 2の判定
- `output/demo/recheck.json`: 同じ経路がfixture上で閉じた根拠と比較指標

生成済みの例は `examples/demo/` にあります。

## デモで確かめること

1. 公開AI PoCについて、顧客設定がすべての前提条件を支持するため1件の候補を出す
2. 公開情報だけの権限推測、期限切れの設定、不明な主体は「未成立・不明」のまま残す
3. 無効な接続はそのスナップショットでは経路成立を阻む
4. 所有不明の資産、似たドメイン、許可範囲外へのCNAMEやIPを除外する
5. 同じ主体・デプロイの後の設定証拠で未認証入口が否定されたら、同じfinding IDを `closed_in_fixture` にする。管理状態や機密分類だけの変更は `scenario_reclassified` として区別する

`configuration_supported_candidate` は「提供された設定証拠がモデルの前提条件を支持する」という意味です。攻撃成功、実際の到達性、データ流出を確認した意味ではありません。`closed_in_fixture` も、その経路と入力スナップショットについての限定された判定です。

## 自分の合成fixtureを評価する

```sh
python3 -m aidon_exposure assess fixtures/before.json \
  --manifest fixtures/manifest.json \
  --at 2026-10-07T09:30:00Z --out output/assessment

python3 -m aidon_exposure recheck fixtures/before.json fixtures/after.json \
  --manifest fixtures/manifest.json \
  --before-at 2026-10-07T09:30:00Z \
  --after-at 2026-10-07T10:30:00Z --out output/recheck
```

`assess` の `--at` を省略すると現在のUTC時刻を使用します。期限切れのfixtureが不明になるのは意図した動作です。固定デモを現実の最新観測と扱わないでください。

不正入力や予算超過は終了コード2で停止します。候補があること自体はCLIの実行失敗ではないため終了コード0です。`scan`、侵入、設定変更、認証情報の利用といったコマンドはありません。

## 実装済み

- Almide: source種別ごとの支持条件、三値＋矛盾の前提評価、主体・デプロイの接続確認、経路候補生成
- Python標準ライブラリ: 明示的な資産許可とその有効期間・失効、所有登録、ドメイン・別名・IP制約、厳格JSON読込、証拠ハッシュ・時刻・改訂管理、処理予算、エージェントループ、報告・再判定
- 証拠ごとの出典・観測時刻・有効期限・改訂・適格性を保存
- 確認済み／推測／不明のノード・辺を保持し、未確認の辺で成立を確定しない
- stable finding ID、業務影響と不確実性による段階的優先度、承認を要する修正提案
- 49件の受入テスト。公開情報のみ、矛盾、異なる主体・デプロイ、期限切れ、改訂後再検査、欠落、scope逸脱、重複、命令文注入を含む

## まだ実装していないこと

- 実ネットワークの探索、DNS解決、HTTP接続、クラウド／SaaS／コードの実コネクタ
- 署名された証拠、所有権や提供元の独立検証、永続的な改訂台帳
- 実行環境での到達性・悪用可能性確認、任意の攻撃経路探索
- LLMによる計画。現状は決定論的なbounded agent loopであり、AIモデルの判断を装っていない
- 変更の適用、承認ワークフローの外部連携、常時監視
- teastia / Porta連携。境界と入力契約を先に置いた拡張案

現在の信頼起点は、操作者が用意したローカルmanifestと合成データです。SHA-256は破損検出用で、真正性や悪意ある偽造の防止を保証しません。生のJSONを内側の `aidon-engine` に直接渡しても、入力の許可・時刻・ハッシュ検証は行われません。利用入口はPython CLIです。

## 最小比較の読み方

同一fixtureで、単純な「公開資産＋既知脆弱性リスト」ベースラインと、「成立条件をすべて支持された候補だけ出す」本エンジンを比較します。評価単位は入口資産。正解ラベルは検査器から独立した `ground_truth.json` に置いた手作りの合成ラベルです。

- ベースライン: TP 0 / FP 1 / FN 1、precision 0.0 / recall 0.0
- 前提条件エンジン: TP 1 / FP 0 / FN 0、precision 1.0 / recall 1.0

これは5件だけの説明用ケースです。代表性のあるベンチマークでも、現実のexploit正解データでもありません。「EASMを超えた」という性能根拠には使えません。商用EASMが持つ権限・攻撃経路・検証機能をこのベースラインは表しません。

設計・境界・次の実装案は [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)、脅威モデルは [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) を参照してください。
