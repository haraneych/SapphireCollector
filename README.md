# プロジェクト名(SapphireCollectorとか？)
(仮)SapphireCollectorは各マルウェア解析サービスから、ハッシュ値ベースで情報をテキスト出力するツールです。
対象とするマルウェア解析サービスは次の３種類です。
- Virustotal(https://www.virustotal.com/)
- Hatching Triage(https://tria.ge/)
- Hybrid Analysis(https://www.hybrid-analysis.com/)

## 事前準備
### 実行環境の準備
このツールはPython3で作成しています。
次のライブラリをインストールしてください。
- requests

### APIキーの準備
各マルウェア解析サービスを呼び出すAPIキーは次のファイルに記載する構成になっています。
フリーアカウントの範囲でAPIを呼び出しておりますので、利用者側で準備をお願いします。
- api_keys.py

## 使い方
調査したいマルウェアについてハッシュ値(MD5)を準備する。
以下のコマンドを実行することで、各種情報がテキストファイルにエクスポートされます。

    python sapphire_collector.py (MD5_hash)

## 活用方法
出力されたテキストファイルを対象にgrepコマンドなどで検索をして、活用ください！
