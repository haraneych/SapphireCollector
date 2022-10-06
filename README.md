# SapphireCollector
SapphireCollectorは各マルウェア解析サービスから、ハッシュ値ベースで情報を標準出力するツールです。
現在対象としているマルウェア解析サービスは次の３種類です。
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
調査したいマルウェアについてハッシュ値(MD5 or SHA1 or SHA256)を準備してください。
以下のコマンドを実行することで、各種情報がターミナルに標準出力されます。

    python3 sapphire_collector.py ハッシュ値(MD5 or SHA1 or SHA256) -o 出力先ファイル名
    Example:python3 sapphire_collector.py 84d164fbfe0982a00404cb3d7b164bf5 -o output.txt

ヘルプの表示

    python3 sapphire_collector.py -h
    python3 sapphire_collector.py --help

## 活用方法
出力されたテキストファイルを対象にgrepコマンドなどで検索をして、活用ください！
