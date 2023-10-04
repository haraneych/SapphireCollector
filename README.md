# StarCollector
StarCollectorは各マルウェア解析サービスから、ハッシュ値ベースで情報を標準出力するツールです。
現在対象としているマルウェア解析サービスは次の３種類です。
- Virustotal(https://www.virustotal.com/)
- Hatching Triage(https://tria.ge/)
- Hybrid Analysis(https://www.hybrid-analysis.com/)

## 事前準備
### 実行環境の準備
このツールはPython3で作成しています。
次のライブラリをインストールしてください。
- requests
- openai

### APIキーの準備
各マルウェア解析サービスを呼び出すAPIキーとOpenAIのAPIキーは次のファイルに記載する構成になっています。
フリーアカウントの範囲でAPIを呼び出しておりますので、利用者側で準備をお願いします。
またOpenAIのAPIキーをお持ちで無い場合でも一部の機能は利用することができます。
- api_keys.py

## 使い方
調査したいマルウェアについてハッシュ値(MD5 or SHA1 or SHA256)を準備してください。
以下のコマンドを実行することで、各種情報(ファイル名、スコア、不審なURLやIPアドレス、マルウェアの動作)がターミナルに標準出力されます。`-o`を付けて実行すると、出力先ファイルをすることが出来ます。


    python3 star_collector.py ハッシュ値(MD5 or SHA1 or SHA256) -o 出力先ファイル名
    Example:python3 star_collector.py 8432e504f078f9319133a9ad826773fc -o output.txt

ChatGPTを用いてマルウェアの動作を要約させる場合

    python3 star_collector.py ハッシュ値(MD5 or SHA1 or SHA256) -c -o 出力先ファイル名  
    Example:python3 star_collector.py 8432e504f078f9319133a9ad826773fc -c -o output.txt

また、各マルウェア解析サービスをから取得した結果をそのまま表示させることができます　　

    python3 star_collector.py ハッシュ値(MD5 or SHA1 or SHA256) -a -o 出力先ファイル名  
    Example:python3 star_collector.py 8432e504f078f9319133a9ad826773fc -a -o output.txt

ヘルプの表示

    python3 star_collector.py -h
    python3 star_collector.py --help

## 活用方法
出力されたテキストファイルを対象にgrepコマンドなどで検索をして、活用ください！
