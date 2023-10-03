import json
import openai

def summaryByChatgpt(discription: str, apikey: str):
    openai.api_key = apikey
    content = '''下記に示すマルウェアの情報から，以下の項目を実施してください．
    1. マルウェア検出に利用可能な情報を抽出してください．特に，ファイル名，マルウェア名，タグ，スコア，サンプルの登録時刻，IOCとなるドメイン名・IPアドレス・URLは必ず表示してください．
    2.  今回のマルウェアはどのような動作を行うのか，列挙した後それぞれ解説してください．
    その際，セキュリティの知識のない技術者でもわかるよう，専門用語を一つ一つ説明しながら解説してください．
    なお，情報源は下記のマルウェアの情報のみとし，下記の情報から読み取れる情報をすべて列挙してください．
    ''' + discription
    res = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
    messages=[
        {"role": "user", "content": content},
    ],
    )
    ans = res.choices[0]["message"]["content"].strip() 
    return ans
