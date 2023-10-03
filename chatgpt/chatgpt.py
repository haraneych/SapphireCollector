import json
import openai

def summaryByChatgpt(apikey: str, description):
    try:
        openai.api_key = apikey
        content = '''下記に示すマルウェアの情報から，以下の項目を実施してください．
        今回のマルウェアはどのような動作を行うのか，列挙した後それぞれ解説してください．
        その際，セキュリティの知識のない技術者でもわかるよう，専門用語を一つ一つ説明しながら解説してください．
        なお，情報源は下記のマルウェアの情報のみとし，下記の情報から読み取れる情報をすべて列挙してください．
        ''' + description
        res = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
        messages=[
            {"role": "user", "content": content},
        ],
        )
        ans = res.choices[0]["message"]["content"].strip() 
        return ans
    except openai.error.InvalidRequestError as e:
        return "要約出来ませんでした"
