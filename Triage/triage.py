import string
from util.HashType import HashType
import requests
from requests import RequestException
#import json

url = {
    HashType.SHA1:"https://api.tria.ge/v0/search?query=sha1:",
    HashType.SHA256:"https://api.tria.ge/v0/search?query=sha256:",
    HashType.MD5:"https://api.tria.ge/v0/search?query=md5:"
}

def searchTriage(hashType: HashType,fileHash: string, apiKey: string):
    
    authorization = f"Bearer {apiKey}"
    headers = {'Authorization': authorization}
    try:
        response = requests.get(url[hashType]+fileHash, headers=headers)
        response.raise_for_status()
    except RequestException as e:
        print(e.response.text)
        return
    result = response.json()
    return result
    #print(json.dumps(result, indent=4))