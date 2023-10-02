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
        return e.response.text
    result = response.json()
    try:
        id = result["data"][0]['id']
        response = requests.get(f"https://tria.ge/api/v0/samples/{id}/overview.json", headers=headers)
        response.raise_for_status()
    except RequestException as e:
        return e.response.text
    except IndexError:
        return
    result = response.json()
    extract_result = {}

    extract_result["score"] = result["analysis"]["score"]
    extract_result["tag"] = result["analysis"]["tags"]
    extract_result["analsys_start_time"] = result["sample"]["created"]
    extract_result["filetype"] = result["tasks"]
    extract_result["C2ip"] = result["targets"]
    extract_result["name&behavior"] = result["signatures"]

    return extract_result
    #print(json.dumps(result, indent=4))
