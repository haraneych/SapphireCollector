import string
from util.HashType import HashType
import requests
from requests import RequestException
import json

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
        extract_result = {}
        extract_result["name"] = ""
        extract_result["tags"] = ""
        extract_result["score"] = ""
        extract_result["analysis_start_time"] = ""
        extract_result["C2ip"] = ""
        extract_result["description"] = ""
        return extract_result
    result = response.json()
    extract_result = {}
    extract_result["name"] = result["signatures"][0]["name"]
    extract_result["score"] = result["analysis"]["score"]
    extract_result["tags"] = result["analysis"]["tags"]
    extract_result["analysis_start_time"] = result["sample"]["created"]
    extract_result["filetype"] = result.get("tasks")
    extract_result["C2ip"] = result["targets"][0]["iocs"]
    extract_result["behavior"] = result.get("signatures")

    return extract_result
    #print(json.dumps(result, indent=4))
