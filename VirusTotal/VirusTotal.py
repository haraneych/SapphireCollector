#import json
import requests
from requests import RequestException

VIRUS_TOTAL_REQUEST_URL = "https://www.virustotal.com/api/v3/files/"

def serchVirusTotal(hash: str, apikey: str):
    url = VIRUS_TOTAL_REQUEST_URL + hash
    try:
        headers = {
            "accept": "application/json",
            "x-apikey": apikey
        }
        res = requests.get(url, headers=headers)
        
        if res.status_code == 200:
            return res.json()
        else:
            res.raise_for_status()
    except RequestException as e:
        return e.response.text
