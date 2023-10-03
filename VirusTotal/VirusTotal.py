import json
import requests
from requests import RequestException
import datetime


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
    
def extract_json(data):
    try:
        attribute = data["data"]["attributes"]
        extracted_data = {}
        extracted_data["name"] = attribute["names"]
        extracted_data["tags"] = attribute["tags"]
        extracted_data["malicious"] = attribute["last_analysis_stats"]["malicious"]
        extracted_data["undetected"] = attribute["last_analysis_stats"]["undetected"]
        extracted_data["start_time"] = UnixTime_to_Standard_time(attribute["first_submission_date"])
        extracted_data["c2"] = ""
        extracted_data["description"] = attribute.get("crowdsourced_ids_results")
        return extracted_data
    except json.JSONDecodeError:
        return None  # 不正なJSONの場合はNoneを返す

def UnixTime_to_Standard_time(unixtime):
    standard_time = datetime.datetime.utcfromtimestamp(unixtime)
    return standard_time
    
    