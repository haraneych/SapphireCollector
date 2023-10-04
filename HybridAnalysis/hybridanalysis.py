import sys
import json
from requests import session
from requests import RequestException

 
def searchHybridAnalysis(file_hash, api_key):
        
    Session = session()
    Session.headers = {
    'api-key': api_key,
    'user-agent': 'Falcon'
    }

    try:
        response = Session.request('POST', 'https://www.hybrid-analysis.com/api/v2/search/hashes', data={'hashes[]': file_hash})
        response.raise_for_status()
    except RequestException as e:
        return e.response.text

    result = response.json()
    
    return result

def HybridRequiredData(hybridanalysis_result):
    
    tags = []
    name= []
    url=[]
    score_list=[]
    vx_family=[]
    analysis_start_time=[]
    hosts=[]
    domains=[]
    signatures_list = []
    Number_of_matchs = 0

    def maxScore(score_list):
        max_number = None

        for item in score_list:
            if isinstance(item, (int, float)):
                if max_number is None or item > max_number:
                    max_number = item

        if max_number is not None:
            return max_number
        else:
            return None
    

    def Delete_the_first_two_characters_in_list(your_list):
        new_list = [item[2:] for item in your_list]
        return new_list
    
    def Duplicate_removal_and_sorting(your_list):
        new_list = sorted(list(set(your_list)))
        return new_list
    
    
    data_list = json.loads(hybridanalysis_result)
    
    for k in range(len(data_list)):
        Number_of_matchs = Number_of_matchs + 1
        data = data_list[k]
        submiissions = data["submissions"]
        for i in range(len(submiissions)):
            target_name= submiissions[i]["filename"]
            target_url = submiissions[i]["url"]
            name.append(str(k+1) + ">" +str(target_name))
            url.append(str(k+1) + ">" +str(target_url))
        
        classificationtags_list = data["classification_tags"]
        tags_list = data["tags"]
        for i in range(len(classificationtags_list)):
            tags.append(str(k+1) + ">"+ str(classificationtags_list[i]))
        for i in range(len(tags_list)):
            tags.append(str(k+1) + ">" + str(tags_list[i]))

        score_list.append(data["threat_score"])
        vx_family.append(str(k+1) +">" +str(data["vx_family"]))
        analysis_start_time.append(str(k+1) + ">" +str(data["analysis_start_time"]))

        domains_list = data["domains"]
        for i in range(len(domains_list)):
            domains.append(str(k+1)+ ">"+ str(domains_list[i]))

        hosts_list = data["hosts"]
        for i in range(len(hosts_list)):
            hosts.append(str(k+1) + ">"+ str(hosts_list[i]))
        
        signatures = data["signatures"]

        if not signatures:
            continue

        for i in range(len(signatures)):
            name_signature = data["signatures"][i]["name"]
            description_signature = data["signatures"][i]["description"]

            OneSignatureData ={
                "name": name_signature,
                "description":description_signature
            }

            signatures_list.append(OneSignatureData)

    
    tags = Duplicate_removal_and_sorting(tags)
    name = Duplicate_removal_and_sorting(name)
    url = Duplicate_removal_and_sorting(url)
    vx_family = Duplicate_removal_and_sorting(vx_family)
    analysis_start_time = Duplicate_removal_and_sorting(analysis_start_time)
    domains = Duplicate_removal_and_sorting(domains)
    hosts = Duplicate_removal_and_sorting(hosts)

    score = maxScore(score_list)
    
    
    OnlyNeedData = {
        "matchs": Number_of_matchs,
        "name": name,
        "tags": tags,
        "url": url,
        "score": score,
        "vx_family": vx_family,
        "analysis_start_time": analysis_start_time,
        "domains" : domains,
        "hosts" : hosts,
        "signatures":signatures_list
    }
        
    result = json.dumps(OnlyNeedData,indent=5)
    return result
