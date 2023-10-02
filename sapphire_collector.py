import json
import sys
import argparse

from util.HashType import HashType
from Triage.triage import searchTriage
from HybridAnalysis.hybridanalysis import searchHybridAnalysis
from VirusTotal.VirusTotal import serchVirusTotal
from api_keys import TRIAGE_APIKEY, HYBRIDANALYSIS_APIKEY, VIRUSTOTAL_APIKEY


def command_welcome():
    print("""   _____                   __    _           ______      ____          __
  / ___/____ _____  ____  / /_  (_)_______  / ____/___  / / /__  _____/ /_____  _____
  \__ \/ __ `/ __ \/ __ \/ __ \/ / ___/ _ \/ /   / __ \/ / / _ \/ ___/ __/ __ \/ ___/
 ___/ / /_/ / /_/ / /_/ / / / / / /  /  __/ /___/ /_/ / / /  __/ /__/ /_/ /_/ / /
/____/\__,_/ .___/ .___/_/ /_/_/_/   \___/\____/\____/_/_/\___/\___/\__/\____/_/
          /_/   /_/

Welcome to SapphireCollector!
""")

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
        "analsis_start_time": analysis_start_time,
        "domains" : domains,
        "hosts" : hosts,
        "signatures":signatures_list
    }
        
    result = json.dumps(OnlyNeedData,indent=5)
    return result


def main():
    parser = argparse.ArgumentParser(description="Tool to search and collect malware information from multiple malware database services by hash value")
    parser.add_argument("hash", nargs="?", help="Hash value of malware to search for. MD5, SHA1, SHA256 can be used.")
    parser.add_argument("-o", "--output", help="File path to output results.")
    args = parser.parse_args()

    if args.hash is None:
        command_welcome()
        parser.print_help()
        return
    
    fileHash = args.hash
    hashType = None
    if len(fileHash) == 32:
        hashType = HashType.MD5
    elif len(fileHash) == 40:
        hashType = HashType.SHA1
    elif len(fileHash) == 64:
        hashType = HashType.SHA256
    
    if hashType is None:
        print('Error: Only MDD5, SHA1, SHA256 can be used for hash type.', file=sys.stderr)
        sys.exit(1)

    triage_result = "[[Triage]]\n" + json.dumps(searchTriage(hashType, fileHash, TRIAGE_APIKEY), indent=4)
    hybridanalysis_result = "[[Hybrid Anarysis]]\n" + HybridRequiredData(json.dumps(searchHybridAnalysis(fileHash, HYBRIDANALYSIS_APIKEY), indent=4))
    virustotal_result = "[[VirusTotal]]\n" + json.dumps(serchVirusTotal(fileHash, VIRUSTOTAL_APIKEY), indent=4)
    result_list = [triage_result, hybridanalysis_result, virustotal_result]
    all_result_text = "\n".join(result_list)


    
    if args.output is None:
        print(all_result_text)
    else:
        output_filepath = args.output
        with open(output_filepath, "w") as f:
            f.write(all_result_text)


if __name__ == "__main__":
    main()
