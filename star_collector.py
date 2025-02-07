import json
import sys
import argparse

from util.HashType import HashType
from Triage.triage import searchTriage
from HybridAnalysis.hybridanalysis import searchHybridAnalysis,HybridRequiredData
from VirusTotal.VirusTotal import serchVirusTotal,extract_json,UnixTime_to_Standard_time
from chatgpt.chatgpt import summaryByChatgpt
from api_keys import TRIAGE_APIKEY, HYBRIDANALYSIS_APIKEY, VIRUSTOTAL_APIKEY,OPENAI_APIKEY


def command_welcome():
    print("""
   _____ __             ______      ____          __            
  / ___// /_____ ______/ ____/___  / / /__  _____/ /_____  _____
  \__ \/ __/ __ `/ ___/ /   / __ \/ / / _ \/ ___/ __/ __ \/ ___/
 ___/ / /_/ /_/ / /  / /___/ /_/ / / /  __/ /__/ /_/ /_/ / /    
/____/\__/\__,_/_/   \____/\____/_/_/\___/\___/\__/\____/_/     
                                                                


Welcome to StarCollector!
""")


def output_allresult(hybridanalysis_result_json,triage_result_json,virustotal_result_json, chatgpt_result):
    result = f"""
<name>
VuirsTotal:{json.dumps(virustotal_result_json["name"],indent=2)}
Triage:{json.dumps(triage_result_json["name"],indent=2)}
Hybrid analysis: {json.dumps(hybridanalysis_result_json["name"],indent=2)}

<tags>
VuirsTotal:{json.dumps(virustotal_result_json["tags"],indent=2)}
Triage:{json.dumps(triage_result_json["tags"],indent=2)}
Hybrid analysis: {json.dumps(hybridanalysis_result_json["tags"],indent=2)}

<score>
VuirsTotal:{virustotal_result_json["malicious"]}/{virustotal_result_json["malicious"]+virustotal_result_json["undetected"]}
Triage:{triage_result_json["score"]}/10
Hybrid analysis: {hybridanalysis_result_json["score"]}/100

<analysis start time>
VuirsTotal:{virustotal_result_json["analysis_start_time"]}
Triage:{triage_result_json["analysis_start_time"]}
Hybrid analysis: {hybridanalysis_result_json["analysis_start_time"]}

<Suspected IP Address of C2 Server>
VuirsTotal:{json.dumps(virustotal_result_json["c2"],indent=2)}
Triage:{json.dumps(triage_result_json["C2ip"],indent=2)}
Hybrid analysis: {json.dumps(hybridanalysis_result_json["hosts"],indent=2)}

"""

    if chatgpt_result:
        result = result +  f"""
<Summary of malware behavior>
{chatgpt_result}

"""
    return result


def main():
    parser = argparse.ArgumentParser(description="Tool to search and collect malware information from multiple malware database services by hash value")
    parser.add_argument("hash", nargs="?", help="Hash value of malware to search for. MD5, SHA1, SHA256 can be used.")
    parser.add_argument("-a", "--all", action="store_true", help="Show all results")
    parser.add_argument("-c", "--chatgpt", action="store_true", help="Chatgpt explains the behavior of malware.")
    parser.add_argument("-o", "--output", help="File path to output results.")
    args = parser.parse_args()
    command_welcome()
    if args.hash is None:
        parser.print_help()
        return

    if args.all and args.chatgpt:
        print('Sorry, -a and -c cannot be used at the same time')
        sys.exit(1)

    if not HYBRIDANALYSIS_APIKEY:
        print('Error: Please set HybridAnalysis API key', file=sys.stderr)
        sys.exit(1)
    
    if not TRIAGE_APIKEY:
        print('Error: Please set Triage API key', file=sys.stderr)
        sys.exit(1)

    if not VIRUSTOTAL_APIKEY:
        print('Error: Please set VirusTotal API key', file=sys.stderr)
        sys.exit(1)
        
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
        
    if args.all:
        triage_result = "[[Triage]]\n" + json.dumps(searchTriage(hashType, fileHash, TRIAGE_APIKEY), indent=4)
        hybridanalysis_result = "[[Hybrid Anarysis]]\n" + json.dumps(searchHybridAnalysis(fileHash, HYBRIDANALYSIS_APIKEY), indent=4)
        virustotal_result = "[[VirusTotal]]\n" + json.dumps(serchVirusTotal(fileHash, VIRUSTOTAL_APIKEY), indent=4)
        result_list = [triage_result, hybridanalysis_result, virustotal_result]
        result = "\n".join(result_list)  
        
    else:
        hybridanalysis_result_json = json.loads(HybridRequiredData(json.dumps(searchHybridAnalysis(fileHash, HYBRIDANALYSIS_APIKEY), indent=4)))
        triage_result_json = json.loads(json.dumps(searchTriage(hashType, fileHash, TRIAGE_APIKEY), indent=4))
        virustotal_result_json = extract_json(json.loads(json.dumps(serchVirusTotal(fileHash, VIRUSTOTAL_APIKEY), indent=4)))
        
        chatgpt_result = ""
        if args.chatgpt:
            if not OPENAI_APIKEY:
                print('Error: Please set OpenAI API key', file=sys.stderr)
                sys.exit(1)
            description =  str(triage_result_json.get("behavior")) + str(hybridanalysis_result_json.get("signatures")) + str(virustotal_result_json.get("description"))
            if description == "None[]None":
                chatgpt_result = "Sorry, can't summarize."
            else:
                description =  str(triage_result_json.get("behavior")) + str(hybridanalysis_result_json.get("signatures")) + str(virustotal_result_json.get("description"))
                chatgpt_result = summaryByChatgpt(OPENAI_APIKEY, description)
        result = output_allresult(hybridanalysis_result_json,triage_result_json,virustotal_result_json,chatgpt_result)

    if args.output :
        output_filepath = args.output
        with open(output_filepath, "w") as f:
            f.write(result)
        
    else:
        print(result)

if __name__ == "__main__":
    main()


