import json
import sys
import argparse

from util.HashType import HashType
from Triage.triage import searchTriage
from HybridAnalysis.hybridanalysis import searchHybridAnalysis
from VirusTotal.VirusTotal import serchVirusTotal
from api_keys2 import TRIAGE_APIKEY, HYBRIDANALYSIS_APIKEY, VIRUSTOTAL_APIKEY


def command_welcome():
    print("""   _____                   __    _           ______      ____          __
  / ___/____ _____  ____  / /_  (_)_______  / ____/___  / / /__  _____/ /_____  _____
  \__ \/ __ `/ __ \/ __ \/ __ \/ / ___/ _ \/ /   / __ \/ / / _ \/ ___/ __/ __ \/ ___/
 ___/ / /_/ / /_/ / /_/ / / / / / /  /  __/ /___/ /_/ / / /  __/ /__/ /_/ /_/ / /
/____/\__,_/ .___/ .___/_/ /_/_/_/   \___/\____/\____/_/_/\___/\___/\__/\____/_/
          /_/   /_/

Welcome to SapphireCollector!
""")


def main():
    parser = argparse.ArgumentParser(description="Tool to search and collect malware information from multiple malware database services by hash value")
    parser.add_argument("hash", nargs="?", help="Hash value of malware to search for. MDD5, SHA1, SHA256 can be used.")
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
    hybridanalysis_result = "[[Hybrid Anarysis]]\n" + json.dumps(searchHybridAnalysis(fileHash, HYBRIDANALYSIS_APIKEY), indent=4)
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
