from util.HashType import HashType
from Triage.triage import searchTriage
from HybridAnalysis.hybridanalysis import searchHybridAnalysis
import json
import sys

TRIAGE_APIKEY = "e1faae1f731f5df362dc495eed5ae5c17e2ab5b3"
HYBRIDANALYSIS_APIKEY = '<HybridAnalysis API key>'
def main():
    args = sys.argv
    fileHash = args[1]

    t = searchTriage(HashType.MD5,fileHash,TRIAGE_APIKEY)
    h = searchHybridAnalysis(fileHash,HYBRIDANALYSIS_APIKEY)
    
    print(json.dumps(t, indent=4))
    print(json.dumps(h, indent=4))

if __name__ == '__main__':
    main()
