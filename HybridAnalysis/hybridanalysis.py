import sys
from requests import session
 
def hash_to_summary(file_hash, api_key):
        
    Session = session()
    Session.headers = {
    'api-key': api_key,
    'user-agent': 'Falcon'
    }
    response = Session.request('POST', 'https://www.hybrid-analysis.com/api/v2/search/hashes', data={'hashes[]': file_hash})
    response_json = response.json()
    
    return response_json



'''
Example:

from HybridAnalysis import hybridanalysis as ha

file_hash = '<Malware Hash Value>' # md5, sha1 or sha256 hash value
api_key = '<Hybrid Analysis API Key>'

res = ha.hash_to_summary(file_hash, api_key)
'''
