import sys
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
        print(e.response.text)
        return

    result = response.json()
    
    return result
