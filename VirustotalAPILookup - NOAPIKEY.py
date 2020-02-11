# Virustotal API lookup
import requests
import random
from datetime import datetime

author = 'Kevin Gibson'
version = '0.1'
version_date = '2/7/2020'
API_Explorer_Page = 'https://developers.virustotal.com/reference'
API_Key = 'YOUR API KEY HERE'

def FileHashLookup(file_hash):
    """
    Lookup the supplied file hash and display results
    :param: file_hash <type: string> - A file hash in any format, MD5, SHA1, SHA256 etc.
    :return: none, print results.
    """
    global API_Key
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params =  {'apikey' : API_Key,
               'resource' : file_hash,
               'allinfo' : True}
    headers = {'Content-Type': 'application/json'}
    response = requests.get(url, headers=headers, params=params)
    #return response
    if response.status_code == 200:
        try:
            r = response.json()
            number_of_infections = r['positives']
            total = r['total']
            if number_of_infections != 0: confidence_percent = round((number_of_infections/total*100), 2)
            print(f"[!] Hash - {file_hash}")
            print(f"[!] Number of sources reporting infected file: {number_of_infections}/{total} - Confidence {confidence_percent}%")
            print("------------------------------------------------------")
            for source in r['scans'].keys():
                if r['scans'][source]['detected']:       
                    print(f"[+] {source} - {r['scans'][source]['result']}")
            print()
        except:
            try:
                print(f"[!] {URL} - {r['verbose_msg']}")
            except:
                pass
    if response.status_code == 204:
        print(f"[!] Exceeded 4 API requests per minute.  - {str(response)}")


def URLLookup(URL):
    """
    Lookup the supplied URL
    :param: URL <type: string> - A URL to check
    :return: none, print results.
    """
    global API_Key
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params =  {'apikey' : API_Key,
               'resource' : URL,
               'allinfo' : True}
    headers = {'Content-Type': 'application/json'}
    response = requests.get(url, headers=headers, params=params)
    print(f"[+] URL - {URL}")
    if response.status_code == 200:
        r = response.json()
        try:
            number_of_positive_results = r['positives']
            total = r['total']
            if number_of_positive_results != 0: confidence_percent = round((number_of_positive_results/total*100), 2)
            print(f"[!] Number of sources reporting malicious URL: {number_of_positive_results}/{total}, Confidence {confidence_percent}%")
            print("------------------------------------------------------")
            for source in r['scans'].keys():
                if r['scans'][source]['detected']:       
                    print(f"[+] {source} - {r['scans'][source]['result']}")
            print()
        except:
            try:
                print(f"[!] {URL} - {r['verbose_msg']}")
            except:
                print("[!] Serialization error!")
    if response.status_code == 204:
        print(f"[!] Exceeded 4 API requests per minute.  - {str(response)}")

def DomainLookup(domain):           #See your notepad++ for json output for parsing
    """
    Lookup the supplied domain
    :param: domain <type: string> - A domain to check
    :return: none, print results.
    """    
    global API_Key
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params =  {'apikey' : API_Key,
               'domain' : domain}
    headers = {'Content-Type': 'application/json'}
    response = requests.get(url, headers=headers, params=params)
    #return response
    if response.ok:
        try:
            detected_malware_list = []
            detected_urls = []
            r = response.json()
            try: detected_malware_list = r['detected_referrer_samples']
            except: pass
            try: detected_urls = r['detected_urls']
            except: pass            
            for sample in r['detected_downloaded_samples']:
                detected_malware_list.append(sample)
            if len(detected_malware_list) != 0:
                print(f"[!] Found {len(detected_malware_list)} malware objects originating from {domain}")
                if len(detected_malware_list) > 1:
                    print(f"[!] Displaying 1 randomly selected malware result.")
                    print("----------------------------------------------------")
                    random_detection = detected_malware_list[random.randint(0,len(detected_malware_list))]
                    FileHashLookup(random_detection['sha256'])
                if len(detected_malware_list) <= 1:
                    for detection in detected_malware_list:
                        FileHashLookup(detection['sha256'])
            if len(detected_urls) != 0:
                print(f"[!] Found {len(detected_urls)} malicious URLs originating from {domain}")
                if len(detected_urls) > 1:
                    print(f"[!] Displaying 1 randomly selected malicious URL result.")
                    print("----------------------------------------------------")
                    random_detection = detected_urls[random.randint(0,len(detected_urls))]
                    URLLookup(random_detection['url'])
                if len(detected_urls) <= 1:
                    for detection in detected_urls:
                        URLLookup(detection['url'])
                
        except Exception as e:
            print(e)
            
    if response.status_code == 204:
        print(f"[!] Exceeded 4 API requests per minute.  - {str(response)}")

    

def IPAddressLookup(ip_address):        #See your notepad++ for json output for parsing
    """
    Lookup the supplied IPv4 Address
    :param: ip_address <type: string> - An IPv4 to check
    :return: none, print results.
    """    
    global API_Key
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params =  {'apikey' : API_Key,
               'ip' : ip_address}
    headers = {'Content-Type': 'application/json'}
    response = requests.get(url, headers=headers, params=params)
    return response
    if response.status_code == 200:
        pass
    if response.status_code == 204:
        print(f"[!] Exceeded 4 API requests per minute.  - {str(response)}")

"Hash lookup test"
# FileHashLookup('88eee6c692e3e4e2889f06f13145637c89332976cf7eae0da43147f5300fe574')
"URL lookup test"
# URLLookup("http://themartadm.com/verify_now/app/signin")
"Domain lookup test"
# DomainLookup('bog-fuchs.de')

