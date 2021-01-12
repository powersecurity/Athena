#!/usr/bin/env python3

'''

Athena: Automating Cyber Threat Intelligence

Description: Cyber T.I tool allows thew user to perform the following VT lookups:
    1) Scan a hash against Virustotal API and display/save results
    2) Upload a file to Virustotal and display/save results
    3) Scan an IP for resolve information aswell as any malicious samples/domains related to that IP
    4) Scan an IP with AbuseIPDB 
    5) Daily list of malicious IP/URL/Hash from Cybercure.ai

Author: Jack Power
Version: 4.1

'''


from pyfiglet import Figlet
import argparse
import time
import json
import requests
import re 


versionNo = "4.1"
VT_key = "" # Set the Virustotal API Key
AB_key = "" # Set the AbuseIPDB API Key

#************************#
#      Text Colours      #
#************************#

TITLE = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'

ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

#*************************#

def banner():
    banner_text = Figlet(font='5lineoblique')
    printBanner = banner_text.renderText('Athena')
    about = "\tAutomating Cyber Threat Intelligence"
    author = "Developed by: Jack Power"
    print(TITLE + printBanner + ENDC + "\n" + WARNING + UNDERLINE + about + ENDC)
    print("\n" + OKBLUE + author + ENDC +  OKGREEN + "\nVersion: " + versionNo + ENDC + "\n\n")

def main():
    banner() # Print banner

    #***********************#
    #       Arguments       #
    #***********************#
    parser = argparse.ArgumentParser(description="Athena: Automated Cyber Threat Intelligence")
    parser.add_argument('-v', '--version', action='version', version='%(prog)s Version ' + versionNo)
    parser.add_argument('-o', '--output', required=False, help='Save output to a file')
    parser.add_argument('-H', '--hash', type=checkhash, required=False, help='Single hash to analyze')

    # Virustotal-related Arguments
    parser.add_argument('-t', '--topvendor', action ='store_const', const=1, required=False, help='Display top 5 AV vendor results')
    parser.add_argument('-fs', '--filescan', help='Submit a file to Virustotal to be scanned')
    parser.add_argument('-vtip', '--vtipaddr', help='Submit a IP to Virustotal to be scanned')
    parser.add_argument('-url', '--url', help='Submit a URL to Virustotal to be scanned')
    # AbuseIPDB-related Arguments
    parser.add_argument('-aip', '--abipaddr', help="Submit an IP to AbuseIPDB to be analyzed")
    # CyberCure-related Arguments
    #***********************#
    parser.add_argument('-ccip', '--ccipaddr', action='store_const', const=1, required=False, help='Check Daily Malicious IP Indicators')
    parser.add_argument('-ccurl', '--ccurladdr', action='store_const', const=1, required=False, help='Check Daily Malicious URL indicators')
    parser.add_argument('-cchash', '--cchash', action='store_const', const=1, required=False, help='Check Daily Malicious Hash indicators')
    #------------------------#
    args = parser.parse_args()

    if args.cchash:
        try:
            file = open(args.output, 'w+')
            file.write("**************************************\n")
            file.write("** Cyber Cure Malicious Hash Report **\n")
            file.write("**************************************\n")
            file.close()
            Cyber_Cure_Hash_List(args.output)
        except TypeError:
            print("<?> You need to output to a file: -o <ouput file>")
        
    if args.ccipaddr:
        file = open(args.output, 'w+')
        file.write("************************************\n")
        file.write("** Cyber Cure Malicious IP Report **\n")
        file.write("************************************\n")
        file.close()
        Cyber_Cure_IP_List(args.output)

    if args.ccurladdr:
        file = open(args.output, "w+")
        file.write("*************************************\n")
        file.write("** Cyber Cure Malicious URL Report **\n")
        file.write("*************************************\n")
        file.close()
        Cyber_Cure_URL_List(args.output)
    
    if args.abipaddr and AB_key:    # AbuseIP IP Check
        AbuseIP_Check(args.abipaddr, AB_key)
    
    if args.vtipaddr and VT_key:    # VT IP Check
        VT_IP_Check(args.vtipaddr, VT_key)

    if args.url and VT_key:     # VT URL Check
        VT_URL_Check(args.url, VT_key)
    
    if args.filescan and VT_key and args.output:    # VT File Upload
        VT_Send_File_To_Scan(VT_key, args.filescan, args.output)
    if not args.filescan and not VT_key and not args.output:
        print("[!] Error: You must supply:\n\t1) File to Scan\n\t2) VT API KEY\n\t3) Output file\n\t Please try again.")
    
    if args.topvendor:
        if args.hash and VT_key:
            file = open(args.output, 'w+')
            file.write("************************************\n")
            file.write("** TOP 5 VirusTotal Vendor Report **\n")
            file.write("************************************\n")
            file.write("[*] Hash Value: " + args.hash.rstrip() + "\n")
            file.close()
            VT_Request_Top_Vendor(VT_key, args.hash.rstrip(), args.topvendor, args.output)
    else:
        if args.hash and VT_key:
            file = open(args.output, 'w+')
            file.write("*******************************\n")
            file.write("** VirusTotal Vendor Report **\n")
            file.write("******************************\n")
            file.write("[*] Hash Value: " + args.hash.rstrip() + "\n")
            file.close()
            VT_Request(VT_key, args.hash.rstrip(), args.output)

# Check Hash Validity
def checkhash(hashValue):
    # Check if VT Key exists
    if VT_key == "":
        print("[!] API Key Error: You have not supplied your Virustotal API key")
    elif VT_key != "":
        try:
            if len(hashValue) == 32:
                print("[+] Checking MD5 Hash: " + hashValue + " in Virustotal")
                time.sleep(1)
                return hashValue
            elif len(hashValue) == 40:
                print("[+] Checking SHA1 Hash: " + hashValue + " in Virustotal")
                time.sleep(1)
                return hashValue
            elif len(hashValue) == 64:
                print("[+] Checking SHA256 Hash: " + hashValue + " in Virustotal")
                time.sleep(1)
                return hashValue
            else:
                time.sleep(0.4)
                print("[!] Hash Length Error: Input is not a valid Hash")
                time.sleep(0.4)
                print("Solution: Enter a valid MD5/SHA1/SHA256 hash\n")
                time.sleep(0.4)
        except Exception:
            print("[!] There appears to be an error with your input hash. Please try again.\n")

# Handles JSON responses
def jsonResponse(response, json_response, hash, output):
    if response == 0:
            print(WARNING + "[-]" + hash + " is not in Virus total.\n" + ENDC)
            time.sleep(1)
            file = open(output, 'a')
            file.write("[-]" + hash + " is not in Virus total\n")
            file.write("\n\n")
            file.close()
    elif response == 1:
        positives = int(json_response.get('positives'))
        if positives == 0:
            print(OKCYAN + "[+]" + hash + " is not malicious\n" + ENDC)
            time.sleep(1)
            file = open(output, 'a')
            file.write("[+]" + hash + " is not malicious\n")
            file.write("\n\n")
            file.close()
        else:
            print(FAIL + "[!]" + hash + " is malicious\n" +ENDC)
            time.sleep(3)
            file = open(output, 'a')
            file.write("[!]" + hash + " is a malicious hash. Hit count: " + str(positives) + "\n")
            file.write("\n\n")
            file.close()
    else:
        print("[~]" + hash + " cound not be searched. Please try again later.\n")
    
#  Cyber Cure Daily Malicious Hash list
def Cyber_Cure_Hash_List(output):
    hash_response = requests.get("http://api.cybercure.ai/feed/get_hash", headers = {"Accept": "application/json"}, params={"output": "json"})
    response = json.loads(hash_response.text)

    print("---------------------------------------------")
    print("--   Cyber Cure Intelligence Feed / Hash   --")
    print("---------------------------------------------")
    print("\n")

    numMalHash = str(response["count"])
    lastUpdate = str(response["ts"])
    print("[*] Malicious Hashes: " + numMalHash)
    print("[*] Last updated: " + lastUpdate + "\n")

    file = open(output, 'a')
    file.write("\n[*] Malicious Hashes: " + numMalHash + "\n")
    file.write("[*] Last updated: " + lastUpdate + "\n\n")

    for hash in response["data"]["hash"]:
        dataOut = "[*] " + hash
        print(dataOut)
        file.write(dataOut)
        file.write("\n")
        time.sleep(0.001)
    file.close()

# Cyber Cure Daily IP List
def Cyber_Cure_IP_List(output):
    ip_response = requests.get("http://api.cybercure.ai/feed/get_ips", headers = {"Accept": "application/json"}, params={"output": "json"})
    response = json.loads(ip_response.text)

    print("-------------------------------------------")
    print("--   Cyber Cure Intelligence Feed / IP   --")
    print("-------------------------------------------")
    print("\n")

    numMalIP = str(response["count"])
    lastUpdate = str(response["ts"])
    print("[*] Malicious IPs: " + numMalIP)
    print("[*] Last updated: " + lastUpdate + "\n")

    file = open(output, 'a')
    file.write("\n[*] Malicious IPs: " + numMalIP + "\n")
    file.write("[*] Last updated: " + lastUpdate + "\n\n")

    for ip in response["data"]['ip']:
        dataOut = "[*] " + ip
        print(dataOut)
        file.write(dataOut)
        file.write("\n")
        time.sleep(0.001)
    file.close()

# Cyber Cure Daily Malicious URL list
def Cyber_Cure_URL_List(output):
    url_response = requests.get("http://api.cybercure.ai/feed/get_url", headers = {"Accept": "application/json"}, params={"output": "json"})
    response = json.loads(url_response.text)

    print("-------------------------------------------")
    print("--   Cyber Cure Intelligence Feed / URL  --")
    print("-------------------------------------------")
    print("\n")

    numMalURL = str(response["count"])
    lastUpdate = str(response["ts"])

    print("[*] Malicious URLs: " + numMalURL)
    print("[*] Last Updated: " + lastUpdate + "\n")

    file = open(output, 'a')
    file.write("\n[*] Malicious URLs: " + numMalURL + "\n")
    file.write("[*] Last updated: " + lastUpdate + "\n\n")

    for url in response["data"]["urls"]:
        strippedDomain = url.strip()
        x = re.sub(r"\.", "[dot]", strippedDomain)
        x = re.sub("https://", "hxxps://", x)
        x = re.sub("http://", "hxxp://", x)
       
        dataOut = "[*] " + x
        print(dataOut)
        file.write(dataOut)
        file.write("\n")
        time.sleep(0.001)
    file.close()

# AbuseIPDB - Check an IP for abuse reputation
def AbuseIP_Check(IP, AB_key):
    querystring = {"ipAddress": IP, "maxAgeInDays": 90}
    headers = {'Accept': 'application/json', 'Key': AB_key,}

    try:
        response = requests.request(method='GET', url='https://api.abuseipdb.com/api/v2/check', headers=headers, params=querystring)
        decodedResponse = json.loads(response.text)

        print("------------------------------------------------")
        print("-          Abuse IPDB / IP Reputation          -")
        print("------------------------------------------------\n")
        time.sleep(0.1)
        print("[*] Results for " + decodedResponse["data"]["ipAddress"])
        print("------------------------------------------------")

        # If IP is a private range
        if ("172" in decodedResponse["data"]["ipAddress"] or "192" in decodedResponse["data"]["ipAddress"] or "10" in decodedResponse["data"]["ipAddress"]):
            if (decodedResponse["data"]["isPublic"] == False):
                print("[-] Private IP")
                exit(1)

        abuseScore = str(decodedResponse["data"]["abuseConfidenceScore"])
        totReports = str(decodedResponse["data"]["totalReports"])
        hostName = str(decodedResponse["data"]["hostnames"]).strip("'[]'")

        print("[*] Country: " + decodedResponse["data"]["countryCode"])
        time.sleep(0.05)
        print("[*] Owner: " + decodedResponse["data"]["domain"])
        time.sleep(0.05)
        if abuseScore == '0':
            print("[*] Abuse Confidence: " + abuseScore + "%")
            time.sleep(0.05)
            print("[*] Times Reported: " + totReports)
            time.sleep(0.05)
        elif abuseScore >= '1':
            print(FAIL + "[*] Abuse Confidence: " + abuseScore + "%" + ENDC) 
            print(FAIL + "[*] Times Reported: " + totReports + ENDC)
            time.sleep(0.05)
        
        usage = str(decodedResponse["data"]["usageType"])
        print("\n[*] UsageType: " + usage)
        if hostName:
            time.sleep(0.05)
            print("[*] Hostname(s): " + hostName)
        
        print("------------------------------------------------\n")
    except requests.RequestException as e:
        return dict(error=str(e))

# VT URL Lookup
def VT_URL_Check(url, VT_key):
    params = {'apikey': VT_key, 'resource': url}
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    except requests.RequestException as e:
        return dict(error=str(e))

    json_response = response.json()
    x = str(json_response)
    scanID = str(x['scan_id'])
    scanDate = str(x['scan_date'])
    positiveRate = str(x['positive'])

    print("\n[*] Scan ID: " + scanID)
    print("[*] Scan Date: " + scanDate)
    print("[*] Link: " + permalink)
    print("----------------------------------------\n")
    print("[*] Positive Rate: " + positiveRate)
    if positiveRate == '0': 
        print("[*] " + resource + " is not malicious")
    elif positiveRate >= '1':
        print("[*] " + resource + " is a malicious URL\n")
       
        print("-------------------------------------")
        print("-    Virustotal URL Scan results    -")
        print("-------------------------------------\n")

        for vendor in x['scans']:
            detected = str(x['scans'][vendor]['detected'])
            if detected == "True":
                result = str(x['scans'][vendor]['result'])
                time.sleep(0.5)
                print("[*] " + vendor + " | " + result)
            elif detected == "False":
                result = str(x['scans'][vendor]['result'])
                if result != "clean site" and result != "unrated site":
                    time.sleep(0.5)
                    print("[*] " +vendor + " | " + result)
        
# VT IP Lookup
def VT_IP_Check(IP, VT_key):
    params = {'apikey': VT_key, 'ip': IP}
    try:
        response = requests.get("https://www.virustotal.com/vtapi/v2/ip-address/report", params=params)
    except requests.RequestException as e:
        return dict(error=str(e))
    
    json_response = response.json()
    x = str(json_response)
    x = x.replace("'", '"')
    x = x.replace("False", '"False"')
    x = x.replace("True", '"true"')
    x = x.replace("None", '"None"')
    try:
        parsed = json.loads(x)
    except KeyError:
        print("[!] Unable to lookup IP address")

    beautifyJsonIP = json.dumps(parsed, indent=2, sort_keys=True)

    # Beautify the JSON
    print("\n\n[*]" + IP + " analyzed by Virustotal")
    time.sleep(0.05)
    print("\n")
    print("----------------------------------------------")
    print("-          Virus Total / IP Report           -")
    print("----------------------------------------------\n")

    response = int(json_response.get('response_code'))
    try:
        as_owner = parsed['as_owner']
        asn = str(parsed['asn'])
        country = parsed['country']
        detected_url = parsed['detected_urls']
    except KeyError:
        print("[!] It appears this IP is not available on Virustotal!")
        exit(1)
    
    print("[*] AS Owner: " + as_owner)
    time.sleep(0.4)

    time.sleep(0.4)
    print("[*] Country: " + country + "\n")
    time.sleep(0.4)

    print("[*] IP Resolution:\n--------------------")
    time.sleep(0.1)
    for hostname in parsed['resolutions']:
        parsedHost = hostname['hostname']
        parsedHostLastResolved = hostname['last_resolved']
        time.sleep(0.01)
        print(parsedHost + "\n" + parsedHostLastResolved + "\n")

    print("\n[*] Obfuscated Domains related to " + IP + "\n---------------------------------------------")
    time.sleep(0.4)
    for domain in parsed['detected_urls']:
        parsedDomain = domain['url']
        strippedDomain = parsedDomain.strip()
        x = re.sub(r"\.", "[dot]", strippedDomain)
        x = re.sub("https://", "hxxps://", x)
        x = re.sub("http://", "hxxp://", x)
        print(x)
        time.sleep(0.01)

    print("\n[*] Detected Downloaded Samples:\n-----------------------------------------")
    time.sleep(0.4)
    try:
        for sample in parsed['detected_downloaded_samples']:
            sampleResult = sample
            parsedSamplePositives = str(sample['positives'])
            parsedSampleSha = sample['sha256']
            time.sleep(0.01)
            print("[+] Sample Positive Rate: " + parsedSamplePositives)
            print("\t Sample SHA256 Hash: " + parsedSampleSha + "\n")
    except KeyError:
        print("[-] No Detected Downloaded Samples")
        exit(1)

# Upload a file to VT to be scanned
def VT_Send_File_To_Scan(VT_key, file_to_scan, output):
    params = {'apikey': VT_key}
    files = {'file': open(file_to_scan, "rb")}

    try:
        response = requests.post("https://www.virustotal.com/vtapi/v2/file/scan", files=files, params=params)
    except requests.RequestException as e:
        return dict(error=str(e))
    
    json_response = response.json()
    x = str(json_response)
    x = x.replace("'", '"')
    x = x.replace("False", '"False"')
    x = x.replace("True", '"true"')
    x = x.replace("None", '"None"')

    print("\n\n[*] " + file_to_scan + " successfully uploaded to Virustotal.")
    time.sleep(0.2)
    print("\n")
    print("----------------------------------------------")
    print("-     Virus Total / Uploaded File Report     -")
    print("----------------------------------------------\n")
    
    parsed = json.loads(x)
    try:
        scan_id = parsed['scan_id']
        sha1 = parsed['sha1']
        resource = parsed['resource']
        sha256 = parsed['sha256']
        permalink = parsed['permalink']
        md5 = parsed['md5']
        msg = parsed['verbose_msg']

        print("[!] " + msg + "\n")
        time.sleep(0.3)
        print("[*] Scan ID: " + scan_id)
        time.sleep(0.3)
        print("[*] SHA1 Hash: " + sha1)
        time.sleep(0.3)
        print("[*] SHA256 Hash: " + sha256)
        time.sleep(0.3)
        print("[*] MD5 Hash: " + md5)
        time.sleep(0.3)
        print("\n")
        print("[*] Link to report: " + permalink)
        time.sleep(0.3)

        print("\n[+] Attempting to load Scan Results (this may take a few minutes..):\n\n")
        print("*** If hash does not appear to be scanned. Wait a few minutes and scan the hash using -H argument ***\n")
        time.sleep(240) # Sleeps for 4 minutes to allow scan to complete

        VT_Request(VT_key, md5, output)
    except KeyError:
        print("[!] File could not be scanned")  

# Virustotal Search for a hash and return all vendor reports
def VT_Request(VT_key, hash, output):
    params = {'apikey': VT_key, 'resource': hash}
    url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    json_response = url.json()
    x = str(json_response)
    x = x.replace("'", '"')
    x = x.replace("False", '"False"')
    x = x.replace("True", '"true"')
    x = x.replace("None", '"None"')
                    
    headerResults = OKGREEN + "***************************************************************************\n" + ENDC
    headerResults += OKGREEN + "** Vendor \t\t\t | \t\t\t Malware Variant **\n" + ENDC
    headerResults += OKGREEN + "***************************************************************************\n" + ENDC
    vendorResult = ""
    variantResult = ""

    try:
        parsed = json.loads(x)
    except KeyError:
        print("[!] Hash has not been scanned on Virustotal. ")

    y = json.dumps(parsed, indent = 4, sort_keys=True)

    response = int(json_response.get('response_code'))
    jsonResponse(response, json_response, hash, output)     

    try:
        parseCheck = parsed['scans'] # Check to see if 'scans' exist. If it doesnt, the hash has not been scanned   
        print(headerResults)
        for vendor in parsed['scans']:
            vendorResult = vendor
            variantResult = parsed['scans'][vendorResult]['result']
            if variantResult == "None":
                variantResult = "Clean"   
            dataOut = "{:<20} {:>50}".format(vendorResult, variantResult)
            print(dataOut)
            time.sleep(0.03)
            file = open(output, 'a')
            file.write(dataOut)
            file.write("\n")
            file.close()  
    except KeyError:
        print("[!] Hash has not been scanned on Virustotal. ")

# Virustotal Search for a hash and return top 5 vendor report
def VT_Request_Top_Vendor(VT_key, hash, topvendor, output):
    params = {'apikey': VT_key, 'resource': hash}
    url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    json_response = url.json()
    x = str(json_response)
    x = x.replace("'", '"')
    x = x.replace("False", '"False"')
    x = x.replace("True", '"true"')
    x = x.replace("None", '"None"')

    # Top 5 Vendors
    ms = "Microsoft"
    sop = "Sophos"
    kas = "Kaspersky"
    crwd = "CrowdStrike"
    feye = "FireEye"

    headerResults = OKGREEN + "****************************TOP 5 Vendors**********************************\n" + ENDC
    headerResults += OKGREEN + "***************************************************************************\n" + ENDC
    headerResults += OKGREEN + "** Vendor \t\t\t | \t\t\t Malware Variant **\n" + ENDC
    headerResults += OKGREEN + "***************************************************************************\n" + ENDC
    vendorResult = ""
    variantResult = ""

    try:
        parsed = json.loads(x)
    except KeyError:
         print("[!] Hash has not been scanned on Virustotal. ")

    response = int(json_response.get('response_code'))
    jsonResponse(response, json_response, hash, output)  

    try:
        parseCheck = parsed['scans'] # Check to see if 'scans' exist. If it doesnt, the hash has not been scanned
        print(headerResults)
        for vendor in parsed['scans']:
            vendorResult = vendor
            variantResult = parsed['scans'][vendorResult]['result']
            if variantResult == "None":
                variantResult = "Clean"
            if vendor == ms or vendor == sop or vendor == kas or vendor == crwd or vendor == feye:
                dataOut = "{:<20} {:>50}".format(vendorResult, variantResult)
                print(dataOut)
                file = open(output, 'a')
                file.write(dataOut)
                file.write("\n")
                file.close()
                time.sleep(0.03)
    except KeyError:
         print("[!] Hash has not been scanned on Virustotal. ")


if __name__ == '__main__':
    main()
        
