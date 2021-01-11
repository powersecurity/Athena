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
Version: 4.0

'''

from pyfiglet import Figlet
import argparse
import time
import os
import requests
import json
import re
import ipaddress 


versionNo = "4.0"
VTkey = "" # enter VT API key here
ABkey = "" # enter AbuseIPDB API key here

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

def banner():
    custom_fig = Figlet(font='5lineoblique')
    bannerText = custom_fig.renderText('Athena')
    blerb = "\tAutomating Cyber Threat Intelligence"
    author = "Developed by: Jack Power"
    print(FAIL + bannerText + ENDC + "\n" + WARNING + UNDERLINE + blerb + ENDC + "\n\n" + OKBLUE + author + ENDC + "\nVersion: " + versionNo + "\n\n")

def main():
    banner()
    parser = argparse.ArgumentParser(description="Athena: Automated Cyber Threat Intelligence")
    parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + versionNo)
    parser.add_argument('-o', '--output', required=False, help='Output File location')
    parser.add_argument('-H', '--hash', type=checkhash, required=False, help='Single hash to analyze')
    parser.add_argument('-t', '--topvendor', action='store_const', const=1, required=False, help='Display top 5 vendor results')
    parser.add_argument('-fs', '--filescan', help='Submit a file to Virustotal to be scanned')
    parser.add_argument('-vtip', '--vtipaddr', help='Submit an IP to Virustotal to be scanned')
    parser.add_argument('-url', '--url', help='Submit a URL Domain to Virustotal to be scanned')
    parser.add_argument('-aip', '--abipaddr', help='Submit an IP to abuseipdb to be analyzed')
    parser.add_argument('-ccip', '--ccipaddr', action='store_const', const=1, required=False, help='Check Daily Malicious IP Indicators')
    parser.add_argument('-ccurl', '--ccurladdr', action='store_const', const=1, required=False, help='Check Daily Malicious URL indicators')
    parser.add_argument('-cchash', '--cchash', action='store_const', const=1, required=False, help='Check Daily Malicious Hash indicators')
    args = parser.parse_args()

    if args.cchash:
        file = open(args.output, 'w+')
        file.write("**************************************\n")
        file.write("** Cyber Cure Malicious Hash Report **\n")
        file.write("**************************************\n")
        file.close()
        Cyber_Cure_Hash_List (args.output)

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

    if args.abipaddr and ABkey:
        AbuseIP_Check(args.abipaddr, ABkey)

    if args.vtipaddr and VTkey:
        VT_IP_Check(args.vtipaddr, VTkey)

    if args.filescan and VTkey and args.output:
        VT_Send_File_To_Scan(VTkey, args.filescan, args.output)
    if not args.filescan and not VTkey and not args.output:
        print("[!] Error: You must supply:\n\t1) File to Scan\n\t2) VT API KEY\n\t3) Output file\n\t Please try again.")
       
    if args.topvendor:
        if args.hash and VTkey:
            file = open(args.output, 'w+')
            file.write("************************************\n")
            file.write("** TOP 5 VirusTotal Vendor Report **\n")
            file.write("************************************\n")
            file.write("[*] Hash Value: " + args.hash.rstrip() + "\n")
            file.close()
            VT_Request_Top_Vendor(VTkey, args.hash.rstrip(), args.topvendor, args.output)
    else:
        if args.hash and VTkey:
            file = open(args.output, 'w+')
            file.write("*******************************\n")
            file.write("** VirusTotal Vendor Report **\n")
            file.write("******************************\n")
            file.write("[*] Hash Value: " + args.hash.rstrip() + "\n")
            file.close()
            VT_Request(VTkey, args.hash.rstrip(), args.output)

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

def AbuseIP_Check(IP, ABkey):
    querystring = {"ipAddress": IP, "maxAgeInDays": 90}
    headers = {'Accept': 'application/json', 'Key': ABkey,}
    try:
        #response = requests.get('https://api.abuseipdb.com/api/v2/check', params=params)
        response = requests.request(method='GET', url='https://api.abuseipdb.com/api/v2/check', headers=headers, params=querystring)
        decodedResponse = json.loads(response.text)
        
        print("")
        print("================================================")
        print("==              ABUSE IPDB Report             ==")
        print("================================================")

        print("")
        print("[*] Results for ", decodedResponse["data"]["ipAddress"])
        print("-----------------------------------------------")

        # If Ip is private
        if ("172" in decodedResponse["data"]["ipAddress"] or "192" in decodedResponse["data"]["ipAddress"] or "10" in decodedResponse["data"]["ipAddress"]):
            if (decodedResponse["data"]["isPublic"] == False):
                print("[-] Private IP")
                exit(1)
        
        abuseScore = str(decodedResponse["data"]["abuseConfidenceScore"])
        totReports = str(decodedResponse["data"]["totalReports"])
        hostName = str(decodedResponse["data"]["hostnames"]).strip("'[]'")

        print("[*] Country: " + decodedResponse["data"]["countryCode"])
        print("[*] Owner: " + decodedResponse["data"]["domain"])
        print("[*] Abuse Confidence: " + abuseScore + "%")
        print("[*] Times Reported: " + totReports)

        print("\n[*] UsageType: " + decodedResponse["data"]["usageType"])
        if hostName:
            print("[*] Hostname(s): " + hostName)
        
        print("")
        print("================================================")
        print("")
    except requests.RequestException as e:
        return dict(error=str(e))
        #as_owner = parsed['as_owner']
        #asn = str(parsed['asn'])
        #country = parsed['country']
        #detected_url = parsed['detected_urls']or=str(e))

def VT_IP_Check(IP, VTkey):
    params = {'apikey': VTkey, 'ip': IP}
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
    print("\n <-- IP Report --> \n")

    response = int(json_response.get('response_code'))
    try:
        as_owner = parsed['as_owner']
        asn = str(parsed['asn'])
        country = parsed['country']
        detected_url = parsed['detected_urls']
    except KeyError:
        print("[!] It appears this IP is not available on Virustotal!")
        exit(1)

    print("[*]AS Owner: " + as_owner)
    time.sleep(0.4)
    print("[*]ASN:" + asn )
    time.sleep(0.4)
    print("[*] Country: " + country + "\n")
    time.sleep(0.4)

    print("[*] IP Resolution:\n--------------------")
    time.sleep(0.1)
    for hostname in parsed['resolutions']:
        hostnameResult = hostname
        parsedHost = hostname['hostname']
        parsedHostLastResolved = hostname['last_resolved']
        time.sleep(0.01)
        print(parsedHost + "\n" + parsedHostLastResolved + "\n")
    
    print("\n[*] Obfuscated Domains related to " + IP + "\n---------------------------------------------")
    time.sleep(0.4)
    for domain in parsed['detected_urls']:
        domainResult = domain
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
        exit(1)

def VT_Send_File_To_Scan(VTkey, file_to_scan, output):
    # Routine that allows a file to be scanned on VT #
    params = {'apikey': VTkey}
    files = {'file': open(file_to_scan, "rb")}
    
    try:
        response = requests.post("https://www.virustotal.com/vtapi/v2/file/scan", files=files, params=params)
    except requests.RequestException as e:
        return dict(error=str(e))
    #print(response)
    json_response = response.json()
    #print(json_response)
    
    x = str(json_response)
    x = x.replace("'", '"')
    x = x.replace("False", '"False"')
    x = x.replace("True", '"true"')
    x = x.replace("None", '"None"')

    # Beautify the JSON
    print("\n\n[*] " + file_to_scan + " successfully uploaded to Virustotal.")
    print("\n <-- File Report --> \n")

    parsed = json.loads(x) 

    try:
        parseCheck = parsed['scan_id']

        scan_id = parseCheck
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
        print("*** If hash does not appear to be scanned. Wait a few minutes and scan the hash using -H argument\n")
        time.sleep(60)

        VT_Request(VTkey, md5, output)

        

    except KeyError:
        print("[!] File could not be scanned")   
    
#**********************************#
#    Routine for VT Hash lookup    #
#**********************************#
def checkhash(hashValue):
    if VTkey == "":
        print("[!] API Key error: You have not supplied your Virustotal API key")
    elif VTkey != "":
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
            print("[!] There appears to be an error with your input hash. Please try again. \n[!] Error:\n")
            print(Exception)

def VT_Request_Top_Vendor(VTkey, hash, topvendor, output):
    params = {'apikey': VTkey, 'resource': hash}
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

def VT_Request(VTkey, hash, output):
    params = {'apikey': VTkey, 'resource': hash}
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

if __name__ == '__main__':
    main()
