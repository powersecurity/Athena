# Athena

![](images/images/Athena-Header.png)

<h1><b>Overview</b></h1>
<b>Automated Tool for Open-Source Cyber Threat Intelligence</b>

Athena is a tool developed with the task of automating open-source threat intelligence feeds such as Virustotal, AbuseIPDB and Cybercure.ai. The main goal of         Athena is to have these resources in one place where the user can easily pass the relevant command-line argument and get an automated response for such things as malicous IPs,URLs and IOCs etc, using API calls to threat intelligence feeds. 

<b>Athena</b> <i>Version 4.4</i> can be used for automated Threat Intelligence lookups. You can perform the following functions:

1) Virustotal Hash scan 
2) Virustotal file upload
3) Virustotal IP Lookup
4) AbuseIPDB Lookup
5) Cybercure.ai Threat Intelligence lookups for Malicious IP/URL/Hash

<h1><b> Functionaility </b></h1>
Each of the above allows the user to quickly and efficiently check for malicious content and receive a CLI output aswell as save the results to an output file.

-o / --output // Output the results to a user-specified file

-H / --hash // Input a hash to scan on Virustotal
![](images/images/Athena-Hash.gif)

-t / --topvendor // Input a hash to scan on Virustotal and return the most reputable vendor results
![](images/images/Athena-Hash-Top5.gif)

-fs / --filescan // Upload a file to Virustotal to scan (A report can be generated automatically, after the scan).
![](images/images/Athena-Fileupload.gif)

-vtip / --vtipaddr // Scan an IP address in Virustotal 
![](images/images/Athena-VTIP.gif)

-url / --url // Scan a URL in Virustotal
![](images/images/Athena-VTURL.gif)

-aip / --aipaddr // Scan an IP for reputation in AbuseIPDB
![](images/images/Athena-AbuseIP.gif)

-ccip / --ccip // Generate a list of known malicious IPs via the Cybercure.ai API (Change everyday)
![](images/images/Athena-CCIP.gif)

-ccurl / --ccurl // Generate a list of known malicious URLs via the Cybercure.ai API (Change everyday)
![](images/images/Athena-CCURL.gif)

--cchash / --cchash // Generate a list of known malicious Hashes via the cybercure.ai API (Change everyday)
![](images/images/Athena-CCHash.gif)

<h1><b>Requirements and Installation</b></h1>

[+] Python3

[+] The following dependencies: 

        1) pyfiglet
        2) argparse
        3) time
        4) json
        5) requests
        6) re 
        7) sys
        
[+] Virustotal API key

[+] AbuseIPDB API key
