import requests
import ipaddress

#API key for VirusTotal, get it from https://www.virustotal.com/gui/join-us
API_KEY = ""

def enrich_ip_address(ip_address):
    # Use the IPInfo API to get geolocation information for the IP address
    # Free plan is up to 50K requests per month
    
    response = requests.get(f"https://ipinfo.io/{ip_address}/json")
    data = response.json()

    # Extract the geolocation information from the API response
    region = data['region']
    country = data['country']
    
    # Use the VirusTotal API to check if the IP address is known to be malicious
    response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}", headers={'x-apikey': API_KEY})
    data = response.json()
    if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
        malicious = True
    else:
        malicious = False
        
    # Check if the IP address is part of the Tor network
    response = requests.get(f"https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={ip_address}")
    if response.text == "1\n":
        tor = True
    else:
        tor = False
    
    # Check if the IP address is from AWS
    def is_aws_ip(ip_address):
        # Check if the input IP address is within the AWS IP address range
        try:
            ip = ipaddress.ip_address(ip_address)
            if ip in ipaddress.ip_network("18.0.0.0/15") or ip in ipaddress.ip_network("35.0.0.0/16") or ip in ipaddress.ip_network("52.0.0.0/15"):
                return True
            else:
                return False
        except ValueError:
            return False
    aws = is_aws_ip(ip_address)

    # Return the enriched data as a dictionary
    return {
        'ip_address': ip_address,
        'region': region,
        'country': country,
        'malicious': malicious,
        'tor': tor,
        'aws': aws
    }

# Check My home IP
enriched_data = enrich_ip_address("8.8.8.8")
print(enriched_data)
