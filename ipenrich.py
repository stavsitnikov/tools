import requests

#virustotal API key, get one from https://www.virustotal.com/gui/join-us
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
    
    # Return the enriched data as a dictionary
    return {
        'ip_address': ip_address,
        'region': region,
        'country': country,
        'malicious': malicious,
        'tor': tor
    }

# The ip address to check
enriched_data = enrich_ip_address("8.8.8.8.8")
print(enriched_data)
