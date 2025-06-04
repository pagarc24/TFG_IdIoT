import requests
import time
import subprocess

## Configutation of API requests
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# API key for NVD API access
NVD_API_KEY = "ENTER_API"
NVD_API_RESULTS_PER_PAGE = 2000 ## This is the max allowed

## Using CPE for more accurate results other than keyword search
OPENSSH_CPE = "cpe:2.3:a:*:openssh:*:*:*:*:*:*:*:*"
keywoards = "OpenSSH"

def fetch_snap_packages():
    result = subprocess.run(["ls", "-l"], check=True, capture_output=True, text=True)
    return result.stdout.splitlines()

def fetch_all_cve(cpe=None, keywords=None):
    if cpe is None and keywords is None:
        print("No search criteria provided.")
        return
    
    cve_ids = set()
    
    headers = {}
    if NVD_API_KEY is not None and NVD_API_KEY != "ENTER_API":
        headers['apiKey'] = NVD_API_KEY
    
    start_idx = 0
    total_results = -1 
    
    while True:
        params = {
            "resultsPerPage": NVD_API_RESULTS_PER_PAGE,
            "startIndex": start_idx
        }
        if cpe:
            params["virtualMatchString"] = cpe
        elif keywords:
            params["keywordSearch"] = keywords
            
        try:
            response = requests.get(NVD_API_BASE_URL, headers=headers, params=params)
            response.raise_for_status() # Check for HTTP errors
            data_obtained = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error obtaining data from NVD API :: {e}")
            break
        except ValueError as e:
            print(f"Error parsing JSON response :: {e}")
            break
        
        vulnerabilities = data_obtained.get("vulnerabilities", [])
        if not vulnerabilities:
            if start_idx == 0:
                print(f"No vulnerabilities found for CPE string :: {cpe}.")
            else:
                print(f"No more vulnerabilities found after {total_results} results.")
            break
        
        if total_results == -1:
            total_results = data_obtained.get("totalResults", 0)
            print(f"Total vulnerabilities found: {total_results}")
            
        for vulnerability in vulnerabilities:
            cve_id = vulnerability.get("cve", {}).get("id")
            if cve_id:
                cve_ids.add(cve_id)
                
        curr_count = len(vulnerabilities)
        start_idx += curr_count
        
        if start_idx >= total_results:
            break
        
        ## We have to manually rate limit
        # for API KEY recomended delay is 0.6 seconds
        # for non API 6 seconds
        if NVD_API_KEY is not None and NVD_API_KEY != "ENTER_API":
            time.sleep(0.7) 
        else:
            time.sleep(6.1)
            
    if cve_ids:
        print(f"\n--- Summary ---")
        print(f"Total unique CVE IDs fetched: {len(cve_ids)}")
        print("List of fetched CVE IDs:") # Uncomment if you want to print the full list at the end
        for cve_id in sorted(list(cve_ids)):
            print(cve_id)
    else:
        print("\nNo CVE IDs were ultimately collected.")                 

def snap_list():
    process = subprocess.run(['snap', 'list'], capture_output=True, text=True)
    out = process.stdout.strip().split('\n')[1:]#Quitamos la primera con los nombres de las columnas
    snap_list = []
    for paquete in out:
        carac = paquete.split(maxsplit=4)#Extraemos las distintas caracteristicas
        if len(carac) >= 5:
            snap_list.append({
                'nombre': carac[0],
                'version': carac[1],
                'publisher': carac[4]
            })
    return snap_list

if __name__ == "__main__":
    api_key_file = "../api_keys/nvd_api_key"
    with open(api_key_file, 'r', encoding='utf-8') as file:
        NVD_API_KEY = file.read()

    # This block of code is checking whether an API key for the NVD API has been provided or not.
    # Here's what it does:
    if NVD_API_KEY is None or NVD_API_KEY == "ENTER_API":
        print("#######################################")
        print("NO API KEY PROVIDED")
        print("rate limited : 1 request per 6 seconds")
        print("#######################################")
    else:
        print("#######################################")
        print("API KEY PROVIDED")
        print("rate limited : 1 request per 0.6 seconds")
        print("#######################################")
        # Fetch all CVEs for OpenSSH using CPE
    fetch_all_cve(keywords=keywoards)
    
    snap_packages = fetch_snap_packages()
    print("Test :")
    for package in snap_packages:
        print(package)