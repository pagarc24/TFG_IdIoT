import requests
import time
import subprocess
import datetime

## Configutation of API requests
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# API key for NVD API access
NVD_API_KEY = "ENTER_API"

filename = "system_analysis"

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

def parsing_response(content):#Comprobaciones
    cve_ids=set()
    #content['totalResults']
    content = content.get("vulnerabilities", [])
    for vulnerability in content:
            cve_id = vulnerability.get("cve", {}).get("id")
            if cve_id:
                cve_ids.add(cve_id)

    return cve_ids                 

def snap_list():
    process = subprocess.run(['snap', 'list'], capture_output=True, text=True)
    out = process.stdout.strip().split('\n')[1:]#Quitamos la primera con los nombres de las columnas
    paquetes_snap = []
    for paquete in out:
        carac = paquete.split(maxsplit=5)#Extraemos las distintas caracteristicas
        if len(carac) >= 5:
            name = carac[0]
            version = carac[1]
            publisher = carac[4].replace("**","")
            cpe = cpe_constructor(name,version,publisher)
            paquetes_snap.append({
                'name': name,
                'version': version,
                'publisher': publisher,
                'cpe': cpe
            })
    return paquetes_snap

def cpe_constructor(name, version, publisher):
    CPE_NAME="cpe:2.3"
    CPE_PART="a" #Application, siempre en nuestro caso
    CPE_VENDOR=publisher
    CPE_PRODUCT=name
    CPE_PRODUCT_VERSION=version

    res = CPE_NAME+":"+CPE_PART+":"+CPE_VENDOR+":"+CPE_PRODUCT+":"+CPE_PRODUCT_VERSION
    # Se añaden comodines representan los campos [update]:[edition]:[language]:[sw_edition]:[target_sw]:[target_hw]:[other]
    res = res + ":*:*:*:*:*:*:*"

    return res

def cpe_search(cpe):
    headers = {}
    if NVD_API_KEY is not None and NVD_API_KEY != "ENTER_API":
        headers['apiKey'] = NVD_API_KEY

    params={}
    params['virtualMatchString']=cpe

    response = requests.get(NVD_API_BASE_URL, headers=headers, params=params)
    return response.json() if response.status_code>=200 or response.status_code<300 else None

def cve_search(cve):
    url = f"{NVD_API_BASE_URL}?cveId={cve}"
    headers = {}
    if NVD_API_KEY is not None and NVD_API_KEY != "ENTER_API":
        headers['apiKey'] = NVD_API_KEY

    response = requests.get(url, headers=headers, params={})
    return response.json() if response.status_code>=200 or response.status_code<300 else None

def recolector():# Se encarga de recoger nombre, version y fabricante/publisher/vendor de distintos gestores
    components=[]
    components.extend(snap_list())
    return components

def get_token():
    api_key_file = "../api_keys/nvd_api_key"
    with open(api_key_file, 'r', encoding='utf-8') as file:
        token = file.read()
    return token 

def component_analysis(component):
    return "None\n"

def system_report(components):
    f = open(filename, 'a')
    for e in components:
        analysis = component_analysis(e) #despues añadir analisis al fichero de report
        print(analysis)
        f.write(analysis)
    f.close()

def init():
    msg = f"Analizando el sistema el {datetime.datetime.now()}\n"
    print(msg)
    f = open(filename, "w")
    f.write(msg)
    f.close()
    NVD_API_KEY = get_token()



if __name__ == "__main__":
    init()

    components = recolector()

    system_report(components)

    print(f"Análisis finalizado, puede consultar los resultados en el fichero {filename}")