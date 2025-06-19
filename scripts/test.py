import requests
import time
import subprocess
import datetime
import distro

## Configutation of API requests
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# API key for NVD API access
NVD_API_KEY = "ENTER_API"

REPORT_FILENAME = "system_analysis"

HIGHLIGHT_REPORT = ''

N_COMPONENTS = 0
N_VULNERABILITIES = 0
N_VULNERABILITIES_HIGHLIGHTED = 0

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

    params={'virtualMatchString': cpe}

    response = requests.get(NVD_API_BASE_URL, headers=headers, params=params)
    return response.json() if 200<=response.status_code<300 else None

def collector():# Se encarga de recoger nombre, version y fabricante/publisher/vendor de distintos gestores
    components=[]
    components.extend(snap_list())
    return components

def get_token():
    api_key_file = "../api_keys/nvd_api_key"
    with open(api_key_file, 'r', encoding='utf-8') as file:
        token = file.read()
    return token 

def parse_description(data, lang='en'):
    desc = ''

    elem = None
    for e in data:
        if e['lang']==lang:
            elem=e

    if elem==None:# If not found, first description
        elem = data[0]
        desc += f'(description in "{lang}" not found, "{elem["lang"]}" selected)\n'

    desc += f'{elem["value"]}\n'
    return desc

def parse_metrics(data):
    metrics = {'cvssMetricV40': '4.0', 'cvssMetricV31': '3.1', 'cvssMetricV30': '3.0', 'cvssMetricV2': '2', 'cvssMetricV1': '1'}
    cvss_metric = ''
    version = ''

    for m_k, m_v in metrics.items():
        if m_k in data:
            cvss_metric = m_k
            version = m_v
            break

    data = data[cvss_metric][0]['cvssData']
    score = float(data['baseScore'])
    vector = {'value': data['vectorString']}
    score_category = data['baseSeverity'] if 'baseSeverity' in data else 'N/A'
    return score, version, vector, score_category

def vulnerability_report(vulnerability):
    global HIGHLIGHT_REPORT
    global N_VULNERABILITIES_HIGHLIGHTED

    report = ''

    data = vulnerability['cve']

    report += f"*** {data['id']} ***\n"

    fecha, hora = data['published'].split('T')
    report+=f"\t- Published: {fecha} {hora}\n"
    fecha, hora = data['lastModified'].split('T')
    report+=f"\t- Last modified: {fecha} {hora}\n"

    score, score_version, vectorstring, score_category = parse_metrics(data['metrics'])

    report += f"\t- Score: {score} ({score_category}) - CVSS {score_version}\n"
    report += f"\t- Vector: {vectorstring['value']}\n"

    cwe = data['weaknesses'][0]['description'][0]['value']
    report += f"\t- CWE: {cwe}\n"

    report += f"\n{parse_description(data['descriptions'])}\n"

    to_highlight, criteria = must_be_highlighted(score_category, vectorstring)
    if to_highlight:
        report += f"******HIGHLIGHT CRITERIA******\n{criteria}\n"
        HIGHLIGHT_REPORT += report
        N_VULNERABILITIES_HIGHLIGHTED += 1
        report = "********ATTENTION********\n"+report+"*************************\n"

    return report

def must_be_highlighted(score_category, vectorstring):
    to_highlight = False
    criteria = ''

    if score_category == "CRITICAL":
        to_highlight = True
        criteria += '\t- Critical Category\n'
    elif score_category == "HIGH":
        to_highlight = True
        criteria += '\t- High Category\n'

    return to_highlight, criteria

def component_analysis(component):
    global N_VULNERABILITIES

    analysis = f"\t{component['name']}\n"
    analysis += f"- Vendor: {component['publisher']}\n"
    analysis += f"- Version: {component['version']}\n"

    vuls = cpe_search(component['cpe'])
    nres = vuls['resultsPerPage']

    if vuls is None:
        analysis += "Error communicating with the API\n"
    elif nres <= 0:
        analysis += "No vulnerabilities found for this component\n"
    else:
        analysis += f"- Number of vulnerabilities: {nres}\n"
        vuls = vuls['vulnerabilities']
        N_VULNERABILITIES += len(vuls)
        for v in vuls:
            analysis += f"\n{vulnerability_report(v)}\n"
    return analysis

def system_report(components):
    global N_COMPONENTS

    f = open(REPORT_FILENAME, 'a')
    N_COMPONENTS = len(components)
    if N_COMPONENTS <= 0:
        msg = "No components were detected for analysis on this system"
        print(msg)
        f.write(f"{msg}\n")
    else:
        for e in components:
            analysis = f"{component_analysis(e)}\n"
            f.write(analysis)
    f.close()

def init():
    global NVD_API_KEY

    msg = f"{distro.name()} {distro.version()}\n"
    msg += f"Analyzing the system on {datetime.datetime.now()}"
    print(msg)
    f = open(REPORT_FILENAME, "w")
    f.write(msg)
    f.write("\n\n")
    f.close()
    NVD_API_KEY = get_token()

if __name__ == "__main__":
    init()

    components = collector()

    #TODO COMENTAR
    #components = []
    components.append({'name': 'MINA_SSHD', 'version': '1', 'publisher':'apache','cpe':'cpe:2.3:a:apache:mina_sshd:-:*:*:*:*:*:*:*'})
    components.append({'name': 'OPENSSH', 'version': '1.5', 'publisher': 'OPENBSD','cpe': 'cpe:2.3:a:openbsd:openssh:1.5:*:*:*:*:*:*:*'})
    system_report(components)

    if HIGHLIGHT_REPORT != '':
        h_msg = "\n=========================\n"
        h_msg += f"ATTENTION: Some detected vulnerabilities meet critical criteria for this system. To ensure its security, they must be reviewed.\n"
        h_msg += "************HIGHLIGHT REPORT************\n"
        h_msg += HIGHLIGHT_REPORT
        h_msg += "=========================\n"
        print(h_msg)
    
    print(f"Analysis completed, you can check the results in the file {REPORT_FILENAME}")
    summary = f"""\nSUMMARY:
    - Analyzed components: {N_COMPONENTS}
    - Detected vulnerabilities: {N_VULNERABILITIES}
    - Detected critical vulnerabilities: {N_VULNERABILITIES_HIGHLIGHTED}"""
    print(summary)