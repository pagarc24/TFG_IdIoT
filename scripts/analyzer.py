import requests
import subprocess
import datetime
import distro
import sys
import os
import zipfile
import io
import xml.etree.ElementTree as ET
import re

# Timeout time established for commands that wait for response
COMMAND_TIMEOUT_SECONDS = 0.5

# Configutation of API requests
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# API key for NVD API access
NVD_API_KEY = "ENTER_API"

REPORT_FILENAME = "system_analysis.txt"

HIGHLIGHT_REPORT = ''


N_COMPONENTS = 0
N_VULNERABILITIES = 0
N_VULNERABILITIES_HIGHLIGHTED = 0
EXPLORED_CPES = set()

CWE_DICT = {}

SOURCE_VULS = {}

def pacman_list():
    try:
        paquetes_pacman = []
        process = subprocess.run(['pacman', '-Q'], stdout=subprocess.PIPE, text=True, stderr=subprocess.DEVNULL)
        out = process.stdout.strip().split('\n')
        for paquete in out:
            if not paquete:
                continue

            carac = paquete.split(maxsplit=1)
            if len(carac) >= 2:
                name = carac[0]
                version = carac[1]
                publisher = "*" 
                cpe = cpe_constructor(name, version, publisher)

                paquetes_pacman.append({
                    'name': name,
                    'version': version,
                    'publisher': publisher,
                    'cpe': cpe,
                    'source': 'pacman'
                })
        return paquetes_pacman
    except:
        return []

def apt_list():
    try:
        paquetes_apt = []
        process = subprocess.run(['apt', 'list', '--installed'], capture_output=True, text=True)
        out = process.stdout.strip().split('\n')[1:]
        for paquete in out:
            if '/' not in paquete:
                continue

            carac = paquete.split(maxsplit=1)
            if len(carac) >= 2:
                name = carac[0].split('/')[0]
                version = carac[1].split()[0]
                publisher = "*" # info not available from apt list
                cpe = cpe_constructor(name, version, publisher)

                paquetes_apt.append({
                    'name': name,
                    'version': version,
                    'publisher': publisher,
                    'cpe': cpe,
                    'source': 'apt'
                })
        return paquetes_apt
    except:
        return []

def dpkg_list():
    try:
        paquetes_dpkg = []
        process = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
        out = process.stdout.strip().split('\n')[5:]

        for paquete in out:
            if not paquete.startswith('ii'):# dpkg -l starts with ii when the package is installed
                continue

            carac = paquete.split(maxsplit=4)
            if len(carac) >= 3:
                name = carac[1]
                version = carac[2]
                publisher = "*"  # info not available from dpkg -l
                cpe = cpe_constructor(name, version, publisher)

                paquetes_dpkg.append({
                    'name': name,
                    'version': version,
                    'publisher': publisher,
                    'cpe': cpe,
                    'source': 'dpkg'
                })
        return paquetes_dpkg
    except:
        return []

def snap_list():
    try:
        paquetes_snap = []
        process = subprocess.run(['snap', 'list'], capture_output=True, text=True)
        out = process.stdout.strip().split('\n')[1:]#Column's name
        
        for paquete in out:
            carac = paquete.split(maxsplit=5)
            if len(carac) >= 5:
                name = carac[0]
                version = carac[1]
                publisher = carac[4].replace("**","")
                cpe = cpe_constructor(name,version,publisher)
                paquetes_snap.append({
                    'name': name,
                    'version': version,
                    'publisher': publisher,
                    'cpe': cpe,
                    'source': 'snap'
                })
        return paquetes_snap
    except:
        return []
    
def get_executables(bin_path):
    executables = []
    try:
        for filename in os.listdir(bin_path):
            full_path = os.path.join(bin_path, filename)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                executables.append(filename)
    except Exception as e:
        print(f"Error listing executables in {bin_path}: {e}")
        return
    return executables
    

def executables_list(source="/usr"):
    try:
        executables_return = []
        executables_found = []

        find_command = ["sudo", "find", source, "-type", "d", "-name", "bin"]
        
        res = subprocess.run(find_command, capture_output=True, text=True, check=True)
        bin_paths = res.stdout.strip().split('\n')
        bin_paths = [path for path in bin_paths if "share" not in path.split(os.sep)]

        for bin_path in bin_paths:
            executables_found = get_executables(bin_path)
            versions_found_count = 0
            versions_not_found_count = 0
            for exe in executables_found:
                full_exe_path = os.path.join(bin_path, exe)
                version_output = ""
                error_msg = ""

                for flag in ["--version", "-V"]:
                    stdout, stderr, returncode = run_command([full_exe_path, flag], timeout_seconds=COMMAND_TIMEOUT_SECONDS)

                    if "timed out" in stderr or "Command not found" in stderr:
                        error_msg = stderr
                        break

                    output = stdout if stdout else stderr
                    if returncode == 0 and output:
                        version_output = output.strip()
                        break
                    elif returncode != 0:
                        if "unrecognized option" not in stderr.lower() and "invalid option" not in stderr.lower() and "usage" not in stderr.lower():
                            error_msg = stderr

                if version_output:
                    name, version = parse_version_output(exe, version_output)
                    if version != "N/A":
                        versions_found_count += 1
                    else:
                        versions_not_found_count += 1
                elif error_msg:
                    version_output = f"ERROR: {error_msg}"
                    name, version = parse_version_output(exe, version_output)
                    if version != "N/A":
                        versions_found_count += 1
                    else:
                        versions_not_found_count += 1
                else:
                    name = "N/A"
                    version = "N/A"
                    versions_not_found_count += 1
                    version_output = "N/A (No version flag responded)"

                if name != "N/A" and version != "N/A":
                    cpe = cpe_constructor(name.lower() ,version.lower() , "*")
                    executables_return.append({
                        'name': name.lower(),
                        'version': version.lower(),
                        'publisher': "*",
                        'cpe': cpe,
                        'source': bin_path
                    })
            return executables_return
    except:
        return []

def cpe_constructor(name, version, publisher):
    CPE_NAME="cpe:2.3"
    CPE_PART="a" #Application
    CPE_VENDOR=publisher
    CPE_PRODUCT=name
    CPE_PRODUCT_VERSION=version

    res = CPE_NAME+":"+CPE_PART+":"+CPE_VENDOR+":"+CPE_PRODUCT+":"+CPE_PRODUCT_VERSION
    # Next wildcards -> [update]:[edition]:[language]:[sw_edition]:[target_sw]:[target_hw]:[other]
    res = res + ":*:*:*:*:*:*:*"

    return res

def run_command(command_list, timeout_seconds=COMMAND_TIMEOUT_SECONDS):
    try:
        result = subprocess.run(command_list, capture_output=True, 
            text=True, check=False, env=os.environ.copy(), timeout=timeout_seconds
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except FileNotFoundError:
        return "", f"Command '{command_list[0]}' not found.", 127
    except subprocess.TimeoutExpired:
        command_str = " ".join(command_list)
        return "", f"The command '{command_str}' exceeded the timeout of {timeout_seconds} seconds.", 1
    except Exception as e:
        command_str = " ".join(command_list)
        return "", f"Error executing the command '{command_str}': {e}", 1

def get_snap_package_info(name):
    output, _, code = run_command(["snap", "list", name])
    if code != 0:
        return None, None, None
    lines = output.splitlines()
    if len(lines) > 1:
        parts = lines[1].split()
        if len(parts) >= 3:
            version, revision = parts[1], parts[2]
            return version, revision, f"/snap/{name}/{revision}"
    return None, None, None

def parse_version_output(exe_name, version_string):
    name = "N/A"
    version = "N/A"

    match = re.match(r'([a-zA-Z0-9]+)_([\d\.]+[a-z]*[\d]*)', version_string)
    if match:
        name = match.group(1)
        version = match.group(2)
        return name, version

    match = re.search(r'\((.+)\)\s+([\d\.]+[a-z]*[\d]*+)', version_string)
    if match:
        name = match.group(1).strip()
        version = match.group(2)
        return name, version
    
    match = re.search(r'from (.+?)\s+([\d\.]+)', version_string)
    if match:
        name = match.group(1).strip()
        version = match.group(2)
        return name, version
        
    match = re.search(r'^(.+?),\s+version\s+([\d\.]+)', version_string)
    if match:
        name = match.group(1).strip()
        version = match.group(2)
        return name, version
    
    if version_string.startswith("ERROR:"):
        match = re.search(r'Version ([\d\.]+)$', version_string)
        if match:
            version = match.group(1)
            name = "N/A"
        return name, version

    match = re.search(r'(\d+\.\d+(\.\d+)?(-[\w\d]+)?)', version_string)
    if match:
        name = exe_name
        version = match.group(1)
        return name, version

    return "N/A", "N/A"

def cpe_search(cpe):
    headers = {}
    if NVD_API_KEY is not None and NVD_API_KEY != "ENTER_API":
        headers['apiKey'] = NVD_API_KEY

    params={'virtualMatchString': cpe}

    response = requests.get(NVD_API_BASE_URL, headers=headers, params=params)
    return response.json() if 200<=response.status_code<300 else None

def collector():# Collects name, version and publisher of diferent components of different package managers

    msg = '========PACKAGES========\n'

    print("Discovering all the different components that make up the system")

    components=[]

    snap_components = snap_list()
    components.extend(snap_components)
    msg += f"- Number of snap-type packages: {len(snap_components)}\n"

    dpkg_components = dpkg_list()
    components.extend(dpkg_components)
    msg += f"- Number of dpkg-type packages: {len(dpkg_components)}\n"

    apt_components = apt_list()
    components.extend(apt_components)
    msg += f"- Number of apt-type packages: {len(apt_components)}\n"

    pacman_components = pacman_list()
    components.extend(pacman_components)
    msg += f"- Number of pacman-type packages: {len(pacman_components)}\n"

    for i in range(len(snap_components)):
        e = snap_components[i]
        package_name = e.get('name')
        _, _, snap_package_path = get_snap_package_info(package_name)
        snap_package_components = executables_list(snap_package_path)
        components.extend(snap_package_components)
        msg += f"- Number of {package_name} executables: {len(snap_package_components)}\n"

    executable_components = executables_list()
    components.extend(executable_components)
    msg += f"- Number of /usr/bin/ executables: {len(executable_components)}\n"


    msg += '========================\n'
    f = open(REPORT_FILENAME, "a")
    f.write(msg)
    f.write("\n")
    f.close()

    return components

def get_token():
    api_key_file = "./api_keys/nvd_api_key"
    try:
        with open(api_key_file, 'r', encoding='utf-8') as file:
            token = file.read()
        return token
    except Exception as e:
        return NVD_API_KEY

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
    vector = data['vectorString']
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
    report += f"\t- Vector: {vectorstring}\n"

    cwe = data['weaknesses'][0]['description'][0]['value']
    cwe_string = cwe_transform(cwe)
    report += f"\t- {cwe_string}\n"

    report += f"\n{parse_description(data['descriptions'])}\n"

    to_highlight, criteria = must_be_highlighted(score_category, vectorstring, cwe)
    if to_highlight:
        report += f"******HIGHLIGHT CRITERIA******\n{criteria}\n"
        HIGHLIGHT_REPORT += report
        N_VULNERABILITIES_HIGHLIGHTED += 1
        report = "********ATTENTION********\n"+report+"*************************\n"

    return report

def cwe_transform(data):
    return f"{data}: {CWE_DICT[data]}" if data in CWE_DICT else data

def must_be_highlighted(score_category, vectorstring, cwe):
    to_highlight = False
    criteria = ''

    #Score Category Criteria
    if score_category == "CRITICAL":
        to_highlight = True
        criteria += '\t- Critical Category\n'

    #Vector String Criteria
    if vectorstring != '':
        vector_dict = {str(i.split(':')[0]): str(i.split(':')[1]) for i in vectorstring.split("/")}

        if 'AV' in vector_dict and vector_dict['AV'] == 'N':
            to_highlight = True
            criteria += '\t- Remotely exploitable\n'
        if 'AC' in vector_dict and vector_dict['AC'] == 'L':
            to_highlight = True
            criteria += '\t- Low complexity access\n'
        
    #CWE Criteria
    #Following https://cwe.mitre.org/top25/ (2024), we choose the top 5 dangerous CWE
    if cwe in ['CWE-79', 'CWE-787', 'CWE-89', 'CWE-352', 'CWE-22']:
        to_highlight = True
        criteria += '\t- The CWE associated with this vulnerability is in the top 5 (2024) most dangerous CWE\n'

    return to_highlight, criteria

def component_analysis(component):
    global N_VULNERABILITIES
    global SOURCE_VULS

    analysis = f"\t{component['name']}\n"
    analysis += f"- Vendor: {component['publisher']}\n"
    analysis += f"- Version: {component['version']}\n"

    vuls = cpe_search(component['cpe'])
    nres = 0 if vuls is None or 'resultsPerPage' not in vuls else vuls['resultsPerPage']

    if vuls is None:
        analysis += "Error communicating with the API\n"
    elif nres <= 0:
        analysis += "No vulnerabilities found for this component\n"
    else:
        analysis += f"- Number of vulnerabilities: {nres}\n"
        vuls = vuls['vulnerabilities']
        nvuls = len(vuls)
        N_VULNERABILITIES += nvuls
        source = component['source']
        SOURCE_VULS[source] = SOURCE_VULS.get(source, 0) + nvuls
        for v in vuls:
            analysis += f"\n{vulnerability_report(v)}\n"
    return analysis

def system_report(components):
    global N_COMPONENTS
    global EXPLORED_CPES

    f = open(REPORT_FILENAME, 'a')
    N_COMPONENTS = len(components)
    if N_COMPONENTS <= 0:
        msg = "No components were detected for analysis on this system"
        print(msg)
        f.write(f"{msg}\n")
    else:
        for i in range(N_COMPONENTS):
            e = components[i]
            cpe_string = e.get('cpe')
            if cpe_string not in EXPLORED_CPES:
                analysis = f"{component_analysis(e)}\n"
                f.write(analysis)
                loading_bar(i+1, N_COMPONENTS, 'Analyzing components', 'Completed')
                EXPLORED_CPES.add(cpe_string)
    f.close()

def loading_bar(it, total, pre, suf):
    percent = 100*(it/float(total))
    filled_length = int(40 * it // total)
    fill = '#'
    bar = fill * filled_length + '-' * (40 - filled_length)
    sys.stdout.write(f'\r{pre} |{bar}| {percent:.1f}% {suf}')
    sys.stdout.flush()
    if it == total:
        print()

def init_cwe_dict():
    global CWE_DICT

    CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_v4.12.xml.zip"
    CWE_DIR = "cwe_data"
    CWE_XML_PATH = os.path.join(CWE_DIR, "cwec_v4.12.xml")

    if not os.path.exists(CWE_XML_PATH):
        try:
            os.makedirs(CWE_DIR, exist_ok=True)
            response = requests.get(CWE_ZIP_URL)
            response.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                z.extractall(CWE_DIR)
        except Exception as e:
            return

    try:
        tree = ET.parse(CWE_XML_PATH)
        root = tree.getroot()
        ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}

        for weakness in root.findall('.//cwe:Weakness', ns):
            cwe_id = f"CWE-{weakness.attrib.get('ID')}"
            name = weakness.attrib.get('Name')
            if cwe_id and name:
                CWE_DICT[cwe_id] = name
    except Exception as e:
        return

def init():
    global NVD_API_KEY

    msg = f"{distro.name()} {distro.version()}\n"
    msg += f"Analyzing the system on {datetime.datetime.now()}"
    print(msg)

    init_cwe_dict()

    f = open(REPORT_FILENAME, "w")
    f.write(msg)
    f.write("\n\n")
    f.close()
    NVD_API_KEY = get_token()

if __name__ == "__main__":
    duration = datetime.datetime.now()
    init()

    components = collector()

    system_report(components)

    if HIGHLIGHT_REPORT != '':
        h_msg = "\n=========================\n"
        h_msg += f"ATTENTION: Some detected vulnerabilities meet critical criteria for this system. To ensure its security, they must be reviewed.\n"
        h_msg += "************HIGHLIGHT REPORT************\n"
        h_msg += HIGHLIGHT_REPORT
        h_msg += "=========================\n"
        print(h_msg)
    
    source_vuls_report = ''
    for source, n in SOURCE_VULS.items():
        source_vuls_report += f"\t- Vulnerabilities detected from {source}: {n}\n"
    
    if source_vuls_report != '':
        source_vuls_report = source_vuls_report[:-1]

    duration=datetime.datetime.now()-duration
    total_segundos = duration.total_seconds()
    min, sec = divmod(total_segundos, 60)
    min = int(min)
    sec = f"{sec:2.3f}"
    print(f"Analysis completed, you can check the results in the file {REPORT_FILENAME}")
    summary = f"""\nSUMMARY:
    - Analyzed components: {N_COMPONENTS}
    - Detected vulnerabilities: {N_VULNERABILITIES}
    - Number of significant detected vulnerabilities: {N_VULNERABILITIES_HIGHLIGHTED}
    {source_vuls_report}
    - Execution time: {min} minutes and {sec} seconds"""
    print(summary)