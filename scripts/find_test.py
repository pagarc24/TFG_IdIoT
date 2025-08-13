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

def executables_list(source=None):
    try:
        executables_list = []
        executables_found = []

        find_command = ["find", source, "-type", "d", "-name", "bin"]
        
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
                    executables_list.append({
                        'name': name.lower(),
                        'version': version.lower(),
                        'publisher': "*",
                        'cpe': cpe,
                        'source': bin_path
                    })
            return executables_list
    except:
        return []

if __name__ == "__main__":

  msg = '========PACKAGES========\n'
  components=[]

  snap_components = snap_list()
  components.extend(snap_components)
  msg += f"- Number of snap-type packages: {len(snap_components)}\n"

  for i in range(len(snap_components)):
    e = snap_components[i]
    package_name = e.get('name')
    _, _, snap_package_path = get_snap_package_info(package_name)
    print(f"SEARCHING: {snap_package_path}")
    snap_package_components = executables_list(snap_package_path)
    components.extend(snap_package_components)
    msg += f"- Number of {package_name} executables: {len(snap_package_components)}\n"
