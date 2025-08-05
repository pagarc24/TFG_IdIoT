import subprocess
import os
import io
import sys
import re

# Timeout time established for commands that wait for response
COMMAND_TIMEOUT_SECONDS = 0.5

# ret = stdout, stderr, ret code 
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

# ret = version, revision, path
def get_core24_info():
    output, _, code = run_command(["snap", "list", "core24"])
    if code != 0:
        return None, None, None
    lines = output.splitlines()
    if len(lines) > 1:
        parts = lines[1].split()
        if len(parts) >= 3:
            version, revision = parts[1], parts[2]
            return version, revision, f"/snap/core24/{revision}"
    return None, None, None

# ret = name, version
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
            name = "N/A" # Vendor is unknown in this case
        return name, version

    match = re.search(r'(\d+\.\d+(\.\d+)?(-[\w\d]+)?)', version_string)
    if match:
        name = exe_name
        version = match.group(1)
        return name, version

    return "N/A", "N/A"

def executable_versions():
    core24_version, core24_revision, core24_path = get_core24_info()
    bin_path = os.path.join(core24_path, "usr", "bin")
    if not core24_path:
        print("Error: Could not find core24 snap information. Is Ubuntu Core running?")
        return
    
    print(f"CORE 24 VER: {core24_version} - REV: {core24_revision} - PATH {core24_path}")
    executables = []
    try:
        for filename in os.listdir(bin_path):
            full_path = os.path.join(bin_path, filename)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                executables.append(filename)
    except Exception as e:
        print(f"Error listing executables in {bin_path}: {e}")
        return

    total_executables = len(executables)
    versions_found_count = 0
    versions_not_found_count = 0

    for exe in executables:
        full_exe_path = os.path.join(bin_path, exe)
        version_output = ""
        version_source = "Not Found"
        error_msg = ""

        for flag in ["--version", "-V"]:
            stdout, stderr, returncode = run_command([full_exe_path, flag], timeout_seconds=COMMAND_TIMEOUT_SECONDS)

            if "timed out" in stderr or "Command not found" in stderr:
                error_msg = stderr
                break

            ## as version is diagnostic, sent on stderr
            output = stdout if stdout else stderr
            if returncode == 0 and output:
                version_output = output.strip()
                version_source = f"'{flag}' flag"
                break
            elif returncode != 0:
                if "unrecognized option" not in stderr.lower() and "invalid option" not in stderr.lower() and "usage" not in stderr.lower():
                    error_msg = stderr

        if version_output:
            vendor_name, version_number = parse_version_output(exe, version_output)
            if version_number != "N/A":
                versions_found_count += 1
            else:
                versions_not_found_count += 1
        elif error_msg:
            version_output = f"ERROR: {error_msg}"
            version_source = "Error"
            vendor_name, version_number = parse_version_output(exe, version_output)
            if version_number != "N/A":
                versions_found_count += 1
            else:
                versions_not_found_count += 1
        else:
            vendor_name = "N/A"
            version_number = "N/A"
            versions_not_found_count += 1
            version_output = "N/A (No version flag responded)"

        print(f"{'Executable:':<15} {exe}")
        print(f"{'  Vendor:':<15} {vendor_name}")
        print(f"{'  Version:':<15} {version_number}")
        print(f"{'  Source:':<15} {version_source}")
        print("-" * 30)

    print("\n--- Summary ---")
    print(f"Total executables processed: {total_executables}")
    print(f"Versions found: {versions_found_count}")
    print(f"Versions not found (or errors): {versions_not_found_count}")
    
    percentage_not_found = (versions_not_found_count / total_executables * 100) if total_executables > 0 else 0
    print(f"Percentage of versions not found: {percentage_not_found:.2f}%")
    print("\n--- End of Report ---")

def main():
    executable_versions()
    
if __name__ == "__main__":
    main()