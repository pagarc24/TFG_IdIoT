import subprocess
import os
import io
import sys

# Timeout time established, 5 seconds seems to be good
COMMAND_TIMEOUT_SECONDS = 5

def run_command(command, path_env=None, timeout_seconds=COMMAND_TIMEOUT_SECONDS):
    """
    Ejecuta un comando en la terminal y devuelve su stdout, stderr y código de retorno.
    Incluye un tiempo máximo para evitar bloqueos. Esencialmente es un wrapper para sub
    process.run()
    """
    try:
        env = os.environ.copy()
        result = subprocess.run( command, capture_output=True, text=True, check=False,
            shell=True, env=env, timeout=timeout_seconds)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except FileNotFoundError: 
        ## Error code for command not found : 127
        return "", f"Comando '{command.split()[0]}' no encontrado.", 127
    except subprocess.TimeoutExpired:
        ## Error, command timeout
        return "", f"El comando '{command}' excedió el tiempo de espera de {timeout_seconds} segundos.", 1
    except Exception as e:
        ## Other excpetion handling
        return "", f"Error ejecutando el comando '{command}': {e}", 1

def get_core24_info():
    """Return version, revision, and path for core24 snap, or None if not found."""
    output, _, code = run_command("snap list core24")
    if code != 0:
        return None, None, None
    lines = output.splitlines()
    if len(lines) > 1:
        parts = lines[1].split()
        if len(parts) >= 3:
            version, revision = parts[1], parts[2]
            return version, revision, f"/snap/core24/{revision}"
    return None, None, None

def main():
    print(f"--- Information for core24 Snap ---")

    core24_version, core24_revision, core24_path = get_core24_info()
    bin_path = os.path.join(core24_path, "usr", "bin")
    if not core24_path:
        print("Error: Could not find core24 snap information. Is Ubuntu Core running?")
        return

    print("-" * 50)
    print(f"Core24 Snap Version: {core24_version}")
    print(f"Core24 Snap Revision: {core24_revision}")
    print(f"Core24 Snap Path: {core24_path}")
    print("-" * 50)

    ## Get a list of the executables that you have access to
    executables = []
    try:
        for filename in os.listdir(bin_path):
            full_path = os.path.join(bin_path, filename)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                executables.append(filename)
    except Exception as e:
        print(f"Error listing executables in {bin_path}: {e}")
        return

    ## Get amount of available executables to make statistics later on
    total_executables = len(executables)
    versions_found_count = 0
    versions_not_found_count = 0

    print(f"\n--- Attempting to query versions for {total_executables} executables in {bin_path} ---")

    for i, exe in enumerate(executables):
        full_exe_path = os.path.join(bin_path, exe)
        version_output = "N/A"
        version_source = "Not Found"
        error_message = "" # Store customs errors like run_command timeout

        # Try common version flags
        for flag in ["--version", "-V"]:
            stdout, stderr, returncode = run_command(f"{full_exe_path} {flag}", path_env=bin_path, timeout_seconds=COMMAND_TIMEOUT_SECONDS)

            ## If one of these 2 errors, break, no point in trying with another flag
            if "timed out" in stderr or "Command not found" in stderr:
                error_message = stderr
                break

            ## Some older version send version info to stderr
            output = stdout if stdout else stderr
            ## Found a version, move to next executable
            if returncode == 0 and output:
                version_output = output.strip()
                version_source = f"'{flag}' flag"
                break
            elif returncode != 0:
                ## This could be a permission denied, or other unexpected error.
                if "unrecognized option" not in stderr.lower() and "invalid option" not in stderr.lower() and "usage" not in stderr.lower():
                    error_message = stderr

        if version_output != "N/A" and not version_output.startswith("ERROR:"):
            versions_found_count += 1
        else:
            versions_not_found_count += 1
            # If no version was found but an error occurred during attempts, set error message
            if not version_output.startswith("ERROR:") and error_message:
                 version_output = f"ERROR: {error_message}"
                 version_source = "Error"
            elif not error_message: # If still N/A and no explicit error message
                version_output = "N/A (No version flag responded)"

        print(f"Executable: {exe}")
        display_version = version_output.splitlines()[0] if version_output != "N/A" and not version_output.startswith("ERROR:") else version_output
        print(f"  Version: {display_version}")
        print(f"  Source: {version_source}")
        print("-" * 30)

    print("\n--- Summary ---")
    print(f"Total executables processed: {total_executables}")
    print(f"Versions found: {versions_found_count}")
    print(f"Versions not found (or errors): {versions_not_found_count}")
    
    percentage_not_found = (versions_not_found_count / total_executables * 100) if total_executables > 0 else 0
    print(f"Percentage of versions not found: {percentage_not_found:.2f}%")
    print("\n--- End of Report ---")

if __name__ == "__main__":
    main()
