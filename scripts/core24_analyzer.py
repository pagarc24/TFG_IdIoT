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
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            shell=True,
            env=env,
            timeout=timeout_seconds # Timeout just in case something gets stuck
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except FileNotFoundError:
        return "", f"Comando '{command.split()[0]}' no encontrado.", 127
    except subprocess.TimeoutExpired:
        # El comando excedió el tiempo máximo, se termina y se devuelve un error específico
        return "", f"El comando '{command}' excedió el tiempo de espera de {timeout_seconds} segundos.", 1
    except Exception as e:
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
    # Redirige stdout a un objeto StringIO para capturar la salida de consola para el archivo TXT
    original_stdout = sys.stdout
    string_buffer = io.StringIO()
    sys.stdout = string_buffer

    print(f"--- Information for core24 Snap ---")

    core24_version, core24_revision, core24_path = get_core24_info()

    if not core24_path:
        print("Error: Could not find core24 snap information. Is Ubuntu Core running?")
        sys.stdout = original_stdout # Restaurar stdout
        print(string_buffer.getvalue()) # Print captured error to console
        return

    print(f"Core24 Snap Version: {core24_version}")
    print(f"Core24 Snap Revision: {core24_revision}")
    print(f"Core24 Snap Path: {core24_path}")
    print(f"\nNote: All binaries within this path are part of this specific core24 snap version.")
    print(f"Their individual 'versions' are ultimately tied to this snap's version.")
    print("-" * 50)

    bin_path = os.path.join(core24_path, "usr", "bin")
    if not os.path.isdir(bin_path):
        print(f"Error: Directory {bin_path} not found.")
        sys.stdout = original_stdout # Restore stdout
        print(string_buffer.getvalue()) # Print captured error to console
        return

    executables = []
    try:
        for filename in os.listdir(bin_path):
            full_path = os.path.join(bin_path, filename)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                executables.append(filename)
        executables.sort() # Para salida consistente
    except Exception as e:
        print(f"Error listing executables in {bin_path}: {e}")
        sys.stdout = original_stdout # Restore stdout
        print(string_buffer.getvalue()) # Print captured error to console
        return

    total_executables = len(executables)
    versions_found_count = 0
    versions_not_found_count = 0

    print(f"\n--- Attempting to query versions for {total_executables} executables in {bin_path} ---")
    print("(Note: Output can be verbose and parsing is heuristic)")

    # ...existing code...

    for i, exe in enumerate(executables):
        # Imprimir progreso en consola (también capturado en el buffer)
        print(f"[{i+1}/{total_executables}] Processing: {exe}...")

        full_exe_path = os.path.join(bin_path, exe)
        version_output = "N/A"
        version_source = "Not Found"
        error_message = "" # Para guardar errores específicos como timeout

        # Probar flags comunes de versión
        for flag in ["--version", "-V" ,"-v"]:
            stdout, stderr, returncode = run_command(f"{full_exe_path} {flag}", path_env=bin_path, timeout_seconds=COMMAND_TIMEOUT_SECONDS)

            # Check for timeout specifically or other critical errors
            if "timed out" in stderr or "Command not found" in stderr:
                error_message = stderr
                break # No point in trying other flags if it timed out or wasn't found

            output = stdout if stdout else stderr # Sometimes output is on stderr

            if returncode == 0 and output:
                version_output = output.strip()
                version_source = f"'{flag}' flag"
                break # Found a version, move to next executable
            elif returncode != 0:
                # If non-zero, but not a recognized "bad flag" error, capture it.
                # This could be a permission denied, or other unexpected error.
                if "unrecognized option" not in stderr.lower() and "invalid option" not in stderr.lower() and "usage" not in stderr.lower():
                    error_message = stderr
                # Else, it was probably just a normal "this flag doesn't exist" error, which is fine.

        # Decidir si se encontró la versión o no para el resumen
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


        # ...existing code...

        print(f"Executable: {exe}")
        # For console/TXT, show only the first line of version or error for brevity
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

    # Restore original stdout so further prints go to console
    sys.stdout = original_stdout
    # Also print the captured output to the console directly
    captured_output = string_buffer.getvalue()
    print(captured_output)


if __name__ == "__main__":
    main()