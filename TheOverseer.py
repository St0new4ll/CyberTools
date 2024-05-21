import ast
import argparse
import os
import stat

allowed_imports = {'numpy', 'tensorflow', 'torch'}

def scan_script(file_path):
    with open(file_path, 'r') as file:
        tree = ast.parse(file.read(), filename=file_path)
    
    disallowed_imports = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in allowed_imports:
                    disallowed_imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module not in allowed_imports:
                disallowed_imports.append(node.module)
    
    return disallowed_imports

def make_read_only(file_path):
    os.chmod(file_path, stat.S_IREAD)

def log_disallowed_imports(file_path, disallowed_imports):
    with open("disallowed_imports_log.txt", "a") as log_file:
        log_file.write(f'"{file_path}" : {", ".join(disallowed_imports)}\n')

def main():
    parser = argparse.ArgumentParser(description="Scan Python script for disallowed imports and change permissions if any are found.")
    parser.add_argument("file", help="The path to the Python script to scan.")
    args = parser.parse_args()
    
    disallowed_imports = scan_script(args.file)
    
    if disallowed_imports:
        make_read_only(args.file)
        log_disallowed_imports(args.file, disallowed_imports)
        print(f"Disallowed imports found in '{args.file}'. Permissions have been changed to read-only and logged.")
    else:
        print("No disallowed imports found. The script is safe.")

if __name__ == "__main__":
    main()
