import subprocess
import os
import sys
import time

VENV_PYTHON = os.path.join(os.getcwd(), "venv", "Scripts", "python.exe")

def run_script(script_name):
    print(f"\n>>> RUNNING {script_name}...")
    result = subprocess.run([VENV_PYTHON, script_name], capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("ERRORS:")
        print(result.stderr)
    return "OK" in result.stdout

if __name__ == "__main__":
    scripts = ["run_p2p_test.py", "run_offline_test.py", "run_cs_ratchet_test.py"]
    results = {}
    
    for s in scripts:
        if os.path.exists(s):
            results[s] = run_script(s)
            time.sleep(2)
        else:
            print(f"[!] Script {s} not found.")

    print("\n" + "="*30)
    print("FINAL TEST SUMMARY")
    print("="*30)
    for s, res in results.items():
        status = "PASSED" if res else "FAILED"
        print(f"{s:25} : {status}")
    print("="*30)
