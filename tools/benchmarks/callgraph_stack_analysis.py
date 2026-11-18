import glob
import os
import subprocess
import re

objdump_path = r"C:\Users\aadit\AppData\Roaming\xPacks\@xpack-dev-tools\arm-none-eabi-gcc\15.2.1-1.1.1\.content\bin\arm-none-eabi-objdump.exe"
elf_path = r"c:\Users\aadit\Desktop\QSAC---Microcontrollers\firmware\build-pico\qsac_firmware.elf"

# Read all .su files
base_dir = r'c:\Users\aadit\Desktop\QSAC---Microcontrollers\firmware\build-pico\CMakeFiles\qsac_firmware.dir'
su_files = glob.glob(os.path.join(base_dir, '**', '*.su'), recursive=True)

stack_sizes = {}
for sf in su_files:
    with open(sf, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            parts = line.split('\t')
            if len(parts) >= 3:
                loc = parts[0]
                bytes_num = int(parts[1])
                kind = parts[2]
                func_name = loc.split(':')[-1]
                # In case of compiler cloning/specialization (e.g. .constprop.0)
                stack_sizes[func_name] = bytes_num

# Disassemble ELF to extract call graph
cmd = [objdump_path, "-d", elf_path]
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

call_graph = {}
current_func = None

for line in proc.stdout:
    # Function header: 10001234 <func_name>:
    m_func = re.match(r'^[0-9a-fA-F]+\s+<([^>]+)>:', line)
    if m_func:
        current_func = m_func.group(1)
        if current_func not in call_graph:
            call_graph[current_func] = set()
        continue
    
    if current_func:
        # Branch/call instructions: bl or b <func_name>
        # e.g., 10001240:	f000 f810 	bl	10001264 <shake256>
        m_call = re.search(r'\b(bl|b|blx)\b\s+[0-9a-fA-F]+\s+<([^>+]+)', line)
        if m_call:
            callee = m_call.group(2)
            call_graph[current_func].add(callee)

proc.wait()

def get_stack_frame(func):
    if func in stack_sizes:
        return stack_sizes[func]
    # Check if func has suffix like .constprop
    clean = func.split('.')[0]
    if clean in stack_sizes:
        return stack_sizes[clean]
    return 0

def find_max_stack_path(func, visited=None):
    if visited is None:
        visited = set()
    if func in visited:
        return 0, [func + " (RECURSION)"]
    visited.add(func)
    
    my_frame = get_stack_frame(func)
    callees = call_graph.get(func, set())
    
    max_child_cost = 0
    max_child_path = []
    
    for c in callees:
        # Skip longjmp, abort, or external SDK functions that aren't part of normal crypto flow if needed
        cost, path = find_max_stack_path(c, visited.copy())
        if cost > max_child_cost:
            max_child_cost = cost
            max_child_path = path
            
    return my_frame + max_child_cost, [(func, my_frame)] + max_child_path

targets = [
    "pqcrystals_dilithium2_ref_signature",
    "pqcrystals_dilithium2_ref_verify",
    "pqcrystals_dilithium2_ref_keypair",
    "pqcrystals_kyber512_ref_keypair",
    "pqcrystals_kyber512_ref_enc",
    "pqcrystals_kyber512_ref_dec",
    "qsac_mldsa_sign",
    "qsac_mldsa_verify",
    "qsac_mlkem_keygen",
    "qsac_mlkem_encaps",
    "qsac_mlkem_decaps",
    "qsac_token_verify",
    "qsac_handshake_client_process_server_hello",
    "uECC_sign",
    "uECC_verify",
    "uECC_shared_secret",
    "qsac_aes256_gcm_encrypt",
    "qsac_aes256_gcm_decrypt",
    "sha3_256",
    "qsac_sha256_hash",
    "qsac_hkdf_sha256"
]

print("================ CALL GRAPH WORST-CASE PEAK STACK ANALYSIS ================")
for t in targets:
    # Check if t is in call_graph
    match = None
    for k in call_graph:
        if k == t or k.startswith(t + "."):
            match = k
            break
    if not match:
        print(f"Target '{t}' not found in ELF.")
        continue
    
    total, path = find_max_stack_path(match)
    print(f"\nTarget: {match} --> Peak Stack Depth: {total} Bytes")
    for step in path:
        if isinstance(step, tuple):
            print(f"    -> {step[0]:45s} : {step[1]:5d} bytes")
        else:
            print(f"    -> {str(step)}")
