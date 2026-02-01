import pefile
import json
import subprocess
import math
import time
import os
import sys

suspicious_sections = ['.textbss', '.dataenc', '.upx0', '.upx1', '.aspack', '.petite', '.themida', '.vmp0', '.vmp1', 'upx', '.xyz', '.packed', '.ab', '.secret', '.evil', '.payload']
suspicious_api_calls = [
    # Process Injection / Memory Manipulation
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'WriteProcessMemory',
    'CreateRemoteThread', 'LoadLibrary', 'GetProcAddress', 'HeapAlloc',
    'HeapFree', 'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',
    'RegSetValueEx', 'CreateServiceW', 'WinExec', 'WinHttpOpen',
    'InternetConnect', 'ShellExecuteA', 'system', 'LoadLibraryA',
    'NtWriteVirtualMemory', 'NtCreateThreadEx', 'NtQueueApcThread',
    'QueueUserAPC', 'RtlMoveMemory', 'CreateProcessA', 'CreateProcessW',
    'CreateProcessInternalW', 'OpenProcess', 'SuspendThread', 'ResumeThread',
    'SetThreadContext', 'GetThreadContext', 'MapViewOfFile',
    'UnmapViewOfFile', 'CreateFileMapping', 'VirtualQuery', 'VirtualQueryEx',
    'GetModuleHandle', 'GetModuleHandleA', 'GetModuleHandleW',
    # Privilege Escalation / Token Manipulation
    'OpenProcessToken', 'LookupPrivilegeValue', 'AdjustTokenPrivileges',
    'ImpersonateLoggedOnUser', 'DuplicateToken', 'DuplicateTokenEx',
    'SetThreadToken', 'RevertToSelf',
    # Persistence
    'RegCreateKeyEx', 'RegOpenKeyEx', 'RegDeleteKey', 'RegSetValue',
    'RegQueryValueEx', 'CoCreateInstance', 'StartServiceA', 'StartServiceW',
    'ChangeServiceConfig', 'WriteProfileString', 'SHSetValue',
    # Networking / C2
    'WinHttpConnect', 'WinHttpSendRequest', 'WinHttpReceiveResponse',
    'InternetOpenA', 'InternetOpenW', 'InternetOpenUrl', 'InternetReadFile',
    'WSAStartup', 'socket', 'connect', 'send', 'recv', 'gethostbyname',
    'DnsQuery', 'URLDownloadToFile',
    # Anti-Debugging / Anti-Analysis
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess', 'NtQuerySystemInformation',
    'GetTickCount', 'QueryPerformanceCounter', 'OutputDebugString',
    'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
    'Thread32First', 'Thread32Next',
    # File System Manipulation
    'CreateFileA', 'CreateFileW', 'WriteFile', 'DeleteFile', 'CopyFile',
    'MoveFileEx', 'SetFileAttributes', 'GetTempPath', 'GetTempFileName',
    # Crypto / Obfuscation
    'CryptAcquireContext', 'CryptImportKey', 'CryptDecrypt', 'CryptEncrypt',
    'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenRandom',
    # Direct NT Syscalls / Low-level
    'NtOpenProcess', 'NtOpenThread', 'NtOpenFile', 'NtCreateFile', 'NtClose',
    'NtDelayExecution', 'NtUnmapViewOfSection'
]
output_data = {}

subsystem_map = {
        1: "IMAGE_SUBSYSTEM_NATIVE",
        2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
        3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
        5: "IMAGE_SUBSYSTEM_OS2_CUI",
        7: "IMAGE_SUBSYSTEM_POSIX_CUI",
        9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
        10: "IMAGE_SUBSYSTEM_EFI_APPLICATION"
}

suspicious_strings = ['powershell.exe', 'cmd.exe', 'wscript', 'csript', 'vmware', 'vbox', 'virtualbox', 'qemu', 'schtasks', 'reg add', 'reg create']

def signtool_verify(path):
    result = subprocess.run(
        ["C:\\Users\\byL0r3t\\Desktop\\pythonProjects\\windows-file-analyzer\\SignTool\\signtool.exe", "verify", "/pa", path],
        capture_output=True,
        text=True
    )
    #print("STDOUT:", result.stdout)
    #print("STDERR:", result.stderr)
    return result.stderr.strip()

def entropy_alert(entropy, section_name):
    if entropy < 1.0:
        return {'type':'low_entropy', 'Section name': section_name, 'Reason': 'Low entropy detected', 'Severity':'Info'}
    elif 1.0 <= entropy < 4.0:
        return {'type':'moderate_entropy', 'Section name': section_name, 'Reason':'Moderate entropy detected', 'Severity':'Info'}
    elif 4.0 <= entropy < 7.0:
        return {'type':'high_entropy', 'Section name': section_name, 'Reason':'High entropy detected', 'Severity':'Medium'}
    else:
        return {'type':'very_high_entropy', 'Section name': section_name, 'Reason':'Very high entropy detected', 'Severity':'Critical'}

def calculate_entropy(data):
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    entropy = 0.0
    data_length = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / data_length
        entropy -= probability * math.log2(probability)
    return entropy

def heuristic_timestamp(timestamp):
    current_time = time.time()
    if timestamp > current_time:
        return {'type':'future_timestamp', 'Timestamp': timestamp, 'Reason':'File timestamp is in the future', 'Severity':'Medium'}
    elif timestamp < (current_time - 10 * 365 * 24 * 60 * 60):
        return {'type':'old_timestamp', 'Timestamp': timestamp, 'Reason':'File timestamp is older than 10 years', 'Severity':'Low'}
    
def external_strings(path):
    result = subprocess.run(
        ["C:\\Users\\byL0r3t\\Desktop\\pythonProjects\\windows-file-analyzer\\strings2.exe", path],
        capture_output=True,
        text=False
    )
    return result.stdout.splitlines()

def main():
    path = sys.argv[1]
    pe = pefile.PE(path)

    # Name
    output_data['Name'] = path

    # File timestamp
    timestamp = pe.FILE_HEADER.TimeDateStamp
    print(f"Timestamp: {timestamp}")
    output_data['Timestamp'] = timestamp
    heuristic_timestamp_info = heuristic_timestamp(timestamp)

    # Entry point
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print(f"Entry Point: {hex(entry_point)}")
    output_data['EntryPoint'] = hex(entry_point)

    # File Signature
    #signature = pe.DOS_HEADER.e_magic
    #print(f"File Signature: {hex(signature)}")
    #output_data['Signature'] = signature

    # Signature verification
    #verification_result = signtool_verify(path)
    #print(f"Signature Verification: {verification_result}")
    #output_data['SignatureVerification'] = verification_result


    # Subsystem type
    subsystem = pe.OPTIONAL_HEADER.Subsystem
    subsystem_str = subsystem_map.get(subsystem, "UNKNOWN")
    print(f"Subsystem: {subsystem_str} ({subsystem})")
    output_data['Subsystem'] = {'Type': subsystem_str, 'Value': subsystem}
    if subsystem == 1:
        heuristic_subsytem_is_native = {'type':'native_subsystem', 'Reason':'File uses NATIVE subsystem which is uncommon for regular applications', 'Severity':'Medium'}

    # Get strings
    strings = external_strings(path)
    new_strings = [s.decode(errors='ignore') for s in strings]
    # Suspicious strings heuristic
    heuristic_suspicious_strings = []
    for s in new_strings:
        for suspicious in suspicious_strings:
            if suspicious.lower() in s.lower():
                heuristic_suspicious_strings.append({'type':'suspicious_string', 'String': s, 'Reason':'Suspicious string detected', 'Severity':'Low'})

    isEntryPointInTextSection = 0

    # File functions
    functions_info = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            func_name = exp.name.decode() if exp.name else "N/A"
            func_address = hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
            print(f"Function: {func_name}, Address: {func_address}")
            tempFunction = {
                "Name": func_name,
                "Address": func_address
            }
            functions_info.append(tempFunction)
    else:
        print("No export directory found.")

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                func_name = imp.name.decode() if imp.name else "N/A"
                func_address = hex(imp.address)
                print(f"Imported Function: {func_name}, Address: {func_address}")
                tempFunction = {
                    "Name": func_name,
                    "Address": func_address
                }
                functions_info.append(tempFunction)


    output_data['Functions'] = functions_info

    heuristic_suspicious_api_calls = []
    for func in functions_info:
        if func['Name'] in suspicious_api_calls:
            heuristic_suspicious_api_calls.append({'type':'suspicious_api_call', 'Function name': func['Name'], 'Reason':'Suspicious API call detected', 'Severity':'High'})

    # Sections
    heuristic_unusual_sections = []
    heuristic_entropy = []
    sections_info = []
    sections_counter = 0
    for section in pe.sections:
        print(f"Section: {section.Name.decode().rstrip(chr(0))}")
        print(f"  Virtual Address: {hex(section.VirtualAddress)}")
        print(f"  Size of Raw Data: {hex(section.SizeOfRawData)}")
        print(f"  Pointer to Raw Data: {hex(section.PointerToRawData)}")
        print(f"  Characteristics: {hex(section.Characteristics)}")

        # Entropy calculation
        section_data = section.get_data()
        entropy = calculate_entropy(section_data)
        print(f" Entropy: {entropy:.4f}")

        tempSection = {
            "Name": section.Name.decode().rstrip(chr(0)),
            "VirtualAddress": hex(section.VirtualAddress),
            "SizeOfRawData": hex(section.SizeOfRawData),
            "PointerToRawData": hex(section.PointerToRawData),
            "Characteristics": hex(section.Characteristics),
            "Entropy": round(entropy, 4)
        }
        heuristic_entropy.append(entropy_alert(entropy, section.Name.decode().rstrip(chr(0))))

        sections_info.append(tempSection)

        sections_counter += 1

        # Verify if entry point is in .text section
        start = section.VirtualAddress
        end = start + section.Misc_VirtualSize
        if section.Name.decode().rstrip(chr(0)) == '.text':
            if start <= entry_point < end:
                isEntryPointInTextSection = 1
        
        # Virtual size vs raw size of a section
        ratio = section.Misc_VirtualSize / max(section.SizeOfRawData, 1)

        if ratio > 20:
            heuristic_unusual_sections.append({'type': 'size_ratio_anomaly', 'Name': section.Name.decode().rstrip(chr(0)), 'VirtualSize': section.Misc_VirtualSize, 'SizeOfRawData': section.SizeOfRawData, 'Reason': 'High virtual size to raw size ratio', 'severity': 'Critical'})

        if ratio > 10:
            heuristic_unusual_sections.append({'type': 'size_ratio_warning', 'Name': section.Name.decode().rstrip(chr(0)), 'VirtualSize': section.Misc_VirtualSize, 'SizeOfRawData': section.SizeOfRawData, 'Reason': 'Moderate virtual size to raw size ratio', 'severity': 'Medium'})

        # Suspicious section names
        if section.Name.decode().rstrip(chr(0)).lower() in suspicious_sections:
            heuristic_unusual_sections.append({'type': 'suspicious_section', 'Name': section.Name.decode().rstrip(chr(0)), 'Reason': 'Suspicious section name', 'severity': 'High'})

    output_data['Sections'] = sections_info   
    if sections_counter == 0:
        heuristic_unusual_sections.append({'type': 'no_sections', 'Reason': 'No sections found in the PE file', 'severity': 'Critical'})
    elif sections_counter > 10:
        heuristic_unusual_sections.append({'type': 'many_sections', 'Number of sections': sections_counter, 'Reason': 'Unusually high number of sections in the PE file', 'severity': 'Medium'})
    elif sections_counter < 3 and sections_counter > 0:
        heuristic_unusual_sections.append({'type': 'few_sections', 'Number of sections': sections_counter, 'Reason': 'Unusually low number of sections in the PE file', 'severity': 'Low'})

    if isEntryPointInTextSection == 0:
        heuristic_unusual_sections.append({'type': 'entry_point_anomaly', 'Reason': 'Entry point is not located in the .text section', 'severity': 'High'})

    output_data['isEntryPointInTextSection'] = isEntryPointInTextSection
    output_data['heuristics'] = {
        'timestamp': heuristic_timestamp_info,
        'unusual_sections': heuristic_unusual_sections,
        'entropy': heuristic_entropy,
        'suspicious_api_calls': heuristic_suspicious_api_calls,
        'native_subsystem': heuristic_subsytem_is_native if 'heuristic_subsytem_is_native' in locals() else None,
        'suspicious_strings': heuristic_suspicious_strings
    }

    if os.path.exists("new_data.json"):
        with open("new_data.json", "r") as f:
            try:
                existing_data = json.load(f)
            except json.JSONDecodeError:    
                existing_data = []
    else:
        existing_data = []
    existing_data.append(output_data)
    with open("new_data.json", "w") as file:
        json.dump(existing_data, file, indent=4)

if __name__ == "__main__":
    main()
 