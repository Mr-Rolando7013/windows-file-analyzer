import pandas as pd
import json
from sklearn.feature_extraction.text import CountVectorizer
from scipy.sparse import hstack
import scipy.sparse as sp
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
import numpy as np
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import GridSearchCV

memory_manipulation_functions = {'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'WriteProcessMemory',
    'CreateRemoteThread', 'LoadLibrary', 'GetProcAddress', 'HeapAlloc',
    'HeapFree', 'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',
    'RegSetValueEx', 'CreateServiceW', 'WinExec', 'WinHttpOpen',
    'InternetConnect', 'ShellExecuteA', 'system', 'LoadLibraryA',
    'NtWriteVirtualMemory', 'NtCreateThreadEx', 'NtQueueApcThread',
    'QueueUserAPC', 'RtlMoveMemory', 'CreateProcessA', 'CreateProcessW',
    'CreateProcessInternalW', 'OpenProcess', 'SuspendThread', 'ResumeThread',
    'SetThreadContext', 'GetThreadContext', 'MapViewOfFile',
    'UnmapViewOfFile', 'CreateFileMapping', 'VirtualQuery', 'VirtualQueryEx',
    'GetModuleHandle', 'GetModuleHandleA', 'GetModuleHandleW'}

privesc_functions = {'OpenProcessToken', 'LookupPrivilegeValue', 'AdjustTokenPrivileges',
    'ImpersonateLoggedOnUser', 'DuplicateToken', 'DuplicateTokenEx',
    'SetThreadToken', 'RevertToSelf'}

persistence_functions = {'RegCreateKeyEx', 'RegOpenKeyEx', 'RegDeleteKey', 'RegSetValue',
    'RegQueryValueEx', 'CoCreateInstance', 'StartServiceA', 'StartServiceW',
    'ChangeServiceConfig', 'WriteProfileString', 'SHSetValue'}

networking_functions = {'WinHttpConnect', 'WinHttpSendRequest', 'WinHttpReceiveResponse',
    'InternetOpenA', 'InternetOpenW', 'InternetOpenUrl', 'InternetReadFile',
    'WSAStartup', 'socket', 'connect', 'send', 'recv', 'gethostbyname',
    'DnsQuery', 'URLDownloadToFile'}

antidebugging_functions = {'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess', 'NtQuerySystemInformation',
    'GetTickCount', 'QueryPerformanceCounter', 'OutputDebugString',
    'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
    'Thread32First', 'Thread32Next'}

file_manipulation_functions = {'CreateFileA', 'CreateFileW', 'WriteFile', 'DeleteFile', 'CopyFile',
    'MoveFileEx', 'SetFileAttributes', 'GetTempPath', 'GetTempFileName'}

crypto_functions = {'CryptAcquireContext', 'CryptImportKey', 'CryptDecrypt', 'CryptEncrypt',
    'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenRandom'}

nt_syscalls_functions = {'NtOpenProcess', 'NtOpenThread', 'NtOpenFile', 'NtCreateFile', 'NtClose',
    'NtDelayExecution', 'NtUnmapViewOfSection'}

feature_cols = [
        "memory_functions_count", "privesc_functions_count", "persistence_functions_count",
        "networking_functions_count", "antidebugging_functions_count", "file_functions_count",
        "crypto_functions_count", "nt_functions_count", "num_sections","max_entropy","mean_entropy","num_high_entropy_sections",
        "num_suspicious_api_calls","ratio_suspicious","num_unusual_sections",
        "num_suspicious_strings","isEntryPointInTextSection","subsystem_value","is_unsigned", "num_functions",
        "ratio_suspicious", "ratio_high_entropy_sections", "ratio_suspicious_memory_api", "ratio_suspicious_persistence_api",
        "ratio_suspicious_privesc_api", "ratio_suspicious_networking_api", "ratio_suspicious_antidebugging_api", "ratio_suspicious_file_api",
        "ratio_suspicious_crypto_api", "ratio_suspicious_nt_api", "num_unique_functions", "ratio_unusual_sections", "heuristics_score"
]

def count_functions(funcs):
    if not funcs:
        return [0, 0, 0, 0, 0, 0, 0, 0]
    
    memory = sum(f["Name"] in memory_manipulation_functions for f in funcs)
    privesc = sum(f["Name"] in privesc_functions for f in funcs)
    persistence = sum(f["Name"] in persistence_functions for f in funcs)
    networking = sum(f["Name"] in networking_functions for f in funcs)
    antidebugging = sum(f["Name"] in antidebugging_functions for f in funcs)
    file = sum(f["Name"] in file_manipulation_functions for f in funcs)
    crypto = sum(f["Name"] in crypto_functions for f in funcs)
    nt = sum(f["Name"] in nt_syscalls_functions for f in funcs)

    return [memory, privesc, persistence, networking, antidebugging, file, crypto, nt]

def section_entropy_stats(secs):
    if not secs:
        return [0, 0, 0]
    entropies = [s.get("Entropy", 0) for s in secs]
    max_entropy = max(entropies)
    mean_entropy = np.mean(entropies)
    high_entropy_count = sum(e > 7.0 for e in entropies)
    return [max_entropy, mean_entropy, high_entropy_count]


def testingFiles(file, model):
    with open(file, 'r') as f:
        new_data = json.load(f)

    new_df = pd.DataFrame(new_data)

    new_df[["memory_functions_count", "privesc_functions_count", "persistence_functions_count",
        "networking_functions_count", "antidebugging_functions_count", "file_functions_count",
        "crypto_functions_count", "nt_functions_count"]] = pd.DataFrame(new_df["Functions"].apply(count_functions).tolist())
    
    new_df[["max_entropy", "mean_entropy", "num_high_entropy_sections"]] = pd.DataFrame(new_df["Sections"].apply(section_entropy_stats).tolist())

    new_df["num_suspicious_strings"] = new_df["heuristics"].apply(lambda h: len(h.get("suspicious_strings", [])) if isinstance(h, dict) else 0)

    # Number of sections to enhance the model
    new_df["num_sections"] = new_df["Sections"].apply(lambda x: len(x) if isinstance(x, list) else 0)
    new_df["num_functions"] = new_df["Functions"].apply(lambda x: len(x) if isinstance(x, list) else 0)

    new_df["entropy_value"] = new_df["Sections"].apply(lambda secs: sum([s.get("Entropy", 0) for s in secs])/len(secs) if isinstance(secs, list) and len(secs) > 0 else 0)
    # Subsystem value as numeric feature
    new_df["subsystem_value"] = new_df["Subsystem"].apply(lambda x: x.get("Value") if isinstance(x, dict) else 0)

    new_df["num_unusual_sections"] = new_df["heuristics"].apply(lambda h: len(h.get("unusual_sections", [])) if isinstance(h, dict) else 0)
    # Convert boolean to int.
    new_df["isEntryPointInTextSection"] = new_df["isEntryPointInTextSection"].astype(int)

    if "SignatureVerification" not in new_df.columns:
        new_df["SignatureVerification"] = ""

    new_df["is_unsigned"] = new_df["SignatureVerification"].apply(
        lambda s: 1 if "No signature" in str(s) else 0
    )

    # Number of suspicious API calls from heuristics. We need to get the length of the list.
    new_df["num_suspicious_api_calls"] = new_df["heuristics"].apply(
        lambda h: len(h.get("suspicious_api_calls", [])) if isinstance(h, dict) else 0
    )

    # Ratio of suspicious API calls to total functions. This is because more functions with few suspicious calls might be less suspicious.
    new_df["ratio_suspicious"] = new_df["num_suspicious_api_calls"] / (new_df["Functions"].apply(len) + 1)

    new_df["ratio_high_entropy_sections"] = new_df["num_high_entropy_sections"] / (new_df["num_sections"] + 1)
    new_df["ratio_suspicious_memory_api"] = new_df["memory_functions_count"] / (new_df["num_functions"] + 1)
    new_df["ratio_suspicious_persistence_api"] = new_df["persistence_functions_count"] / (new_df["num_functions"] + 1)
    new_df["ratio_suspicious_privesc_api"] = new_df["privesc_functions_count"] / (new_df["num_functions"] + 1)
    new_df["ratio_suspicious_networking_api"] = new_df["networking_functions_count"] / (new_df["num_functions"] + 1)
    new_df["ratio_suspicious_antidebugging_api"] = new_df["antidebugging_functions_count"] / (new_df["num_functions"] + 1)
    new_df["ratio_suspicious_file_api"] = new_df["file_functions_count"] / (new_df["num_functions"] + 1)
    new_df["ratio_suspicious_crypto_api"] = new_df["crypto_functions_count"] / (new_df["num_functions"] + 1)
    new_df["ratio_suspicious_nt_api"] = new_df["nt_functions_count"] / (new_df["num_functions"] + 1)

    new_df["num_unique_functions"] = new_df["Functions"].apply(lambda funcs: len(set(f["Name"] for f in funcs)) if isinstance(funcs, list) else 0)
    new_df["ratio_unusual_sections"] = new_df["num_unusual_sections"] / (new_df["num_sections"] + 1)

    new_df["heuristics_score"] = (
        new_df["num_suspicious_api_calls"] * 2 +   # weight API calls more
        new_df["num_suspicious_strings"] * 1 +
        new_df["num_unusual_sections"] * 1.5 +
        new_df["ratio_high_entropy_sections"] * 3
    )
    X_new = new_df[feature_cols].fillna(0)

    y_pred = model.predict(X_new)

    pred_labels = "Malicious" if y_pred[0] == 1 else "Benign"
    print(f"File: {file}, Predicted class: {pred_labels}")

def main():

    with open('data.json', 'r') as file:
        data = json.load(file)

    # Convert to DataFrame to analyze and extract features from the JSON dataset
    df = pd.DataFrame(data)

    df[["memory_functions_count", "privesc_functions_count", "persistence_functions_count",
        "networking_functions_count", "antidebugging_functions_count", "file_functions_count",
        "crypto_functions_count", "nt_functions_count"]] = pd.DataFrame(df["Functions"].apply(count_functions).tolist())
    
    df[["max_entropy", "mean_entropy", "num_high_entropy_sections"]] = pd.DataFrame(df["Sections"].apply(section_entropy_stats).tolist())

    df["num_suspicious_strings"] = df["heuristics"].apply(lambda h: len(h.get("suspicious_strings", [])) if isinstance(h, dict) else 0)

    # Number of sections to enhance the model
    df["num_sections"] = df["Sections"].apply(lambda x: len(x) if isinstance(x, list) else 0)
    df["num_functions"] = df["Functions"].apply(lambda x: len(x) if isinstance(x, list) else 0)

    df["entropy_value"] = df["Sections"].apply(lambda secs: sum([s.get("Entropy", 0) for s in secs])/len(secs) if isinstance(secs, list) and len(secs) > 0 else 0)
    # Subsystem value as numeric feature
    df["subsystem_value"] = df["Subsystem"].apply(lambda x: x.get("Value") if isinstance(x, dict) else 0)

    df["num_unusual_sections"] = df["heuristics"].apply(lambda h: len(h.get("unusual_sections", [])) if isinstance(h, dict) else 0)
    # Convert boolean to int.
    df["isEntryPointInTextSection"] = df["isEntryPointInTextSection"].astype(int)

    if "SignatureVerification" not in df.columns:
        df["SignatureVerification"] = ""

    df["is_unsigned"] = df["SignatureVerification"].apply(
        lambda s: 1 if "No signature" in str(s) else 0
    )

    df["num_suspicious_api_calls"] = df["heuristics"].apply(
        lambda h: len(h.get("suspicious_api_calls", [])) if isinstance(h, dict) else 0
    )

    # Ratio of suspicious API calls to total functions. This is because more functions with few suspicious calls might be less suspicious.
    df["ratio_suspicious"] = df["num_suspicious_api_calls"] / (df["Functions"].apply(len) + 1)

    df["ratio_high_entropy_sections"] = df["num_high_entropy_sections"] / (df["num_sections"] + 1)
    df["ratio_suspicious_memory_api"] = df["memory_functions_count"] / (df["num_functions"] + 1)
    df["ratio_suspicious_persistence_api"] = df["persistence_functions_count"] / (df["num_functions"] + 1)
    df["ratio_suspicious_privesc_api"] = df["privesc_functions_count"] / (df["num_functions"] + 1)
    df["ratio_suspicious_networking_api"] = df["networking_functions_count"] / (df["num_functions"] + 1)
    df["ratio_suspicious_antidebugging_api"] = df["antidebugging_functions_count"] / (df["num_functions"] + 1)
    df["ratio_suspicious_file_api"] = df["file_functions_count"] / (df["num_functions"] + 1)
    df["ratio_suspicious_crypto_api"] = df["crypto_functions_count"] / (df["num_functions"] + 1)
    df["ratio_suspicious_nt_api"] = df["nt_functions_count"] / (df["num_functions"] + 1)

    df["num_unique_functions"] = df["Functions"].apply(lambda funcs: len(set(f["Name"] for f in funcs)) if isinstance(funcs, list) else 0)
    df["ratio_unusual_sections"] = df["num_unusual_sections"] / (df["num_sections"] + 1)

    df["heuristics_score"] = (
        df["num_suspicious_api_calls"] * 2 +   # weight API calls more
        df["num_suspicious_strings"] * 1 +
        df["num_unusual_sections"] * 1.5 +
        df["ratio_high_entropy_sections"] * 3
    )

    # We need a y variable for regression. Assuming 'label' is the target variable in the dataset.
    y = df["label"]

    X = df[feature_cols].fillna(0)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


    
    model = LinearRegression()
    model.fit(X_train, y_train)

    print("Training R² score:", model.score(X_train, y_train))
    print("Test R² score:", model.score(X_test, y_test))

    y_pred = model.predict(X_test)
    print("Predictions for first 10 samples:", y_pred[:10])
    print("Actual labels for first 10 samples:", y_test[:10].values)

    testingFiles("Tinder_Data.json", model)
    testingFiles("todo_list.json" ,model)
    testingFiles("temperatureConverter.json", model)
    testingFiles("badRabbit.json", model)
    testingFiles("birele.json", model)
    testingFiles("deriaLock.json", model)

    logisticModel = LogisticRegression(max_iter=1000)
    logisticModel.fit(X_train, y_train)
    y_pred = logisticModel.predict(X_test)
    print("-----------------------------------------")
    print("Logistic Training R² score:", logisticModel.score(X_train, y_train))
    print("Logistic Test R² score:", logisticModel.score(X_test, y_test))
    print("Predictions for first 10 samples:", y_pred[:10])
    print("Actual labels for first 10 samples:", y_test[:10].values)

    testingFiles("Tinder_Data.json", logisticModel)
    testingFiles("todo_list.json" ,logisticModel)
    testingFiles("temperatureConverter.json", logisticModel)
    testingFiles("badRabbit.json", logisticModel)
    testingFiles("birele.json", logisticModel)
    testingFiles("deriaLock.json", logisticModel)

    param_grid = {
    'n_estimators': [100, 200],
    'max_depth': [10, 20, None],
    'min_samples_split': [2, 5],
    'min_samples_leaf': [1, 2]
}

    grid_search = GridSearchCV(estimator=RandomForestClassifier(random_state=42), param_grid=param_grid, cv=5)
    grid_search.fit(X_train, y_train)

    print("Best hyperparameters:", grid_search.best_params_)

    
    rfModel = RandomForestClassifier(class_weight='balanced', random_state=42)
    rfModel.fit(X_train, y_train)
    y_pred = rfModel.predict(X_test)

    print("-----------------------------------------")
    print("RF Training R² score:", rfModel.score(X_train, y_train))
    print("RF Test R² score:", rfModel.score(X_test, y_test))
    print("Predictions for first 10 samples:", y_pred[:10])
    print("Actual labels for first 10 samples:", y_test[:10].values)

    cv_scores = cross_val_score(rfModel, X, y, cv=10, scoring='accuracy')

    print("Cross-validation scores:", cv_scores)
    print("Mean accuracy:", cv_scores.mean())

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Accuracy
    print("Accuracy:", accuracy_score(y_test, y_pred))

    # Precision, Recall, and F1-Score
    print("Precision:", precision_score(y_test, y_pred))
    print("Recall:", recall_score(y_test, y_pred))
    print("F1-Score:", f1_score(y_test, y_pred))

    testingFiles("Tinder_Data.json", rfModel)
    testingFiles("todo_list.json" ,rfModel)
    testingFiles("temperatureConverter.json", rfModel)
    testingFiles("badRabbit.json", rfModel)
    testingFiles("birele.json", rfModel)
    testingFiles("deriaLock.json", rfModel)
    testingFiles("Cerber7.json", rfModel)

    
if __name__ == "__main__":
    main()