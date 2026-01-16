import pandas as pd
import json
from sklearn.feature_extraction.text import CountVectorizer
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
import numpy as np
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import cross_val_score
from sklearn.metrics import r2_score
from sklearn.model_selection import GridSearchCV
from sklearn.tree import DecisionTreeClassifier

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
        "num_sections","mean_entropy",
        "num_suspicious_strings", "num_functions",
        "num_suspicious_api_calls", "subsystem_value",
        "num_unusual_sections", "isEntryPointInTextSection"
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

# Need to see the return of this func
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
    
    new_df["mean_entropy"] = new_df["Sections"].apply(
        lambda s: section_entropy_stats(s)[1]
    )

    new_df["num_suspicious_strings"] = new_df["heuristics"].apply(lambda h: len(h.get("suspicious_strings", [])) if isinstance(h, dict) else 0)

    # Number of sections to enhance the model
    new_df["num_sections"] = new_df["Sections"].apply(lambda x: len(x) if isinstance(x, list) else 0)
    new_df["num_functions"] = new_df["Functions"].apply(lambda x: len(x) if isinstance(x, list) else 0)
    new_df["subsystem_value"] = new_df["Subsystem"].apply(lambda x: x.get("Value") if isinstance(x, dict) else 0)
    new_df["num_unusual_sections"] = new_df["heuristics"].apply(lambda h: len(h.get("unusual_sections", [])) if isinstance(h, dict) else 0)
    new_df["isEntryPointInTextSection"] = new_df["isEntryPointInTextSection"].astype(int)
    new_df["num_suspicious_api_calls"] = new_df["heuristics"].apply(
        lambda h: len(h.get("suspicious_api_calls", [])) if isinstance(h, dict) else 0
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
    
    df["mean_entropy"] = df["Sections"].apply(
        lambda s: section_entropy_stats(s)[1]
    )

    df["num_suspicious_strings"] = df["heuristics"].apply(lambda h: len(h.get("suspicious_strings", [])) if isinstance(h, dict) else 0)

    # Number of sections to enhance the model
    df["num_sections"] = df["Sections"].apply(lambda x: len(x) if isinstance(x, list) else 0)
    df["num_functions"] = df["Functions"].apply(lambda x: len(x) if isinstance(x, list) else 0)
    df["subsystem_value"] = df["Subsystem"].apply(lambda x: x.get("Value") if isinstance(x, dict) else 0)
    df["num_unusual_sections"] = df["heuristics"].apply(lambda h: len(h.get("unusual_sections", [])) if isinstance(h, dict) else 0)
    df["isEntryPointInTextSection"] = df["isEntryPointInTextSection"].astype(int)
    df["num_suspicious_api_calls"] = df["heuristics"].apply(
        lambda h: len(h.get("suspicious_api_calls", [])) if isinstance(h, dict) else 0
    )

    # We need a y variable for regression. Assuming 'label' is the target variable in the dataset.
    y = df["label"]

    X = df[feature_cols].fillna(0)

    nan_summary = df.isna().sum().sort_values(ascending=False)
    print("Columns with missing values:")
    print(nan_summary[nan_summary > 0])
    inf_summary = np.isinf(df.select_dtypes(include=[np.number])).sum()
    print(inf_summary[inf_summary > 0])

    print(df[feature_cols].describe().T)
    print(df.groupby("label")[feature_cols].mean().T)

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
    accuracy_logistic = accuracy_score(y_test, y_pred)
    precision_logistic = precision_score(y_test, y_pred)
    recall_logistic = recall_score(y_test, y_pred)
    f1_logistic = f1_score(y_test, y_pred)
    
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
    accuracy_random = accuracy_score(y_test, y_pred)
    precision_random = precision_score(y_test, y_pred)
    recall_random = recall_score(y_test, y_pred)
    f1_random = f1_score(y_test, y_pred)

    print("-----------------------------------------")
    print("RF Training R² score:", rfModel.score(X_train, y_train))
    print("RF Test R² score:", rfModel.score(X_test, y_test))
    cv_scores = cross_val_score(rfModel, X, y, cv=10, scoring='accuracy')

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

    dTModel = DecisionTreeClassifier(random_state=42)
    dTModel.fit(X_train, y_train)
    y_pred = dTModel.predict(X_test)
    print("Train model Desicion Tree: ", accuracy_score(y_train, dTModel.predict(X_train)))
    accuracy_dt = accuracy_score(y_test, y_pred)
    print ("Test model Desicion Tree: ", accuracy_dt)
    precision_dt = precision_score(y_test, y_pred)
    recall_dt = recall_score(y_test, y_pred)
    f1_dt = f1_score(y_test, y_pred)

    print("-----------------------------------------")
    print("DT Training R² score:", dTModel.score(X_train, y_train))
    testingFiles("Tinder_Data.json", dTModel)
    testingFiles("todo_list.json" ,dTModel)
    testingFiles("temperatureConverter.json", dTModel)
    testingFiles("badRabbit.json", dTModel)
    testingFiles("birele.json", dTModel)
    testingFiles("deriaLock.json", dTModel)
    testingFiles("Cerber7.json", dTModel)

    results = {
        "model": ["Logistic Regression", "Random Forest"],
        "accuracy": [
            accuracy_logistic,
            accuracy_random
        ],
        "precision": [
            precision_logistic,
            precision_random
        ],
        "recall": [
            recall_logistic,
            recall_random
        ],
        "f1_score": [
            f1_logistic,
            f1_random
        ]
    }
    results_df = pd.DataFrame(results)
    print("\nModel Comparison:")
    print(results_df)
    results_df.plot(
        x="model",
        kind="bar",
        figsize=(10, 6),
        colormap="viridis",
        edgecolor="black"
    )

    plt.title("Model Performance Comparison")
    plt.ylabel("Score")
    plt.ylim(0, 1)
    plt.xticks(rotation=0)
    plt.legend(title="Metrics")
    plt.tight_layout()
    plt.savefig("model_comparison.png", dpi=300, bbox_inches="tight")
    print("Saved plot: model_comparison.png")

    
if __name__ == "__main__":
    main()