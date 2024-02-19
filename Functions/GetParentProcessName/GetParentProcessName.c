#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <TlHelp32.h>

DWORD GetParentProcessId(DWORD pid) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot;
    DWORD parentPID = 0;

    // Create processes snapshot
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    // Loop through process snapshot
    do {
        if (pe32.th32ProcessID == pid) {
            // Get ppid of matching pid
            parentPID = pe32.th32ParentProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return parentPID;
}

TCHAR* GetParentProcessName(DWORD dwProcessId) {
    HANDLE hPProcess = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    TCHAR* szProcessName = NULL;

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == dwProcessId) {
                    szProcessName = _tcsdup(pe32.szExeFile);
                    _tprintf(TEXT("Parent process name - %s\n"), szProcessName);
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }
    return szProcessName;
}

int main() {
    DWORD pid = GetCurrentProcessId();
    DWORD ppid = GetParentProcessId(pid);
    TCHAR* pprocessName = GetParentProcessName(ppid);

    _tprintf(TEXT("Parent process name - %s\n"), pprocessName);

    printf("Press Enter to Quit\n");
    getchar();

    return 0;
}