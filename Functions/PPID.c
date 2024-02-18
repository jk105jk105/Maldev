#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

DWORD GetParentProcessId(DWORD pid) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot;
    DWORD parentPID = 0;

    // Create process snapshot
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

int main() {
    DWORD pid = GetCurrentProcessId();
    DWORD ppid = GetParentProcessId(pid);

    printf("Parent Process ID - %lu\n", ppid);

    return 0;
}