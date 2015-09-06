#include <windows.h>
#include <tlhelp32.h>
#include <ntdef.h>

typedef struct _SYSTEM_PROCESS_IMAGE_NAME_INFORMATION
{
    HANDLE ProcessId;
    UNICODE_STRING ImageName;
} SYSTEM_PROCESS_IMAGE_NAME_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemProcessIdInformation = 88
} SYSTEM_INFORMATION_CLASS;

int main()
{
    typedef NTSTATUS WINAPI (*PNtQuerySystemInformation)
            (SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    if (const HMODULE hMod = GetModuleHandle(L"ntdll.dll"))
        if (const PNtQuerySystemInformation NtQuerySystemInformation = reinterpret_cast<PNtQuerySystemInformation>(GetProcAddress(hMod, "NtQuerySystemInformation")))
        {
            PROCESS_INFORMATION pi;
            STARTUPINFO si;
            memset(&si, 0, sizeof(STARTUPINFO));
            si.cb = sizeof(STARTUPINFO);

            wchar_t wBuf[0x100] = L"\"C:\\Program Files\\COMODO\\COMODO Internet Security\\cfpconfg.exe\" --launchSchedule {B9D5C6F9-17D2-4917-8BD0-614BAA1C6A59}";
            if (CreateProcess(0, wBuf, 0, 0, FALSE, CREATE_UNICODE_ENVIRONMENT, 0, 0, &si, &pi))
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                HANDLE hToken;
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
                {
                    TOKEN_PRIVILEGES tokprv;
                    if (LookupPrivilegeValue(0, SE_DEBUG_NAME, &tokprv.Privileges[0].Luid))
                    {
                        tokprv.PrivilegeCount = 1;
                        tokprv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                        AdjustTokenPrivileges(hToken, FALSE, &tokprv, 0, 0, 0);
                    }
                    CloseHandle(hToken);
                }

                Sleep(10000);
                const HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnapshot != INVALID_HANDLE_VALUE)
                {
                    HANDLE hObject = 0;
                    PROCESSENTRY32 processEntry32;
                    processEntry32.dwSize = sizeof(PROCESSENTRY32);
                    if (Process32First(hSnapshot, &processEntry32))
                    {
                        SYSTEM_PROCESS_IMAGE_NAME_INFORMATION sysProcInfo;
                        sysProcInfo.ImageName.Buffer = wBuf;
                        do
                        {
                            if (wcscmp(processEntry32.szExeFile, L"cmdupd.exe") == 0)
                            {
                                sysProcInfo.ProcessId = reinterpret_cast<HANDLE>(processEntry32.th32ProcessID);
                                sysProcInfo.ImageName.Length = 0;
                                sysProcInfo.ImageName.MaximumLength = 0x100;
                                if (NT_SUCCESS(NtQuerySystemInformation(SystemProcessIdInformation, &sysProcInfo, sizeof(SYSTEM_PROCESS_IMAGE_NAME_INFORMATION), 0)) &&
                                        sysProcInfo.ImageName.Length >= 52*sizeof(wchar_t) &&        //[52 = "\Device\?\COMODO\COMODO Internet Security\cmdupd.exe"]
                                        wcscmp(wBuf + sysProcInfo.ImageName.Length/sizeof(wchar_t) - 43, L"\\COMODO\\COMODO Internet Security\\cmdupd.exe") == 0 &&
                                        (hObject = OpenProcess(SYNCHRONIZE, FALSE, processEntry32.th32ProcessID)))
                                    break;
                            }
                        } while (Process32Next(hSnapshot, &processEntry32));
                    }
                    CloseHandle(hSnapshot);

                    if (hObject)
                    {
                        WaitForSingleObject(hObject, 30*60000);
                        CloseHandle(hObject);
                    }
                }
            }
        }

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\COMODO\\CIS\\Data", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS)
    {
        const unsigned long long iValue = 0xFFFFFFFF;
        RegSetValueEx(hKey, L"AvDbCheckDate", 0, REG_QWORD, static_cast<const BYTE*>(static_cast<const void*>(&iValue)), sizeof(unsigned long long));
        RegCloseKey(hKey);
    }
    return 0;
}
