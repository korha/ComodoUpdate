#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

int main()
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
                do
                {
                    if (wcscmp(processEntry32.szExeFile, L"cmdupd.exe") == 0)
                    {
                        if (const HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, processEntry32.th32ProcessID))
                        {
                            const DWORD dwSize = GetProcessImageFileName(hProcess, wBuf, 0x100);
                            if (dwSize >= 52 &&        //[52 = "\Device\?\COMODO\COMODO Internet Security\cmdupd.exe"]
                                    wcscmp(wBuf + dwSize - 43, L"\\COMODO\\COMODO Internet Security\\cmdupd.exe") == 0)
                            {
                                hObject = hProcess;
                                break;
                            }
                            CloseHandle(hProcess);
                        }
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

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\COMODO\\CIS\\Data", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS)
    {
        const unsigned long long iValue = 0xFFFFFFFF;
        RegSetValueEx(hKey, L"AvDbCheckDate", 0, REG_QWORD, static_cast<const BYTE*>(static_cast<const void*>(&iValue)), sizeof(unsigned long long));
        RegCloseKey(hKey);
    }
    return 0;
}
