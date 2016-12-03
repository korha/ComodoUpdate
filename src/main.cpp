//ComodoCheckDate
#define _WIN32_WINNT _WIN32_IE_WINBLUE
#define WIN32_LEAN_AND_MEAN
#include <winternl.h>
#include <ntstatus.h>

#define EXPORT //__declspec(dllexport)
#define IMPORT __declspec(dllimport)

//-------------------------------------------------------------------------------------------------
extern "C" IMPORT NTSTATUS NTAPI LdrDisableThreadCalloutsForDll(PVOID BaseAddress);
extern "C" IMPORT NTSTATUS NTAPI NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions);
extern "C" IMPORT NTSTATUS NTAPI NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);

//-------------------------------------------------------------------------------------------------
EXPORT PVOID WINAPI ImageDirectoryEntryToDataStub(PVOID, BOOLEAN, USHORT, PULONG)
{
    return nullptr;
}

EXPORT BOOL WINAPI MiniDumpWriteDumpStub(HANDLE, DWORD, HANDLE, int, PVOID, PVOID, PVOID)
{
    return FALSE;
}

//-------------------------------------------------------------------------------------------------
extern "C" BOOL WINAPI DllEntryPoint(HINSTANCE hInstDll, DWORD fdwReason, LPVOID)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        LdrDisableThreadCalloutsForDll(hInstDll);
    else if (fdwReason == DLL_PROCESS_DETACH)
    {
        wchar_t wKey[] = L"\\Registry\\Machine\\SOFTWARE\\COMODO\\CIS\\Data";
        UNICODE_STRING us;
        us.Buffer = wKey;
        us.Length = sizeof(wKey)-sizeof(wchar_t);
        us.MaximumLength = sizeof(wKey);
        OBJECT_ATTRIBUTES objAttributes;
        objAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
        objAttributes.RootDirectory = nullptr;
        objAttributes.ObjectName = &us;
        objAttributes.Attributes = OBJ_CASE_INSENSITIVE;
        objAttributes.SecurityDescriptor = nullptr;
        objAttributes.SecurityQualityOfService = nullptr;
        HANDLE hKey;
        if (NtOpenKeyEx(&hKey, KEY_SET_VALUE, &objAttributes, 0) == STATUS_SUCCESS)
        {
            wchar_t wValue[] = L"AvDbCheckDate";
            us.Buffer = wValue;
            us.Length = sizeof(wValue)-sizeof(wchar_t);
            us.MaximumLength = sizeof(wValue);
            ULONGLONG iValue = MAXUINT;
            NtSetValueKey(hKey, &us, 0, REG_QWORD, &iValue, sizeof(ULONGLONG));
            NtClose(hKey);
        }
    }
    return TRUE;
}
