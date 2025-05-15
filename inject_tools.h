#pragma once
#include <stdio.h>
#include <io.h>
#include <windows.h>
#include <TlHelp32.h>

// Injection mode -- are we injecting a DLL or are we injecting shellcode?
#define MODE_DLL            0
#define MODE_SHELLCODE      1

#define DEFAULT_STACK_SIZE  0


// This logging stuff is here to still allow advanced users to see whats up but also prevent
// my messages from hitting your stdout or messing something up.
#ifndef DISABLE_INJECT_LOG

    #ifndef INJECT_LOG
    // internal helper that formats a message into a temp buffer then sends to debug stream
    static inline void inject_log_impl(const wchar_t* fmt, ...)
    {
        wchar_t buf[1024];
        va_list args;
        va_start(args, fmt);
        // safe-format into buf (truncates if >1023 chars + NUL)
        _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
        va_end(args);
        OutputDebugStringW(buf);
    }

    #define INJECT_LOG(...) inject_log_impl(__VA_ARGS__)
    #endif

#else

    #ifndef INJECT_LOG
      // disable it entirely
    #define INJECT_LOG(...) ((void)0)
    #endif

#endif

/**
 * @brief Retrieves the process ID for a running process by its executable name.
 *
 * Takes a wide-character process name (e.g. L"notepad.exe") and searches
 * the snapshot of all running processes. If a match is found, writes the
 * process ID to @p proc_pid.
 *
 * @param proc_name    Wide-character string of the target process executable name.
 * @param proc_pid     Pointer to a DWORD that receives the process ID.
 * @return TRUE if the process was found and @p proc_pid set; FALSE otherwise.
 */
BOOL GetPIDByName(wchar_t* proc_name, DWORD* proc_pid)
{
    BOOL ret_val = FALSE;
    PROCESSENTRY32W current_process_entry = { 0 };
    current_process_entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE process_list_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (process_list_snapshot == INVALID_HANDLE_VALUE)
    {
        INJECT_LOG(L"[!] CreateToolhelp32Snapshot failed. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        goto th32_cleanup;
    }

    if (!Process32FirstW(process_list_snapshot, &current_process_entry))
    {
        INJECT_LOG(L"[!] Process32FirstW failed. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        goto th32_cleanup;
    }

    do
    {
        if (wcscmp(current_process_entry.szExeFile, proc_name))
        {
            continue;
        }

        *proc_pid = current_process_entry.th32ProcessID;
        break;

    } while (Process32NextW(process_list_snapshot, &current_process_entry));


    ret_val = TRUE;

th32_cleanup:
    if (process_list_snapshot) { CloseHandle(process_list_snapshot); }
    return ret_val;
}


/**
 * @brief Creates/retrieves a DLL payload by resolving its full path name.
 *
 * Computes the full path of @p dll_file_name and writes
 * its wide-character form into a buffer. The caller is
 * responsible for freeing the returned buffer.
 *
 * @param dll_file_name  Wide-character string of the DLL file name (relative or absolute).
 * @param payload_size   Pointer to size_t to receive the size of the returned buffer in bytes.
 * @return Pointer to a malloc-allocated buffer containing the full path, or NULL on failure.
 */
BYTE* GetDLLPayload(wchar_t* dll_file_name, size_t* payload_size)
{
    BYTE* full_dll_path = NULL;
    DWORD size_full_dll_path_in_wchars = GetFullPathNameW(dll_file_name, 0, (wchar_t*)full_dll_path, NULL); // Run once to get the buffer size
    if (size_full_dll_path_in_wchars == 0)
    {
        INJECT_LOG(L"[!] GetFullPathNameW to retrieve full dll path size failed. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        return NULL;
    }

    full_dll_path = (BYTE*)malloc(size_full_dll_path_in_wchars * sizeof(wchar_t));
    if (!full_dll_path)
    {
        INJECT_LOG(L"[!] Failed to locally allocate memory for full dll path.\n");
        return NULL;
    }


    if (!GetFullPathNameW(dll_file_name, size_full_dll_path_in_wchars, (wchar_t*)full_dll_path, NULL))
    {
        INJECT_LOG(L"[!] GetFullPathNameW for DLL name failed. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        free(full_dll_path);
        return NULL;
    }

    if (payload_size) { *payload_size = size_full_dll_path_in_wchars * sizeof(wchar_t); }

    return full_dll_path;
}

/**
 * @brief Retrieves the shellcode bytes from a file and stores them into a heap buffer.
 *
 * The caller is responsible for freeing the returned buffer.
 *
 * @param shellcode_file_name  Wide-character string of the shellcode file path.
 * @param payload_size         Pointer to size_t to receive the number of bytes read.
 * @return Pointer to a malloc-allocated buffer with shellcode, or NULL on failure.
 */
BYTE* GetShellcodePayload(wchar_t* shellcode_file_name, size_t* payload_size)
{
    BYTE* payload = NULL;

    FILE* shellcode_file = _wfopen(shellcode_file_name, L"rb");
    if (!shellcode_file)
    {
        INJECT_LOG(L"[!] _wfopen for shellcode failed. Error: %s (0x%08X)\n", _wcserror(errno), errno);
        return NULL;
    }

    size_t file_length = _filelengthi64(_fileno(shellcode_file));

    payload = (BYTE*)malloc(file_length);
    if (!payload)
    {
        INJECT_LOG(L"[!] Failed to locally allocate memory for full dll path.\n");
        fclose(shellcode_file);
        return NULL;
    }

    size_t bytes_read = fread(payload, sizeof(BYTE), file_length, shellcode_file);
    if (!bytes_read || bytes_read < file_length)
    {
        INJECT_LOG(L"[!] fread of shellcode file failed. Error: %s (0x%08X)\n", _wcserror(errno), errno);
        fclose(shellcode_file);
        free(payload);
        return NULL;
    }

    if (payload_size) { *payload_size = file_length; }

    return payload;
}

/**
 * @brief Injects a payload (DLL path or shellcode) into a remote process.
 *
 * Depending on @p mode, this function uses GetDLLPayload or GetShellcodePayload
 * to load the payload into a local buffer, allocates executable memory in
 * @p target_proc, writes the payload into that memory region, and returns
 * the base address in the remote process.
 *
 * @param mode                Injection mode: MODE_DLL or MODE_SHELLCODE.
 * @param target_proc         Handle to the target process
 * @param payload_file_name   Wide-character string of the payload file name.
 * @return Base address of the allocated memory in the target process, or NULL on failure.
 */
LPVOID Inject(BOOL mode, HANDLE target_proc, wchar_t* payload_file_name)
{
    LPVOID ret_val = NULL;

    // Don't forget -- YOU MUST FREE THIS PAYLOAD
    size_t payload_size = 0;
    BYTE* payload = (mode == MODE_DLL) ? GetDLLPayload(payload_file_name, &payload_size) : GetShellcodePayload(payload_file_name, &payload_size);
    if (!payload)
    {
        goto cleanup;
    }

    // Allocate the memory now (Not being stealthy! Any anti-cheat worth its salt will catch this nonsense! Also, Windows defender might screech at you)
    LPVOID payload_base_addr = VirtualAllocEx(target_proc, NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!payload_base_addr)
    {
        INJECT_LOG(L"[!] OpenProcess on target process failed. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        goto cleanup;
    }

    // Write the payload bytes now
    size_t payload_bytes_written = 0;
    BOOL is_payload_deployed = WriteProcessMemory(target_proc, payload_base_addr, payload, payload_size, &payload_bytes_written);
    if (!is_payload_deployed || payload_bytes_written != payload_size)
    {
        INJECT_LOG(L"[!] WriteProcessMemory to write payload failed. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        INJECT_LOG(L"---- [!] Bytes Written: %llu / %llu\n", payload_bytes_written, payload_size);
        if (!VirtualFreeEx(target_proc, payload_base_addr, 0, MEM_RELEASE))
        {
            INJECT_LOG(L"[!] Oh my... a double error! VirtualFreeEx was unable to free the reserved memory in target process. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        }
        goto cleanup;
    }

    ret_val = payload_base_addr;

cleanup:
    if (payload) { free(payload); }
    return ret_val;
}

/**
 * @brief Convenience wrapper to inject a DLL into a remote process.
 *
 * Calls Inject(MODE_DLL, ...).
 *
 * @param target_process      Handle to the target process.
 * @param payload_file_name   Wide-character string of the DLL file name.
 * @return Base address of the allocated memory, or NULL on failure.
 */
LPVOID InjectDLL(HANDLE target_process, wchar_t* payload_file_name)
{
    return Inject(MODE_DLL, target_process, payload_file_name);
}

/**
 * @brief Convenience wrapper to inject raw shellcode into a remote process.
 *
 * Calls Inject(MODE_SHELLCODE, ...).
 *
 * @param target_process      Handle to the target process.
 * @param payload_file_name   Wide-character string of the shellcode file name.
 * @return Base address of the allocated memory, or NULL on failure.
 */
LPVOID InjectShellcode(HANDLE target_process, wchar_t* payload_file_name)
{
    return Inject(MODE_SHELLCODE, target_process, payload_file_name);
}

/**
 * @brief Executes an injected payload by creating a remote thread.
 *
 * If @p mode is MODE_DLL, the remote thread starts at LoadLibraryW
 * and @p payload_base_address is passed as the DLL path argument.
 * If @p mode is MODE_SHELLCODE, the remote thread starts at
 * @p payload_base_address (raw shellcode).
 *
 * @param mode                   Execution mode: MODE_DLL or MODE_SHELLCODE.
 * @param target_process         Handle to the target process.
 * @param payload_base_address   Address in the target process where payload resides.
 * @return Handle to the created remote thread, or NULL on failure.
 */
HANDLE RunPayload(BOOL mode, HANDLE target_process, LPVOID payload_base_address)
{
    HANDLE ret_val = NULL;

    HMODULE k32_dll = GetModuleHandleW(L"kernel32.dll");
    if (!k32_dll)
    {
        INJECT_LOG(L"[!] GetModuleHandleW failed to acquire kernel32.dll handle. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        goto run_payload_exit;
    }

    FARPROC load_lib_addr = GetProcAddress(k32_dll, "LoadLibraryW");
    if (!load_lib_addr)
    {

        INJECT_LOG(L"[!] GetProcAddress failed to acquire address of LoadLibraryW. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        goto run_payload_exit;
    }

    HANDLE injected_thread = NULL;
    if (mode == MODE_DLL)
    {
        injected_thread = CreateRemoteThreadEx(target_process, NULL, DEFAULT_STACK_SIZE, (LPTHREAD_START_ROUTINE)load_lib_addr, payload_base_address, 0, NULL, NULL);
    }
    else
    {
        injected_thread = CreateRemoteThreadEx(target_process, NULL, DEFAULT_STACK_SIZE, (LPTHREAD_START_ROUTINE)payload_base_address, NULL, 0, NULL, NULL);
    }

    if (!injected_thread)
    {
        INJECT_LOG(L"[!] CreateRemoteThreadEx in target process failed. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        goto run_payload_exit;
    }

    ret_val = injected_thread;

run_payload_exit:

    return ret_val;
}

/**
 * @brief Convenience wrapper to execute an injected DLL.
 *
 * Calls RunPayload(MODE_DLL, ...).
 *
 * @param target_process         Handle to the target process.
 * @param payload_base_address   Base address of the injected DLL path buffer.
 * @return Handle to the created remote thread, or NULL on failure.
 */
HANDLE RunPayloadDLL(HANDLE target_process, LPVOID payload_base_address)
{
    return RunPayload(MODE_DLL, target_process, payload_base_address);
}

/**
 * @brief Convenience wrapper to execute injected shellcode.
 *
 * Calls RunPayload(MODE_SHELLCODE, ...).
 *
 * @param target_process         Handle to the target process.
 * @param payload_base_address   Base address of the injected shellcode buffer.
 * @return Handle to the created remote thread, or NULL on failure.
 */
HANDLE RunPayloadShellcode(HANDLE target_process, LPVOID payload_base_address)
{
    return RunPayload(MODE_SHELLCODE, target_process, payload_base_address);
}