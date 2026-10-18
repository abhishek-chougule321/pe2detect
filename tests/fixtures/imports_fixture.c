/* Inert test fixture: references suspicious APIs (injection, keylogging,
   registry, HTTP, tokens, debugger checks, sockets) so they appear in the
   import table. The calls sit behind a branch that never runs, so the
   program only returns 0. */
#include <winsock2.h>
#include <windows.h>
#include <wininet.h>

int main(int argc, char **argv) {
    if (argc == 12345) {
        HANDLE h = NULL; HKEY k; HANDLE t; BOOL b; WSADATA w; HINTERNET i; void *p;
        p = VirtualAllocEx(h, NULL, 0, MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(h, p, NULL, 0, NULL);
        CreateRemoteThread(h, NULL, 0, NULL, NULL, 0, NULL);
        SetWindowsHookExW(WH_KEYBOARD_LL, NULL, NULL, 0);
        GetAsyncKeyState(0); GetForegroundWindow();
        RegOpenKeyExW(HKEY_CURRENT_USER, NULL, 0, KEY_SET_VALUE, &k);
        RegSetValueExW(k, NULL, 0, REG_SZ, NULL, 0);
        i = InternetOpenW(NULL, 0, NULL, NULL, 0);
        InternetOpenUrlW(i, NULL, NULL, 0, 0, 0); InternetReadFile(i, NULL, 0, NULL);
        OpenProcessToken(h, 0, &t); AdjustTokenPrivileges(t, FALSE, NULL, 0, NULL, NULL);
        CheckRemoteDebuggerPresent(h, &b);
        WSAStartup(0x202, &w); socket(2, 1, 6); connect(0, NULL, 0); send(0, NULL, 0, 0);
    }
    return 0;
}
