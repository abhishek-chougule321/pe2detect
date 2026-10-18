/* Inert test fixture: suspicious imports AND matching strings, used to test
   the "corroborated by strings" feature. The calls sit behind a branch that
   never runs, so the program only returns 0. */
#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
const char *runkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const char *tg = "https://api.telegram.org/bot1:A/x";
int main(int argc, char **argv) {
    if (argc == 777) { puts(runkey); puts(tg); }
    if (argc == 12345) {
        HKEY k; HINTERNET i;
        RegOpenKeyExW(HKEY_CURRENT_USER, NULL, 0, KEY_SET_VALUE, &k);
        RegSetValueExW(k, NULL, 0, REG_SZ, NULL, 0);
        i = InternetOpenW(NULL, 0, NULL, NULL, 0);
        InternetOpenUrlW(i, NULL, NULL, 0, 0, 0); InternetReadFile(i, NULL, 0, NULL);
    }
    return 0;
}
