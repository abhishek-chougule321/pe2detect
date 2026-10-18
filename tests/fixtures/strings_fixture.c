/* Inert test fixture: only contains string literals for the strings scanner.
   Nothing is executed; main() just returns. */
#include <stdio.h>
const char *a[] = {
  "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "vssadmin.exe delete shadows /all /quiet",
  "powershell.exe -nop -w hidden -enc SQBFAFgA",
  "stratum+tcp://pool.example.test:3333",
  "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
  "https://api.telegram.org/bot123456:ABC/sendMessage",
  "VBoxService.exe", "wireshark.exe",
  "\\Google\\Chrome\\User Data\\Default\\Login Data",
  "simple keylogger build", "wevtutil cl Security",
  "schtasks /create /sc onlogon /tn Updater",
};
const wchar_t *w[] = { L"Your files have been encrypted", L"Set-MpPreference -DisableRealtimeMonitoring $true" };
int main(int c, char **v) { if (c == 999) { printf("%s %ls", a[c % 12], w[c % 2]); } return 0; }
