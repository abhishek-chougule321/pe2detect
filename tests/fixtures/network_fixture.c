/* Inert test fixture with network-looking strings. Nothing runs. */
#include <stdio.h>
const char *n[] = {
  "http://203.0.113.50:8080/gate.php",
  "https://update-check.example.test/files/payload.exe",
  "connect to 8.8.8.8 for dns",
  "lan host 192.168.1.10",
  "loopback 127.0.0.1",
  "assemblyIdentity version=\"6.0.0.0\"",
  "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
  "http://crl.example-ca.test/ca.crl",
  "build 10.0.19041.1 kernel",
  "see (https://docs.example.test/help).",
};
const wchar_t *w = L"https://wide.example.test/c2/beacon";
int main(int c, char **v) { if (c == 999) printf("%s %ls", n[c % 10], w); return 0; }
