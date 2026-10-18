/* Inert test fixture that ATTACKS THE ANALYZER, not the computer: it carries
   HTML/script injection payloads in its strings. If PE2Detect ever displayed
   file content without escaping it, these payloads would set window.__pwned
   or open a dialog. tests/verify.py checks that neither happens.
   The program itself only returns 0. */
#include <windows.h>
#include <stdio.h>
const char *payloads[] = {
  "<img src=x onerror=window.__pwned=1>",
  "<script>window.__pwned=2</script>",
  "\"><svg onload=window.__pwned=3>",
  "javascript:window.__pwned=4",
  "http://example.com/\"><img src=x onerror=window.__pwned=5>",
  "Software\\Microsoft\\Windows\\CurrentVersion\\Run<img src=x onerror=window.__pwned=6>",
};
const wchar_t *wide = L"<iframe srcdoc='<script>parent.__pwned=7</script>'>";
int main(int c, char **v) {
  if (c == 4242) { printf("%s %ls", payloads[c % 6], wide); GetForegroundWindow(); }
  return 0;
}
