# Security policy

## Reporting a vulnerability

If you find a security problem in PE2Detect, for example a file that causes script injection, a crash or a way around the no-network policy, please report it privately through GitHub's **Report a vulnerability** option on the repository's Security tab, rather than in a public issue.

Please include the PE2Detect version or commit, your browser, and the steps to reproduce.

## Do not attach live malware

Never attach live malware to an issue or report. Share the SHA-256 hash and, if needed, a link to a public sample repository such as MalwareBazaar, or a minimal crafted file that triggers the problem.

## How PE2Detect protects you from the files it analyzes

- **Files are never executed.** They are read as bytes and parsed with typed arrays. The page never saves, downloads or opens them, and drag-and-drop is captured so the browser never opens a dropped file.
- **File content is never treated as code.** Every value taken from a file (names, strings, imports, version info, certificate fields, the file name) is HTML-escaped. The code uses no `eval`, dynamic code, iframes or object URLs.
- **Only PE2Detect's own script can run.** The Content Security Policy pins `script-src` to the SHA-256 hash of the page's script, so injected scripts and inline event handlers are refused even if escaping ever failed.
- **No network access.** `connect-src 'none'` and `default-src 'none'` block all requests, so no data can leave the page.
- **Robust parsing.** Bounds checks and loop limits in every parser, a prototype-free object for version-info fields, and a 100 MB file-size limit.
- **Tested.** `tests/verify.py` loads a deliberately hostile file carrying injection payloads in every attacker-controlled field and fails if any payload runs.

PE2Detect protects the page, not your computer: the files you handle can still be dangerous. Keep suspicious files inside an isolated sandbox or virtual machine.
