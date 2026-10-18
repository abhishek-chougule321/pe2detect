# PE2Detect tests

This folder holds the **source** of every test file and the scripts that build them and verify PE2Detect against independent tools. No binaries, keys or malware are stored in the repository: everything is built locally into `tests/build/`, which git ignores.

All test programs are inert. Their suspicious API calls sit behind branches that never run, and the signed test files use throwaway certificates generated on each build.

## Requirements (Ubuntu or WSL)

```bash
sudo apt install mingw-w64 osslsigncode upx-ucl binutils python3-pip
pip install -r requirements.txt
python3 -m playwright install --with-deps chromium
```

**signify note:** on systems with OpenSSL 3, signify's `oscrypto` dependency may fail with "Error detecting the version of libcrypto". Installing oscrypto from its repository fixes it:

```bash
pip install --force-reinstall --no-deps "git+https://github.com/wbond/oscrypto.git"
```

If signify is unavailable, the signature comparison is skipped and every other check still runs.

## Run

```bash
./build_fixtures.sh                     # self-made test files only
./build_fixtures.sh --with-real-signed  # also downloads genuinely signed files for comparison
python3 verify.py
```

## What is checked

| Check | Compared with |
|---|---|
| Page makes no network requests; an exfiltration attempt is blocked | Browser request log |
| CSP hash matches the script; injected event handlers are refused | The page's own policy |
| A hostile file never runs code (file picker and drag-and-drop) | Payload flags, dialogs, DOM inspection |
| The interface never labels a file "clean" or "malware"; reference and sandbox notes present | Rendered text |
| Import tables (32-bit, 64-bit, packed, real installer) | pefile |
| ASCII and wide string counts | GNU `strings` |
| Signed hash, certificate thumbprint and serial | signify |
| Expected findings for each test file | Known contents of each fixture |
| Brand-impersonation and Windows-system-file rules | Made-up signer data, checked directly |
| Corrupted headers and signatures never crash the page | Browser error log |

## Test files

| File | Built from | Tests |
|---|---|---|
| `imports-32.exe`, `imports-64.exe` | `fixtures/imports_fixture.c` | Import parsing, capabilities (injection, keylogging, HTTP, tokens, sockets) |
| `packed-32.exe` | `imports-32.exe` packed with UPX | Packing indicators |
| `strings.exe` | `fixtures/strings_fixture.c` | String rules, including wide strings |
| `network.exe` | `fixtures/network_fixture.c` | URL and IP extraction, defanging, noise filtering |
| `corroboration.exe` | `fixtures/corroboration_fixture.c` | Strings backing up capabilities |
| `update_helper.exe` | `minimal.c` + `version_impersonation.rc`, signed | Version info claiming a (fictional) vendor while signed by someone else, self-signed, SHA-1, fresh certificate, renamed file |
| `evilupdater.exe` | `minimal.c` + `version_consistent.rc`, signed twice | Nested signatures, name consistency |
| `expired_no_timestamp.exe` | signed with an expired certificate | Missing timestamp, expiry |
| `outside_validity.exe` | timestamped after the certificate expired | Signing outside the validity window |
| `unauth_blob.exe` | signed with an extra unsigned attribute | Unrecognized data inside the signature |
| `hidden_payload.exe` | `make_hidden_payload.py` | Data hidden after the signature (CVE-2013-3900) |
| `"><img src=x onerror=…>.exe` | `fixtures/hostile_fixture.c` + `hostile_version.rc`, patched by `make_hostile.py`, signed with a certificate whose name is a payload | Script-injection attempts in strings, imports, a section name, version info, certificate fields and the file name |
| `vcruntime140.dll`, `npp_installer.exe` | downloaded with `--with-real-signed` | Real Microsoft and DigiCert signatures, no false positives |
| `npp_tampered.exe`, `ms_hidden_payload.dll` | modified copies of the above | Tampering and hidden data on real signatures |
