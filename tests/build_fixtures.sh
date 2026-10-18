#!/usr/bin/env bash
# Builds every test file from source into tests/build/ (git-ignored).
# Requirements: mingw-w64, osslsigncode, upx, python3 with "cryptography".
# Optional (--with-real-signed): downloads genuinely signed third-party files
# for comparison. They are never committed; see tests/README.md.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
B=build; F=fixtures
CC=x86_64-w64-mingw32-gcc; CC32=i686-w64-mingw32-gcc; RC=x86_64-w64-mingw32-windres
LIBS="-lwininet -lws2_32 -ladvapi32 -luser32"

echo "== unsigned fixtures"
$CC  -O1 $F/imports_fixture.c        -o $B/imports-64.exe $LIBS
$CC32 -O1 $F/imports_fixture.c       -o $B/imports-32.exe $LIBS
$CC  -O0 $F/strings_fixture.c        -o $B/strings.exe -ladvapi32
$CC  -O0 $F/network_fixture.c        -o $B/network.exe
$CC  -O0 $F/corroboration_fixture.c  -o $B/corroboration.exe $LIBS
cp $B/imports-32.exe $B/packed-32.exe && upx -q --force $B/packed-32.exe >/dev/null

echo "== signed fixtures"
python3 make_certs.py
$RC $F/version_impersonation.rc -O coff -o $B/ver_imp.o
$RC $F/version_consistent.rc    -O coff -o $B/ver_ok.o
$CC $F/minimal.c $B/ver_imp.o -o $B/base_impersonation.exe
$CC $F/minimal.c $B/ver_ok.o  -o $B/base_consistent.exe
NOW=$(date +%s)
TSA="-TSA-certs $B/tsa.crt -TSA-key $B/tsa.key"
FRESH="-certs $B/fresh.crt -key $B/fresh.key"
OLD="-certs $B/expired.crt -key $B/expired.key"
q() { osslsigncode sign "$@" >/dev/null; }
# Claims to be Microsoft's svchost, signed with a 2-day-old self-signed cert, SHA-1
q $FRESH -h sha1 -n "Windows Update Helper" -time $NOW $TSA -TSA-time $NOW -in $B/base_impersonation.exe -out $B/svc_update.exe
# Consistent names, SHA-256 + timestamp, plus a nested SHA-1 signature
q $FRESH -h sha256 -time $NOW $TSA -TSA-time $NOW -in $B/base_consistent.exe -out $B/tmp_signed.exe
q -nest $FRESH -h sha1 -time $NOW -in $B/tmp_signed.exe -out $B/evilupdater.exe
# Expired certificate, no timestamp
q $OLD -h sha256 -time 1590000000 -in $B/base_consistent.exe -out $B/expired_no_timestamp.exe
# Timestamped at a time outside the certificate's validity
q $OLD -h sha256 -time 1690000000 $TSA -TSA-time 1690000000 -in $B/base_consistent.exe -out $B/outside_validity.exe
# Extra unauthenticated attribute inside the signature
q $FRESH -h sha256 -addUnauthenticatedBlob -in $B/base_consistent.exe -out $B/unauth_blob.exe
# Hidden payload after the signature (CVE-2013-3900 technique)
python3 make_hidden_payload.py $B/evilupdater.exe $B/hidden_payload.exe
rm -f $B/tmp_signed.exe

echo "== hostile file (attacks the analyzer with injection payloads)"
$RC $F/hostile_version.rc -O coff -o $B/ver_hostile.o
$CC -O0 $F/hostile_fixture.c $B/ver_hostile.o -o $B/hostile_base.exe -luser32
python3 make_hostile.py $B/hostile_base.exe $B/hostile_patched.exe
q -certs $B/hostile.crt -key $B/hostile.key -h sha256 -n "<svg onload=window.__pwned=21>" \
  -i "http://example.com/\"><img src=x onerror=window.__pwned=22>" -time $NOW $TSA -TSA-time $NOW \
  -in $B/hostile_patched.exe -out "$B/\"><img src=x onerror=window.__pwned=30>.exe"

if [[ "${1:-}" == "--with-real-signed" ]]; then
  echo "== genuinely signed third-party files (not committed)"
  pip download msvc-runtime --platform win_amd64 --only-binary=:all: --no-deps -d $B/wheel -q
  python3 -c "import zipfile,glob; z=zipfile.ZipFile(glob.glob('$B/wheel/*.whl')[0]); open('$B/vcruntime140.dll','wb').write(z.read([n for n in z.namelist() if n.endswith('Scripts/vcruntime140.dll')][0]))"
  curl -sL -o $B/npp_installer.exe https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7.1/npp.8.7.1.Installer.x64.exe
  cp $B/npp_installer.exe $B/npp_tampered.exe && printf '\x90' | dd of=$B/npp_tampered.exe bs=1 seek=5000 conv=notrunc 2>/dev/null
  python3 make_hidden_payload.py $B/vcruntime140.dll $B/ms_hidden_payload.dll
fi
echo "done: test files are in tests/build/"
