"""PE2Detect verification suite.

Loads ../index.html in a headless browser, analyzes every file in tests/build/,
and compares the results with independent reference tools:
  - pefile          (import tables)
  - GNU strings     (string extraction counts)
  - signify         (Authenticode hashes, thumbprints, serials; optional)
It also checks the expected findings for each test file, that the page makes
no network requests, and that corrupted files never crash the page.

Run:  python3 build_fixtures.sh [--with-real-signed]   then   python3 verify.py
"""
import asyncio, base64, hashlib, random, re, struct, subprocess, sys, tempfile
from pathlib import Path
import pefile
from playwright.async_api import async_playwright

HERE = Path(__file__).parent
PAGE = (HERE.parent / "index.html").resolve().as_uri()
BUILD = HERE / "build"
results = []

def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))

async def load(page, path):
    await page.set_input_files("#fileInput", str(path))
    await page.wait_for_selector("#results:not(.hidden)", timeout=15000)
    await page.wait_for_timeout(300)

async def back(page):
    await page.click("#resetBtn")

async def text(page, selector):
    el = await page.query_selector(selector)
    return await el.inner_text() if el else ""

# ---------------------------------------------------------------- checks
async def check_privacy(page):
    print("\nPrivacy")
    requests = []
    page.on("request", lambda r: requests.append(r.url))
    await load(page, BUILD / "network.exe"); await back(page)
    external = [u for u in requests if not u.startswith(("file:", "data:"))]
    check("page makes no network requests", not external, ", ".join(external[:3]))
    exfil = await page.evaluate('() => fetch("https://example.com/x").then(() => "sent").catch(() => "blocked")')
    check("Content Security Policy blocks an exfiltration attempt", exfil == "blocked", exfil)

async def check_imports(page, files):
    print("\nImport tables vs pefile")
    for f in files:
        pe = pefile.PE(str(f))
        expected = [(e.dll.decode(), [i.name.decode() for i in e.imports if i.name])
                    for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
        await load(page, f)
        got = await page.eval_on_selector_all("#importsPanel details", """ds => ds.map(d => [d.querySelector('.dll').textContent,
              [...d.querySelectorAll('.fn')].map(x => x.childNodes[0].textContent).filter(n => !n.startsWith('Ordinal'))])""")
        check(f"{f.name}: every DLL and function matches", [tuple(x) for x in got] == [(d, n) for d, n in expected])
        await back(page)

async def check_strings(page, files):
    print("\nString extraction vs GNU strings")
    for f in files:
        ascii_n = len(subprocess.run(["strings", "-a", "-n", "5", str(f)], capture_output=True, text=True).stdout.splitlines())
        wide_n = len(subprocess.run(["strings", "-a", "-el", "-n", "5", str(f)], capture_output=True, text=True).stdout.splitlines())
        await load(page, f)
        note = await text(page, "#stringsPanel .panel-note")
        check(f"{f.name}: {ascii_n} ASCII and {wide_n} wide strings", f"{ascii_n:,} ASCII and {wide_n:,} wide" in note, note[:80])
        await back(page)

EXPECTED = {
    "imports-64.exe":        ["Injects code into another process", "Records keystrokes", "Communicates over HTTP", "Manipulates access tokens"],
    "packed-32.exe":         ["Likely packed or obfuscated", "named like UPX"],
    "strings.exe":           ["Deletes shadow copies", "Ransom note wording", "Run / RunOnce registry key", "Tor .onion address",
                              "Telegram bot API", "Tampers with Microsoft Defender", "Mining pool protocol"],
    "network.exe":           ["hxxp[://]203[.]0[.]113[.]50:8080/gate.php", "Raw IP host", "Links to a file download", "Possibly a version number"],
    "corroboration.exe":     ["Corroborated by strings"],
    "update_helper.exe":     ["Suspicious signature", "Self-signed certificate", "outdated SHA-1", "does not match the CompanyName \"Lumora Software Inc.\"", "lumora_update.exe"],
    "evilupdater.exe":       ["nested SHA-1", "Self-signed certificate"],
    "expired_no_timestamp.exe": ["No timestamp", "has expired and there is no timestamp"],
    "outside_validity.exe":  ["when the certificate was not valid"],
    "unauth_blob.exe":       ["Unrecognized unsigned attribute"],
    "hidden_payload.exe":    ["hidden after the signature", "Match: the file has not changed since signing"],
    "vcruntime140.dll":      ["Signed: no suspicious indicators", "Microsoft Windows Software Compatibility Publisher"],
    "npp_tampered.exe":      ["modified after it was signed"],
    "ms_hidden_payload.dll": ["hidden after the signature", "Microsoft Corporation"],
}

async def check_findings(page):
    print("\nExpected findings per test file")
    for name, needles in EXPECTED.items():
        f = BUILD / name
        if not f.exists():
            continue
        await load(page, f)
        body = await text(page, "#results")
        missing = [n for n in needles if n.lower() not in body.lower()]
        check(f"{name}: {len(needles)} expected findings", not missing, "missing: " + "; ".join(missing))
        if name == "network.exe":
            ioc_table = await text(page, ".netioc")
            check("network.exe: indicators shown only in defanged form", "http://" not in ioc_table and "https://" not in ioc_table)
            benign = await page.eval_on_selector("details.benign", "d => d.textContent")   # collapsed, so read all text
            check("network.exe: XML namespace URL set aside as routine", "schemas[.]microsoft[.]com" in benign)
        await back(page)


async def check_signer_rules(page):
    print("\nSigner rules tested directly (made-up data, no test binary)")
    result = await page.evaluate("""() => {
        const signedBy = org => ({ status: "signed", hashMatches: true, hidden: [], unknownUnauth: [], nested: [],
            digest: { name: "SHA-256", weak: false }, timestamp: null, claimedSigningTime: null,
            cert: { subject: { fields: { O: org, CN: org }, text: "CN=" + org + ", O=" + org, rawHex: "aa" }, issuer: { rawHex: "bb" },
                    eku: null, policies: [], keyAlg: "RSA", keyBits: 2048,
                    notBefore: new Date("2024-01-01"), notAfter: new Date("2027-01-01") } });
        const red = (sig, ver, name) => assessSigner(sig, ver, name, { flag: null }, 0).red.map(r => r.strength + ": " + r.text);
        return {
            brand: red(signedBy("Some Signer LLC"), { CompanyName: "Adobe Inc.", ProductName: "Adobe Reader" }, "reader.exe"),
            systemFile: red(signedBy("Some Signer LLC"), { CompanyName: "Some Signer LLC", OriginalFilename: "lsass.exe" }, "lsass.exe"),
            fictional: red(signedBy("Some Signer LLC"), { CompanyName: "Lumora Software Inc." }, "update.exe"),
        };
    }""")
    check("a known brand in the version info with a different signer is a strong finding",
          any(r.startswith("strong") and "claims to be from Adobe" in r for r in result["brand"]), str(result["brand"]))
    check("a Windows system file name with a non-Windows signer is a strong finding",
          any(r.startswith("strong") and 'Windows file "lsass.exe"' in r for r in result["systemFile"]), str(result["systemFile"]))
    check("an unknown company name that differs from the signer is only a weak finding",
          result["fictional"] and all(r.startswith("weak") for r in result["fictional"]), str(result["fictional"]))

async def check_signatures(page, files):
    print("\nAuthenticode parsing vs signify")
    try:
        from signify.authenticode import AuthenticodeFile
    except Exception as err:
        print(f"  SKIP  signify not available ({type(err).__name__}); see tests/README.md")
        return
    for f in files:
        with open(f, "rb") as fh:
            sd = next(AuthenticodeFile.from_stream(fh).iter_embedded_signatures())
            cert = next(c for c in sd.certificates if c.issuer == sd.signer_info.issuer and c.serial_number == sd.signer_info.serial_number)
            want = {"hash": sd.indirect_data.digest.hex(), "sha1": hashlib.sha1(cert.to_der).hexdigest(), "serial": cert.serial_number}
        await load(page, f)
        rows = dict(await page.eval_on_selector_all("#signaturePanel .hash-row", "rs => rs.map(r => [r.querySelector('b').textContent, r.querySelector('code').textContent])"))
        ok = (rows.get("Signed", "").split(" ")[-1] == want["hash"] and rows.get("SHA-1") == want["sha1"]
              and int(rows.get("Serial", "0"), 16) == want["serial"])
        check(f"{f.name}: signed hash, thumbprint and serial match", ok, str(rows)[:120])
        await back(page)

async def check_fuzz(page, sources):
    print("\nRobustness: corrupted files must never crash the page")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    random.seed(7)
    with tempfile.TemporaryDirectory() as tmp:
        count = 0
        for src in sources:
            data = src.read_bytes()
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            opt = pe_off + 24
            dirs = opt + (112 if struct.unpack_from("<H", data, opt)[0] == 0x20B else 96)
            sec_off, sec_size = struct.unpack_from("<II", data, dirs + 32)
            region = (sec_off, sec_off + sec_size) if sec_size else (64, min(len(data), 4096))
            for i in range(15):
                b = bytearray(data)
                for _ in range(random.choice([1, 10, 100])):
                    b[random.randrange(*region)] = random.randrange(256)
                path = Path(tmp) / f"fuzz_{src.stem}_{i}.exe"
                path.write_bytes(b)
                await page.set_input_files("#fileInput", str(path)); await page.wait_for_timeout(250)
                count += 1
        check(f"{count} corrupted files handled without a page error", not errors, "; ".join(errors[:2]))


async def check_security(page):
    print("\nSecurity: hostile files must never run code in the page")
    html = (HERE.parent / "index.html").read_text(encoding="utf-8")
    script = re.findall(r"<script>(.*?)</script>", html, flags=re.S)
    want = "sha256-" + base64.b64encode(hashlib.sha256(script[0].encode()).digest()).decode()
    check("CSP hash matches the script (run tools/update_csp_hash.py after edits)", len(script) == 1 and f"'{want}'" in html)

    # Defense in depth: even injected markup with an event handler must not run
    blocked = await page.evaluate("""() => new Promise(done => {
        const d = document.createElement("div");
        d.innerHTML = '<img src="data:," onerror="window.__cspFail = 1"><img src="x" onerror="window.__cspFail = 1">';
        document.body.appendChild(d);
        setTimeout(() => { d.remove(); done(window.__cspFail === undefined); }, 400);
    })""")
    check("CSP refuses inline event handlers injected into the page", blocked)

    dialogs = []
    page.on("dialog", lambda dlg: (dialogs.append(dlg.message), asyncio.ensure_future(dlg.dismiss())))
    hostile = next(BUILD.glob("*pwned=30*.exe"))
    for how in ["file picker", "drag and drop"]:
        if how == "file picker":
            await load(page, hostile)
        else:
            data = list(hostile.read_bytes())
            url_before = page.url
            downloads = []
            page.on("download", lambda d: downloads.append(d))
            await page.evaluate("""([bytes, name]) => {
                const file = new File([new Uint8Array(bytes)], name);
                const dt = new DataTransfer(); dt.items.add(file);
                for (const type of ["dragenter", "dragover", "drop"])
                    document.dispatchEvent(new DragEvent(type, { dataTransfer: dt, bubbles: true, cancelable: true }));
            }""", [data, hostile.name])
            await page.wait_for_selector("#results:not(.hidden)", timeout=15000); await page.wait_for_timeout(500)
            check("dropping a file never navigates to it or downloads it", page.url == url_before and not downloads)
        # open every collapsed section and hover everything, to trigger any hidden handler
        await page.evaluate("document.querySelectorAll('details').forEach(d => d.open = true)")
        await page.hover("#results"); await page.wait_for_timeout(300)
        state = await page.evaluate("""() => ({
            pwned: window.__pwned,
            handlers: document.querySelectorAll("[onerror],[onload],[onmouseover],[onclick]").length,
            frames: document.querySelectorAll("iframe,object,embed").length,
            scripts: document.querySelectorAll("script").length,
            injectedTags: document.querySelectorAll("#results svg, #results img, #results i").length,
            shownAsText: document.getElementById("results").innerText.includes("<img src=x onerror=window.__pwned=10>"),
            prototypeIntact: Object.getPrototypeOf({}) === Object.prototype && ({}).polluted === undefined,
        })""")
        ok = (state["pwned"] is None and state["handlers"] == 0 and state["frames"] == 0 and state["scripts"] == 1
              and state["injectedTags"] == 0 and not dialogs and state["prototypeIntact"])
        check(f"hostile file via {how}: no payload ran, no markup injected, no dialog", ok, str(state))
        check(f"hostile file via {how}: payloads are displayed as plain text", state["shownAsText"])
        await back(page)

async def check_size_limit(page):
    print("\nFile size limit")
    with tempfile.TemporaryDirectory() as tmp:
        big = Path(tmp) / "too_big.exe"
        with open(big, "wb") as f:
            f.write(b"MZ"); f.seek(100 * 1024 * 1024); f.write(b"\0")   # just over 100 MB
        await page.set_input_files("#fileInput", str(big)); await page.wait_for_timeout(800)
        message = await text(page, "#errorBox")
        check("files over 100 MB are refused with a clear message", "up to 100.0 MB" in message and await page.is_hidden("#results"), message)
    check("start screen states the 100 MB limit", "up to 100 MB" in await page.inner_text("#dropZone"))

async def check_wording_and_notes(page):
    print("\nWording and notes")
    found = set()
    for name in ["imports-64.exe", "update_helper.exe", "network.exe", "packed-32.exe", "vcruntime140.dll"]:
        f = BUILD / name
        if not f.exists():
            continue
        await load(page, f)
        # Remove everything that shows the file's own content; what remains is the tool's wording
        words = await page.evaluate("""() => {
            const clone = document.getElementById("results").cloneNode(true);
            clone.querySelectorAll("code, .fn, .dll, .strings-table, td.ioc, dd, .filename, ul.chain, .str-hit-text, details.dll")
                 .forEach(n => n.remove());
            return (clone.textContent.match(/\\b(clean|malware|malicious|benign)\\b/gi) || []);
        }""")
        found.update(w.lower() for w in words)
        await back(page)
    check('the interface never calls a file "clean" or "malware"', not found, ", ".join(sorted(found)))
    hero = await page.inner_text("#dropZone")
    footer = await page.inner_text(".site-footer")
    check("start screen says: reference only, not a final verdict, use a sandbox or VM",
          "final verdict" in hero and "sandbox or virtual machine" in hero)
    check("footer has the independent-project and sandbox/VM disclaimers", "Independent project" in footer and "sandbox or virtual machine" in footer)
    await load(page, BUILD / "imports-64.exe")
    check("every report starts with 'Indicators, not a verdict'", "Indicators, not a verdict" in await text(page, ".reference-note"))
    await back(page)

async def main():
    if not BUILD.exists():
        sys.exit("tests/build/ not found: run ./build_fixtures.sh first")
    print(f"Testing {PAGE}")
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1280, "height": 900})
        page.on("pageerror", lambda e: results.append(False) or print("  FAIL  page error:", e))
        await page.goto(PAGE)
        pe_files = [BUILD / n for n in ["imports-32.exe", "imports-64.exe", "packed-32.exe", "corroboration.exe"]]
        await check_privacy(page)
        await check_security(page)
        await check_wording_and_notes(page)
        await check_size_limit(page)
        await check_imports(page, pe_files + [f for f in [BUILD / "npp_installer.exe"] if f.exists()])
        await check_strings(page, [BUILD / n for n in ["strings.exe", "network.exe", "imports-64.exe"]])
        await check_findings(page)
        await check_signer_rules(page)
        signed = [BUILD / n for n in ["update_helper.exe", "evilupdater.exe", "expired_no_timestamp.exe", "outside_validity.exe",
                                      "vcruntime140.dll", "npp_installer.exe"] if (BUILD / n).exists()]
        await check_signatures(page, signed)
        await check_fuzz(page, [BUILD / "imports-64.exe", BUILD / "update_helper.exe"])
        await browser.close()
    passed = sum(results)
    print(f"\n{passed} of {len(results)} checks passed")
    sys.exit(0 if all(results) else 1)

asyncio.run(main())
