"""Pin index.html's Content Security Policy to the hash of its own script.

The policy allows exactly one script to run: the one whose SHA-256 hash is
listed in the policy. Any other script, including inline event handlers such
as onerror="..." injected through a crafted file, is refused by the browser.

Run this after EVERY change to the <script> block in index.html:
    python3 tools/update_csp_hash.py
If you forget, the browser refuses the edited script and the page stops
working; tests/verify.py also fails with "CSP hash matches the script".
"""
import base64, hashlib, re, sys
from pathlib import Path

page = Path(__file__).resolve().parent.parent / "index.html"
html = page.read_text(encoding="utf-8")

scripts = re.findall(r"<script>(.*?)</script>", html, flags=re.S)
if len(scripts) != 1:
    sys.exit(f"expected exactly one inline <script>, found {len(scripts)}")
digest = base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode()

new_html, count = re.subn(r"script-src [^;\"]+", f"script-src 'sha256-{digest}'", html, count=1)
if count != 1:
    sys.exit("could not find script-src in the Content-Security-Policy meta tag")
page.write_text(new_html, encoding="utf-8")
print(f"script-src pinned to sha256-{digest}")
