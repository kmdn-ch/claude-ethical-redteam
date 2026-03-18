import os
import requests

LOGS_DIR = "logs"
WORDLISTS_DIR = os.path.join(LOGS_DIR, "wordlists")
PATT_BASE = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"

# category → path in the PATT repo (URL-encoded spaces)
CATEGORIES = {
    "sqli":           "SQL%20Injection/Intruder/SQL-Injection-Generic.txt",
    "sqli-error":     "SQL%20Injection/Intruder/SQL-Injection-Error-Based.txt",
    "xss":            "XSS%20Injection/Intruder/XSS-without-HTML.txt",
    "xss-html":       "XSS%20Injection/Intruder/XSS-with-HTML.txt",
    "lfi":            "File%20Inclusion/Intruder/Linux-Traversal.txt",
    "lfi-windows":    "File%20Inclusion/Intruder/Windows-Traversal.txt",
    "cmdi":           "Command%20Injection/Intruder/command-execution-unix.txt",
    "cmdi-windows":   "Command%20Injection/Intruder/command-execution-windows.txt",
    "ssrf":           "Server%20Side%20Request%20Forgery/Intruder/SSRF.txt",
    "ssti":           "Server%20Side%20Template%20Injection/Intruder/Generic.txt",
    "open-redirect":  "Open%20Redirect/Intruder/Open-Redirect.txt",
    "xxe":            "XXE%20Injection/Intruder/xxe.txt",
    "path-traversal": "Path%20Traversal/Intruder/path-traversal.txt",
}


def run(category: str, for_ffuf: bool = False, ffuf_url: str = "") -> str:
    if category.lower() == "list":
        lines = "\n".join(f"  • {k}" for k in CATEGORIES)
        return f"📚 Available PATT categories:\n{lines}"

    path = CATEGORIES.get(category.lower())
    if not path:
        keys = ", ".join(CATEGORIES)
        return f"❌ Unknown category '{category}'. Available: {keys}"

    url = f"{PATT_BASE}/{path}"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        payloads = [l for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
    except Exception as e:
        return f"❌ Failed to fetch PATT payloads: {str(e)}"

    if not payloads:
        return f"⚠️ No payloads found for category '{category}'"

    os.makedirs(WORDLISTS_DIR, exist_ok=True)
    wordlist_path = os.path.join(WORDLISTS_DIR, f"patt_{category}.txt")
    with open(wordlist_path, "w", encoding="utf-8") as f:
        f.write("\n".join(payloads))

    preview = "\n".join(f"  {p}" for p in payloads[:10])
    result = (
        f"✅ PATT '{category}' – {len(payloads)} payloads fetched\n"
        f"Saved: {wordlist_path}\n"
        f"Preview:\n{preview}"
        + (f"\n  ... +{len(payloads) - 10} more" if len(payloads) > 10 else "")
    )

    if for_ffuf and ffuf_url:
        from .ffuf import run as ffuf_run
        ffuf_result = ffuf_run(url=ffuf_url, wordlist=wordlist_path)
        result += f"\n\n--- ffuf with PATT {category} payloads ---\n{ffuf_result}"

    return result


TOOL_SPEC = {
    "name": "run_payloads",
    "description": (
        "Fetch payload lists from PayloadsAllTheThings (PATT) by attack category. "
        "Use standalone to inspect payloads, or set for_ffuf=true with a ffuf_url "
        "containing a FUZZ placeholder to immediately fuzz the target with those payloads. "
        "Use category='list' to see all available categories."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "category": {
                "type": "string",
                "description": (
                    "Attack category: sqli, sqli-error, xss, xss-html, lfi, lfi-windows, "
                    "cmdi, cmdi-windows, ssrf, ssti, xxe, open-redirect, path-traversal — "
                    "or 'list' to see all"
                ),
            },
            "for_ffuf": {
                "type": "boolean",
                "description": "If true, run ffuf immediately with the fetched payloads",
            },
            "ffuf_url": {
                "type": "string",
                "description": (
                    "Target URL for ffuf — must contain FUZZ placeholder, "
                    "e.g. https://target.com/page?id=FUZZ (required when for_ffuf=true)"
                ),
            },
        },
        "required": ["category"],
    },
}
