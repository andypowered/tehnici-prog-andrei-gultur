import requests

SITES = [
    # Pagini obișnuite (Părțile 2, 3 și 4)
    "https://example.com",
    "https://httpbin.org/html",
    "https://httpbin.org/json",
    "https://httpbin.org/status/200",
    "https://httpbin.org/redirect/1",
    "https://httpbin.org/delay/2",
    # Pagini care eșuează
    "https://httpbin.org/status/404",
    "https://httpbin.org/status/500",
    "https://httpbin.org/delay/10",
    "http://this-site-does-not-exist.invalid",
    # Anteturi de securitate (Partea 5)
    "https://httpbin.org/response-headers?X-Frame-Options=DENY&X-Content-Type-Options=nosniff",
    "https://httpbin.org/response-headers?x-frame-options=DENY",
    # Răspunde aleatoriu cu 200 sau 500 (Partea 6)
    "https://httpbin.org/status/200,500",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def build_url(host, path):
    """Returnează o adresă completă, de exemplu https://example.com/login."""
    if path.startswith("/"):
        return "https://" + host + path
    else:
        return "https://" + host + "/" + path


def is_https(url):
    """Returnează True dacă adresa începe cu https://, altfel False."""
    if url.startswith("https://"):
        return True
    else:
        return False


def show_response(url):
    """Trimite un GET la url și afișează statusul și Content-Type."""
    try:
        r = requests.get(url, timeout=5)
        print("Status:", r.status_code)
        print("Content-Type:", r.headers.get("Content-Type", "unknown"))
    except Exception as e:
        print("Status: None")
        print("Eroare:", str(e))


def check_site(url):
    """Returnează un dicționar cu: status, content_type, length, server."""
    try:
        r = requests.get(url, timeout=5)
        status = r.status_code
        content_type = r.headers.get("Content-Type", "unknown")
        length = len(r.content)
        server = r.headers.get("Server", "unknown")
        return {"status": status, "content_type": content_type, "length": length, "server": server}
    except Exception as e:
        return {"status": None, "error": str(e)}






def scan_sites():
    """Verifică toate site-urile din SITES, afișează-le pe cele care merg și un rezumat."""
    results = []
    for url in SITES:
        res = check_site(url)


        results.append((url, res))

    bune = []
    for url, res in results:
        if res.get("status") == 200:
            bune.append((url, res))

    bune.sort(key=lambda x: x[1]["length"], reverse=True)

    for url, res in bune:
        print(f"{url} -> {res['status']}, {res['length']} octeți")

    reusite = len(bune)


    esuate = len(SITES) - reusite
    print(f"Resuite: {reusite} | Esuate: {esuate}")




def check_headers(url):
    """Returnează un dicționar cu: present, missing, score."""
    try:
        r = requests.get(url, timeout=5)
    except Exception as e:


        return {"status": None, "error": str(e)}

    mici = {}
    for k, v in r.headers.items():
        mici[k.lower()] = v


    present = []
    missing = []
    for h in SECURITY_HEADERS:
        if h.lower() in mici:
            present.append(h)

        else:


            missing.append(h)

    score = int(len(present) * 100 / len(SECURITY_HEADERS))
    return {"present": present, "missing": missing, "score": score}


def retry_check(url, attempts=3):
    """Încearcă de cel mult `attempts` ori; returnează un dicționar cu: status, attempts."""
    last_status = None
    last_error = ""
    for i in range(1, attempts + 1):
        try:


            r = requests.get(url, timeout=5)
            if r.status_code < 500:
                return {"status": r.status_code, "attempts": i}
            else:
                last_status = r.status_code
        except Exception as e:
            last_status = None
            last_error = str(e)


    if last_status is None:
        return {"status": None, "error": last_error, "attempts": attempts}
    else:
        return {"status": last_status, "attempts": attempts}
