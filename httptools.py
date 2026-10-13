import requests

BASE = "https://httpbin.org"
PATHS = ["/get", "/redirect/2", "/delay/1", "/status/404", "/delay/5"]


# Partea 1: parametri în URL
def search(params):
    """GET pe /get cu parametri în URL; returnează parametrii primiți de server."""
    r = requests.get(BASE + "/get", params=params)
    return r.json()["args"]


def search_url(params):
    """Returnează adresa completă construită de requests, cu tot cu parametri."""
    r = requests.get(BASE + "/get", params=params)
    return r.url


# Partea 2: anteturi
def fetch_with_agent(agent):
    """GET pe /headers cu User-Agent=agent; returnează User-Agent-ul văzut de server."""
    r = requests.get(BASE + "/headers", headers={"User-Agent": agent})
    return r.json()["headers"]["User-Agent"]


def default_agent():
    """Returnează User-Agent-ul trimis de requests când nu setezi nimic."""
    r = requests.get(BASE + "/headers")
    return r.json()["headers"]["User-Agent"]


# Partea 3: trimiterea datelor
def post_json(data):
    """POST cu datele ca JSON pe /post; returnează JSON-ul primit de server."""
    r = requests.post(BASE + "/post", json=data)
    return r.json()["json"]


def post_form(data):
    """POST cu datele ca formular pe /post; returnează formularul primit de server."""
    r = requests.post(BASE + "/post", data=data)
    return r.json()["form"]


# Partea 4: coduri de stare
def describe_status(code):
    """GET pe /status/<code>; returnează 'succes', 'eroare client' sau 'eroare server'."""
    r = requests.get(BASE + f"/status/{code}")
    if 200 <= r.status_code < 300:
        return "succes"
    elif 400 <= r.status_code < 500:
        return "eroare client"
    else:
        return "eroare server"


def is_ok(code):
    """GET pe /status/<code>; returnează True dacă cererea a reușit, altfel False."""
    try:
        r = requests.get(BASE + f"/status/{code}")
        r.raise_for_status()
        return True
    except requests.HTTPError:
        return False


# Partea 5: redirecționări
def count_redirects(n):
    """GET pe /redirect/<n>; returnează câte redirecționări au fost urmate."""
    r = requests.get(BASE + f"/redirect/{n}")
    return len(r.history)


def final_url(n):
    """GET pe /redirect/<n>; returnează adresa la care ai ajuns."""
    r = requests.get(BASE + f"/redirect/{n}")
    return r.url


def first_hop(n):
    """GET pe /redirect/<n> FĂRĂ a urma redirecționarea; returnează antetul Location."""
    r = requests.get(BASE + f"/redirect/{n}", allow_redirects=False)
    return r.headers["Location"]


# Partea 6: sesiuni și cookie-uri
def cookie_demo(name, value):
    """Setează un cookie, apoi citește cookie-urile înapoi folosind O SINGURĂ sesiune."""
    s = requests.Session()
    s.get(BASE + "/cookies/set", params={name: value})
    r = s.get(BASE + "/cookies")
    return r.json()["cookies"]


def no_session_demo(name, value):
    """Fă același lucru cu apeluri simple requests.get; returnează cookie-urile văzute de server."""
    requests.get(BASE + "/cookies/set", params={name: value})
    r = requests.get(BASE + "/cookies")
    return r.json()["cookies"]


# Partea 7: raportul final
def report(path):
    """Returnează un dicționar care descrie pagina de la BASE + path."""
    try:
        r = requests.get(BASE + path, timeout=3)
        return {
            "status": r.status_code,
            "final_url": r.url,
            "redirects": len(r.history),
            "seconds": r.elapsed.total_seconds(),
            "content_type": r.headers.get("Content-Type"),
        }
    except requests.RequestException as e:
        return {"status": None, "error": str(e)[:100]}


def main():
    results = []
    for path in PATHS:
        rep = report(path)
        rep["path"] = path
        results.append(rep)

    ok = [d for d in results if d.get("status") == 200]
    ok_sorted = sorted(ok, key=lambda d: d.get("seconds", 0), reverse=True)

    for d in ok_sorted:
        print(f"{d['path']} -> {d['status']}, {d.get('seconds', 0):.2f} secunde")

    reusite = len(ok)
    esuate = len(results) - reusite
    print(f"Reușite: {reusite} | Eșuate: {esuate}")


# Bonus: autentificare
def check_login(user, password):
    """Returnează True dacă serverul acceptă datele de autentificare, altfel False."""
    try:
        r = requests.get(BASE + "/basic-auth/admin/secret", auth=(user, password))
        return r.status_code == 200
    except requests.RequestException:
        return False


if __name__ == "__main__":
    main()
