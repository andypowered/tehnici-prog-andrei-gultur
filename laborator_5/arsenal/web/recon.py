import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from arsenal.web.client import cere

CUVINTE = ["admin", "login", "backup", "config", "test", "uploads", "phpmyadmin"]


def amprenta(tinta):
    r = cere(tinta)
    return {
        "cod": r.status_code,
        "server": r.headers.get("Server"),
        "x_powered_by": r.headers.get("X-Powered-By"),
    }


def citeste_robots(tinta):
    r = cere(tinta.rstrip("/") + "/robots.txt")
    if r.status_code != 200:
        return []
    linii = []
    for linie in r.text.splitlines():
        if linie.strip().lower().startswith("disallow:"):
            linii.append(linie.strip())
    return linii


def descopera(tinta, cuvinte):
    gasite = []
    interzise = []
    for c in cuvinte:
        url = tinta.rstrip("/") + "/" + c
        try:
            r = cere(url, allow_redirects=False)
        except Exception as e:
            print("eroare:", c, e)
            continue
        if r.status_code == 200:
            gasite.append(c)
        elif r.status_code == 403:
            interzise.append(c)
            print("interzis (interesant):", c)
    return gasite, interzise


def extrage_linkuri(tinta):
    r = cere(tinta)
    linkuri = re.findall(r'href="([^"]+)"', r.text)
    return sorted(set(linkuri))


def citeste_wordlist(cale):
    cuvinte = []
    with open(cale, encoding="utf-8") as f:
        for linie in f:
            linie = linie.strip()
            if linie:
                cuvinte.append(linie)
    return cuvinte


def main():
    p = argparse.ArgumentParser(description="Recon web: antete, robots, directoare, linkuri.")
    p.add_argument("tinta")
    p.add_argument("--wordlist", default=None)
    p.add_argument("--output", default=str(Path(__file__).with_name("fisa.json")))
    a = p.parse_args()

    cuvinte = citeste_wordlist(a.wordlist) if a.wordlist else CUVINTE
    info = amprenta(a.tinta)
    print("cod:", info["cod"])
    print("Server:", info["server"])
    print("X-Powered-By:", info["x_powered_by"])

    robots = citeste_robots(a.tinta)
    print("robots.txt:")
    for linie in robots:
        print("   ", linie)

    gasite, interzise = descopera(a.tinta, cuvinte)
    print("gasite:", gasite)
    print("interzise:", interzise)

    linkuri = extrage_linkuri(a.tinta)
    print("linkuri:")
    for link in linkuri:
        print("   ", link)

    fisa = {
        "tinta": a.tinta,
        "cod": info["cod"],
        "server": info["server"],
        "x_powered_by": info["x_powered_by"],
        "robots": robots,
        "directoare": gasite,
        "interzise": interzise,
        "linkuri": linkuri,
    }
    Path(a.output).write_text(json.dumps(fisa, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("fisa salvata:", a.output)


if __name__ == "__main__":
    main()
