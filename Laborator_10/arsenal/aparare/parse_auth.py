"""Parseaza un jurnal auth.log si numara esecurile de autentificare.

Fiecare functie intoarce un rezultat; tiparirea se face doar in main().
Astfel functiile pot fi legate intre ele si refolosite de detector.
"""

import argparse
import re
from collections import Counter
from pathlib import Path

TIPAR = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")

CALE_IMPLICITA = Path(__file__).resolve().parent / "start" / "auth.log"


def esec(linie):
    """Intoarce (user, ip) daca linia e un esec de autentificare, altfel None."""
    m = TIPAR.search(linie)
    if m is None:
        return None
    return (m.group(1), m.group(2))


def citeste_esecuri(cale):
    """Citeste jurnalul si intoarce lista de dict-uri {"user": ..., "ip": ...}."""
    esecuri = []
    try:
        f = open(cale, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        print("nu gasesc", cale)
        return esecuri
    except OSError as exc:
        print("nu pot citi", cale, "-", exc)
        return esecuri

    with f:
        for linie in f:
            r = esec(linie)
            if r is not None:
                esecuri.append({"user": r[0], "ip": r[1]})
    return esecuri


def pe_ip(esecuri):
    """Intoarce un Counter cu numarul de esecuri pentru fiecare adresa IP."""
    return Counter(e["ip"] for e in esecuri)


def main(argv=None):
    p = argparse.ArgumentParser(description="Numara esecurile de autentificare pe IP.")
    p.add_argument("log", nargs="?", default=str(CALE_IMPLICITA), help="calea catre auth.log")
    a = p.parse_args(argv)

    esecuri = citeste_esecuri(a.log)
    counts = pe_ip(esecuri)

    print(f"Esecuri de autentificare: {len(esecuri)}")
    for ip, n in counts.most_common():
        print(f"  {ip}: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
