"""Lucrarea A — Decoder universal (Laboratorul 6).

Recunoaste stratul unei codari (url / hex / base64), il desface, urmareste
straturi multiple, sparge XOR cu cheie de un octet prin forta bruta si sparge
hash-uri de parole prin dictionar.

Utilizare (din directorul laborator_6/):
    python -m arsenal.forensics.decode "NTM1OTU3NTk="
    python -m arsenal.forensics.decode probe/mesaj.txt --fisier
    python -m arsenal.forensics.decode probe/xor.bin --fisier --xor
    python -m arsenal.forensics.decode <hash> --hash --wordlist probe/wordlist.txt
"""

import argparse
import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote

# ---------------------------------------------------------------- A1. Text si octeti
# Diferenta de baza: textul (str) e pentru oameni, octetii (bytes) pentru masina.
#   s = "Salut"        -> str, 5 caractere
#   b = s.encode()     -> bytes, b"Salut", b[0] == 83 (un numar, nu o litera)
#   b.hex()            -> "53616c7574" (text care reprezinta octetii)
#   bytes.fromhex(...) -> refacerea octetilor din hex
# Tot ce urmeaza lucreaza pe bytes, nu pe text.


def demo_text_octeti():
    """Incalzirea A1: arata conversiile text <-> octeti <-> hex."""
    s = "Salut"
    b = s.encode()  # bytes
    print(b, b[0])  # b'Salut' 83
    h = b.hex()
    print(h)  # 53616c7574
    print(bytes.fromhex(h))  # b'Salut'
    return b


# ------------------------------------------------- A2. Recunoasti stratul dupa forma
_RE_URL = re.compile(r"%[0-9A-Fa-f]{2}")
_RE_HEX = re.compile(r"^[0-9a-fA-F]+$")
_RE_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def ghici_strat(s):
    """Ghiceste codarea unui sir dupa caractere, fara sa decodeze.

    Ordinea conteaza: intai URL (semnul %), apoi hex (alfabet strict),
    apoi base64 (alfabetul cel mai larg). Orice altceva -> "necunoscut".
    """
    if not isinstance(s, str):
        return "necunoscut"
    t = s.strip()
    if not t:
        return "necunoscut"
    # TODO(A2): daca are %xx -> "url"
    if _RE_URL.search(t):
        return "url"
    # TODO(A2): daca doar 0-9 a-f si lungime para -> "hex"
    if len(t) >= 2 and len(t) % 2 == 0 and _RE_HEX.match(t):
        return "hex"
    # TODO(A2): daca doar A-Za-z0-9+/= -> "base64"
    if len(t) >= 4 and len(t) % 4 == 0 and _RE_B64.match(t):
        return "base64"
    return "necunoscut"


# ------------------------------------------------------ A3. Desfaci stratul recunoscut
def desfa(s):
    """Decodeaza un strat si intoarce (strat, rezultat_bytes).

    Pentru "necunoscut" intoarce sirul ca octeti, neschimbat.
    """
    strat = ghici_strat(s)
    t = s.strip()
    try:
        # TODO(A3): pentru fiecare strat, decodeaza
        if strat == "base64":
            # completeaza padding-ul lipsa, ca sa nu crape pe siruri trunchiate
            lipsa = len(t) % 4
            if lipsa:
                t = t + "=" * (4 - lipsa)
            return strat, base64.b64decode(t, validate=False)
        if strat == "hex":
            return strat, bytes.fromhex(t)
        if strat == "url":
            return strat, unquote(t).encode()
    except (binascii.Error, ValueError):
        return "necunoscut", s.encode()
    return strat, s.encode()


# ------------------------------------------------- A4. Straturi multiple, intr-o bucla
def citibil(b):
    """True daca toti octetii sunt text imprimabil ASCII (32..126)."""
    # TODO(A4): True daca toti octetii sunt 32..126
    if not b:
        return False
    return all(32 <= c < 127 for c in b)


def decodeaza_straturi(val, max_pasi=8):
    """Desface straturi repetat pana iese text citibil.

    Un rezultat intermediar (ex. base64) este si el "citibil", asa ca nu ne
    oprim la primul text citibil: continuam cat timp se mai recunoaste un
    strat SI decodarea produce tot text citibil. Ne oprim (fara bucla
    infinita: maxim max_pasi incercari) cand stratul e necunoscut sau cand
    decodarea ar produce octeti binari (semn ca am ajuns la textul clar).

    Intoarce (rezultat_str, istoric_straturi).
    """
    istoric = []
    for _ in range(max_pasi):
        strat, b = desfa(val)
        if strat == "necunoscut":
            break
        # TODO(A4): daca decodarea da octeti necitibili, val era textul clar
        if not citibil(b):
            break
        istoric.append(strat)
        # altfel val = b.decode(); continua
        val = b.decode()
        if ghici_strat(val) == "necunoscut":
            break
    return val, istoric


# --------------------------------------- A5. Spargi un XOR cu cheie de un octet
def sparge_xor(date):
    """Incearca toate cele 256 de chei; intoarce [(cheie, text)] citibile.

    Operatorul ^ e XOR: b ^ k aplica cheia pe un octet. O cheie de un octet
    are fix 256 de valori, deci le incercam pe toate (forta bruta).
    """
    gasite = []
    for k in range(256):
        clar = bytes(b ^ k for b in date)
        # TODO(A5): daca citibil(clar): pastreaza
        if citibil(clar):
            try:
                gasite.append((k, clar.decode()))
            except UnicodeDecodeError:
                continue
    return gasite


def scor_text(text):
    """Scor de 'arata a text': litere + spatii vs. punctuatie ciudata.

    Folosit ca sa alegem cheia XOR corecta dintre toti candidatii citibili.
    """
    if not text:
        return -1
    scor = sum(1 for c in text if c.isalpha() or c == " ")
    scor += 10 * text.count(" ")
    if "FLAG" in text:
        scor += 100
    return scor


def cea_mai_buna(gasite):
    """Alege (cheie, text) cu scorul maxim din candidatii XOR."""
    if not gasite:
        return None
    return max(gasite, key=lambda pereche: scor_text(pereche[1]))


# --------------------------------------------- A6. Spargi un hash prin dictionar
ALG_DUPA_LUNGIME = {32: "md5", 40: "sha1", 64: "sha256"}


def identifica_hash(tinta):
    """Identifica algoritmul dupa lungimea hash-ului hex."""
    return ALG_DUPA_LUNGIME.get(len(tinta.strip()))


def sparge_hash(tinta, cuvinte, algoritm=None):
    """Nu 'decriptezi' hash-ul: hashuiezi fiecare cuvant si compari.

    Lungimea iti spune ce algoritm sa folosesti (32 md5 / 40 sha1 / 64 sha256).
    Intoarce parola gasita sau None.
    """
    tinta = tinta.strip().lower()
    alg = algoritm or identifica_hash(tinta)
    if alg is None:
        raise ValueError(f"lungime necunoscuta ({len(tinta)}): alege md5/sha1/sha256")
    for cuv in cuvinte:
        # TODO(A6): cuv = cuv.strip(); compara hashlib.<alg>(cuv) cu tinta
        cuv = cuv.strip()
        if not cuv:
            continue
        if hashlib.new(alg, cuv.encode()).hexdigest() == tinta:
            return cuv
    return None


def citeste_cuvinte(cale):
    return Path(cale).read_text(encoding="latin1").splitlines()


# ------------------------------------------------- A7. argparse, fisa JSON si test
def construieste_parser():
    p = argparse.ArgumentParser(description="Decoder universal: straturi, XOR, hash.")
    p.add_argument("intrare", help="sir de decodat sau cale catre fisier")
    p.add_argument("--fisier", action="store_true",
                   help="trateaza intrarea ca o cale catre fisier")
    p.add_argument("--xor", action="store_true",
                   help="forta bruta XOR cu cheie de un octet (pentru fisiere binare)")
    p.add_argument("--hash", action="store_true",
                   help="sparge un hash prin dictionar")
    p.add_argument("--wordlist", default="probe/wordlist.txt",
                   help="dictionar pentru --hash")
    p.add_argument("--algoritm", default=None, choices=["md5", "sha1", "sha256"],
                   help="forteaza algoritmul de hash (altfel, dupa lungime)")
    p.add_argument("--max-pasi", type=int, default=8)
    p.add_argument("--output", default="arsenal/forensics/fisa.json",
                   help="unde se salveaza fisa JSON")
    return p


def main(argv=None):
    a = construieste_parser().parse_args(argv)

    # TODO(A7): daca a.fisier, citeste octetii din cale; altfel trateaza ca sir
    if a.hash:
        tinta = Path(a.intrare).read_text(encoding="utf-8").splitlines()[0] \
            if a.fisier else a.intrare
        tinta = tinta.strip()
        alg = a.algoritm or identifica_hash(tinta)
        parola = sparge_hash(tinta, citeste_cuvinte(a.wordlist), alg)
        print(f"hash: {tinta} ({alg}) -> {parola!r}")
        fisa = {"mod": "hash", "algoritm": alg, "tinta": tinta, "parola": parola}
    elif a.xor:
        date = Path(a.intrare).read_bytes() if a.fisier \
            else a.intrare.encode("latin1")
        gasite = sparge_xor(date)
        for k, text in gasite:
            print(f"cheie: {k} {text!r}")
        best = cea_mai_buna(gasite)
        if best is not None:
            print(f"cea mai probabila cheie: {best[0]} {best[1]!r}")
        fisa = {"mod": "xor", "sursa": a.intrare,
                "rezultate": [{"cheie": k, "text": t} for k, t in gasite],
                "cea_mai_buna": {"cheie": best[0], "text": best[1]}
                if best is not None else None}
    elif a.fisier:
        raw = Path(a.intrare).read_bytes()
        try:
            val = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            val = raw.decode("latin1").strip()
        rezultat, istoric = decodeaza_straturi(val, a.max_pasi)
        print(f"straturi: {' -> '.join(istoric)}")
        print(f"rezultat: {rezultat!r}")
        fisa = {"mod": "straturi", "sursa": a.intrare,
                "strat": istoric, "rezultat": rezultat}
    else:
        rezultat, istoric = decodeaza_straturi(a.intrare, a.max_pasi)
        print(f"straturi: {' -> '.join(istoric)}")
        print(f"rezultat: {rezultat!r}")
        fisa = {"mod": "straturi", "strat": istoric, "rezultat": rezultat}

    # TODO(A7): salveaza {strat, rezultat} in arsenal/forensics/fisa.json
    iesire = Path(a.output)
    iesire.parent.mkdir(parents=True, exist_ok=True)
    iesire.write_text(json.dumps(fisa, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    print(f"fisa salvata in {iesire}")
    return fisa


if __name__ == "__main__":
    print("--- A1. text vs. octeti ---")
    demo_text_octeti()
    print("---------------------------")
    main()
