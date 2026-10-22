"""Lucrarea B (B1-B4) — Forensics pe fisiere (Laboratorul 6).

B1 magic bytes: tipul real al fisierului, nu extensia.
B2 strings: secventele de text citibil dintr-un binar.
B3 EXIF/GPS: metadatele pozei, cu coordonatele in grade zecimale.
B4 carving: extrage arhiva ZIP lipita la coada unui PNG.

Utilizare (din directorul laborator_6/):
    python -m arsenal.forensics.forensics probe/foto.jpg
    python -m arsenal.forensics.forensics probe/ascuns.png --carve gasit.zip
    python -m arsenal.forensics.forensics proba.bin --doar tip
"""

import argparse
import re
import zipfile
from pathlib import Path

from PIL import Image
from PIL.ExifTags import TAGS, IFD, GPSTAGS

# ------------------------------------------------- B1. Magic bytes: tipul real
# Primele octeti spun adevarul; extensia poate minti. Deschidem mereu "rb":
# fara modul binar, octetii se pot altera la citire (newline-uri, encodari).
SEMNATURI = [
    (b"%PDF", "pdf"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8", "jpeg"),
    (b"PK\x03\x04", "zip/docx"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
]


def tip_real(cale):
    """Citeste primii octeti si intoarce tipul real ('png', 'jpeg', ...)."""
    # TODO(B1): cap = open(cale, "rb").read(8); compara cu semnaturile
    cap = open(cale, "rb").read(8)
    for semn, tip in SEMNATURI:
        if cap.startswith(semn):
            return tip
    return "necunoscut (" + cap.hex() + ")"


# ------------------------------------------------- B2. strings: textul din binar
def strings(cale, minim=4):
    """Scoate secventele imprimabile (regex pe octeti) dintr-un fisier."""
    # TODO(B2): for m in re.findall(rb"[ -~]{4,}", date)
    date = open(cale, "rb").read()
    gasite = []
    for m in re.findall(rb"[ -~]{" + str(minim).encode() + rb",}", date):
        gasite.append(m.decode())
    return gasite


# ------------------------------------------------- B3. Metadate EXIF si GPS din poza
def dms_la_zecimal(dms, emisfera):
    """(grade, minute, secunde) + emisfera -> grade zecimale (S/V negative)."""
    try:
        grade = float(dms[0]) + float(dms[1]) / 60.0 + float(dms[2]) / 3600.0
    except (TypeError, IndexError, ValueError):
        return None
    if emisfera in ("S", "W"):
        grade = -grade
    return grade


def citeste_exif(cale):
    """Intoarce (etichete, gps_zecimal). Etichete: {nume_tag: valoare}."""
    img = Image.open(cale)
    # _getexif() e vechi; getexif() e API-ul nou — incercam ambele.
    try:
        exif = img.getexif()
    except AttributeError:  # pragma: no cover
        exif = img._getexif() or {}
    etichete = {}
    for id_tag, val in (dict(exif).items() if exif else []):
        etichete[TAGS.get(id_tag, id_tag)] = val
    gps_zecimal = None
    if exif:
        # TODO(B3): ia blocul GPS (tag 34853) si converteste lat/lon
        gps = exif.get_ifd(IFD.GPSInfo)
        if gps:
            nume = {GPSTAGS.get(k, k): v for k, v in gps.items()}
            lat = dms_la_zecimal(gps.get(2), gps.get(1))
            lon = dms_la_zecimal(gps.get(4), gps.get(3))
            if lat is not None and lon is not None:
                gps_zecimal = {"lat": lat, "lon": lon, "brut": nume}
    return etichete, gps_zecimal


# ------------------------------------------------- B4. File carving: fisierul ascuns
def carve(cale, iesire="gasit.zip", semnatura=b"PK\x03\x04"):
    """Cauta semnatura ZIP si scrie tot ce urmeaza intr-un fisier separat."""
    # TODO(B4): i = date.find(b"PK\x03\x04"); scrie date[i:] in gasit.zip
    date = open(cale, "rb").read()
    i = date.find(semnatura)
    if i == -1:
        return None
    Path(iesire).write_bytes(date[i:])
    return {"offset": i, "iesire": iesire, "dimensiune": len(date) - i}


def arata_continut_zip(cale_zip):
    """Listeaza fisierele dintr-o arhiva (dupa carving, vezi ce era inauntru)."""
    with zipfile.ZipFile(cale_zip) as z:
        return z.namelist()


def construieste_parser():
    p = argparse.ArgumentParser(description="Forensics pe fisiere: B1-B4.")
    p.add_argument("cale", help="fisierul de analizat")
    p.add_argument("--doar", default=None,
                   choices=["tip", "strings", "exif", "carve"],
                   help="ruleaza doar o etapa")
    p.add_argument("--minim", type=int, default=4,
                   help="lungimea minima pentru strings")
    p.add_argument("--carve-out", default="gasit.zip",
                   help="unde se salveaza fisierul extras prin carving")
    return p


def main(argv=None):
    a = construieste_parser().parse_args(argv)
    doar = a.doar

    if doar is None or doar == "tip":
        print(f"[B1] tip real: {tip_real(a.cale)}")

    if doar is None or doar == "strings":
        siruri = strings(a.cale, a.minim)
        print(f"[B2] {len(siruri)} secvente citibile (primele 30):")
        for s in siruri[:30]:
            print("   ", s)

    if doar is None or doar == "exif":
        etichete, gps = citeste_exif(a.cale)
        print("[B3] EXIF:")
        for nume, val in etichete.items():
            print(f"    {nume} = {val}")
        # TODO(B3): tipareste latitudinea si longitudinea
        if gps:
            print(f"[B3] GPS: lat={gps['lat']:.6f} lon={gps['lon']:.6f}")
            print("     (pune coordonatele pe o harta: valoare OSINT; "
                   "sterge EXIF inainte de a publica poze)")
        else:
            print("[B3] GPS: lipsa")

    if doar is None or doar == "carve":
        rez = carve(a.cale, a.carve_out)
        if rez is None:
            print("[B4] nicio semnatura ZIP gasita")
        else:
            print(f"[B4] arhiva extrasa de la octetul {rez['offset']} "
                  f"-> {rez['iesire']} ({rez['dimensiune']} octeti)")
            try:
                print("[B4] continut arhiva:", arata_continut_zip(rez["iesire"]))
            except zipfile.BadZipFile:
                print("[B4] atentie: extrasul nu e un ZIP valid")


if __name__ == "__main__":
    main()
