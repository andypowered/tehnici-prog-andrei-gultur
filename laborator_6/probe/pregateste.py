"""Script de pregatire pentru Laboratorul 6: forensics si steganografie.

Creeaza, in acelasi director (probe/), fisierele-tinta pe care se lucreaza:
  probe/mesaj.txt     - sir in mai multe straturi (hex -> base64 -> url)
  probe/xor.bin       - text criptat cu XOR pe un octet (cheia 77)
  probe/hashuri.txt   - 3 hash-uri (md5 / sha1 / sha256)
  probe/wordlist.txt  - dictionar care contine parolele corecte
  probe/foto.jpg      - poza cu EXIF si GPS (Chisinau)
  probe/ascuns.png    - PNG cu o arhiva ZIP lipita la coada
  probe/challenge.bin - optional: hex(base64(xor(plain))) + sha256 de verificare

Rulare (din radacina laboratorului, ex. laborator_6/):
    python probe/pregateste.py
"""
import base64
import hashlib
import io
import zipfile
from pathlib import Path
from urllib.parse import quote

from PIL import Image
from PIL.ExifTags import IFD

AICI = Path(__file__).resolve().parent


def preg_mesaj():
    clar = "FLAG{straturi_multiple_decodate}"
    strat_hex = clar.encode().hex()
    strat_b64 = base64.b64encode(strat_hex.encode()).decode()
    strat_url = quote(strat_b64, safe="")
    (AICI / "mesaj.txt").write_text(strat_url + "\n", encoding="utf-8")
    print(f"[mesaj.txt] clar={clar!r} | hex->b64->url, lungime={len(strat_url)}")
    return clar


def preg_xor():
    clar = b"Mesaj secret de laborator: FLAG{xor_cu_cheie_de_un_octet}!"
    cheie = 77  # 0x4D
    criptat = bytes(b ^ cheie for b in clar)
    (AICI / "xor.bin").write_bytes(criptat)
    print(f"[xor.bin] cheie={cheie} (0x{cheie:02X}), {len(criptat)} octeti")
    return cheie, clar


def preg_hashuri():
    # (parola, algoritm) -> hash calculat cu hashlib
    parole = [("letmein", "md5"), ("qwerty", "sha1"), ("admin123", "sha256")]
    linii = []
    for parola, alg in parole:
        h = hashlib.new(alg, parola.encode()).hexdigest()
        linii.append(h)
        print(f"[hashuri.txt] {alg}({parola!r}) = {h}")
    (AICI / "hashuri.txt").write_text("\n".join(linii) + "\n", encoding="utf-8")
    wordlist = [
        "123456", "password", "123456789", "qwerty", "abc123",
        "parola", "letmein", "dragon", "master", "admin",
        "admin123", "salut123", "utm2026", "forensics", "laborator",
        "securitate", "vara2026", "test1234", "hello", "world",
    ]
    (AICI / "wordlist.txt").write_text("\n".join(wordlist) + "\n", encoding="latin1")
    print(f"[wordlist.txt] {len(wordlist)} cuvinte (contine parolele tinta)")
    return [p for p, _ in parole]


def preg_foto():
    lat_dec, lon_dec = 47.0105, 28.8638  # Chisinau, UTM FCIM
    # grade/minute/secunde pentru EXIF
    lat_dms = (47.0, 0.0, 37.8)   # 47° 0' 37.8" N
    lon_dms = (28.0, 51.0, 49.68)  # 28° 51' 49.68" E
    w, h = 400, 300
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = (x * 255 // w, y * 255 // h, 128)
    exif = img.getexif()
    exif[270] = "Laboratorul 6 - forensics si steganografie"  # ImageDescription
    exif[271] = "UTM FCIM"                                     # Make
    exif[272] = "Camera de laborator"                         # Model
    exif[305] = "Python Pillow"                               # Software
    exif[306] = "2026:10:13 10:00:00"                         # DateTime
    gps = exif.get_ifd(IFD.GPSInfo)
    gps[0] = b"\x02\x03\x00\x00"  # GPSVersionID
    gps[1] = "N"
    gps[2] = lat_dms
    gps[3] = "E"
    gps[4] = lon_dms
    gps[5] = 0  # altitudine: deasupra marii
    gps[7] = (10.0, 0.0, 0.0)  # timestamp fictiv
    cale = AICI / "foto.jpg"
    img.save(cale, "JPEG", exif=exif, quality=95)
    print(f"[foto.jpg] {w}x{h} JPEG, GPS={lat_dec}N {lon_dec}E "
          f"(DMS {lat_dms}N {lon_dms}E)")
    return lat_dec, lon_dec


def preg_ascuns():
    img = Image.new("RGB", (200, 200), (30, 90, 200))
    px = img.load()
    for y in range(200):
        for x in range(200):
            if (x // 20 + y // 20) % 2 == 0:
                px[x, y] = (200, 180, 40)
    cale = AICI / "ascuns.png"
    img.save(cale, "PNG")
    secret = "FLAG{fisier_ascuns_prin_carving}\nAcesta este fisierul extras din coada PNG-ului.\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("secret.txt", secret)
        z.comment = b"indiciu: arhiva lipita la coada PNG-ului"
    with open(cale, "ab") as f:
        f.write(buf.getvalue())
    print(f"[ascuns.png] PNG 200x200 + ZIP lipit ({len(buf.getvalue())} octeti), "
          f"contine secret.txt")
    return secret.strip().splitlines()[0]


def preg_challenge():
    clar = b"FLAG{challenge_combinat_xor_plus_base64}"
    cheie = 42  # 0x2A
    criptat = bytes(b ^ cheie for b in clar)
    strat_b64 = base64.b64encode(criptat).decode()
    strat_hex = strat_b64.encode().hex()
    (AICI / "challenge.bin").write_text(strat_hex, encoding="utf-8")
    sha = hashlib.sha256(clar).hexdigest()
    (AICI / "challenge_sha256.txt").write_text(sha + "\n", encoding="utf-8")
    print(f"[challenge.bin] hex(b64(xor(k={cheie}))), sha256(clar)={sha}")
    return clar, cheie


def main():
    AICI.mkdir(parents=True, exist_ok=True)
    preg_mesaj()
    preg_xor()
    preg_hashuri()
    preg_foto()
    preg_ascuns()
    preg_challenge()
    print("Gata. Fisiere in:", AICI)


if __name__ == "__main__":
    main()
