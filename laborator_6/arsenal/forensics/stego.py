"""Lucrarea B (B5-B6) — Steganografie LSB (Laboratorul 6).

B5 ascundere: scrie un mesaj in ultimii biti ai canalelor (R,G,B) ale
   pixelilor. Rezultatul arata identic cu originalul.
B6 dezvaluire: citeste ultimii biti, regrupeaza cate 8 -> octeti -> text,
   pana la primul octet 0 (final de mesaj). Exact inversul ascunderii.

ATENTIE: salveaza mereu in .png (fara pierdere); un .jpg recompreseaza
imaginea si distruge bitii ascunsi.

Utilizare (din directorul laborator_6/):
    python -m arsenal.forensics.stego ascunde probe/foto.jpg stego.png "FLAG{ascuns_in_pixeli}"
    python -m arsenal.forensics.stego arata stego.png
"""

import argparse
from PIL import Image


def _biti_din_octeti(date):
    return "".join(f"{x:08b}" for x in date)


def _pixeli(img):
    """Lista pixelilor, compatibil cu Pillow vechi si nou (getdata e
    depreciat in Pillow 12+)."""
    if hasattr(img, "get_flattened_data"):
        return list(img.get_flattened_data())
    return list(img.getdata())


def ascunde(gazda, mesaj, iesire):
    """Ascunde mesajul (bytes/str) in LSB-urile pozei gazda; salveaza PNG."""
    if isinstance(mesaj, str):
        mesaj = mesaj.encode()
    # octetul 0 marcheaza finalul de mesaj la dezvaluire
    biti = _biti_din_octeti(mesaj + b"\x00")
    img = Image.open(gazda).convert("RGB")
    px = _pixeli(img)
    capacitate = len(px) * 3
    if len(biti) > capacitate:
        raise ValueError(f"mesajul ({len(biti)} biti) nu incape "
                         f"in poza ({capacitate} biti)")
    # TODO(B5): pentru fiecare bit, pune-l in LSB-ul unui canal
    canale = []
    for (r, g, b) in px:
        canale += [r, g, b]
    for i, bit in enumerate(biti):
        # canal = (canal & ~1) | int(bit)
        canale[i] = (canale[i] & ~1) | int(bit)
    px_nou = [(canale[i], canale[i + 1], canale[i + 2])
              for i in range(0, len(canale), 3)]
    # TODO(B5): img.putdata(px_nou); img.save("stego.png")
    img.putdata(px_nou)
    img.save(iesire, "PNG")
    return iesire


def dezvaluie(cale):
    """Citeste LSB-urile pixelilor si reconstituie mesajul (pana la \\x00)."""
    px = _pixeli(Image.open(cale).convert("RGB"))
    # TODO(B6): aduna ultimii biti (r&1, g&1, b&1)
    biti = ""
    for (r, g, b) in px:
        biti += str(r & 1) + str(g & 1) + str(b & 1)
    # TODO(B6): grupeaza cate 8 biti -> octeti -> text
    octeti = bytearray()
    for i in range(0, len(biti), 8):
        grup = biti[i:i + 8]
        if len(grup) < 8:
            break
        val = int(grup, 2)
        if val == 0:  # opreste-te la primul octet 0 (final de mesaj)
            break
        octeti.append(val)
    return bytes(octeti).decode("utf-8", errors="replace")


def construieste_parser():
    p = argparse.ArgumentParser(description="Steganografie LSB: ascunde/arata.")
    sub = p.add_subparsers(dest="comanda", required=True)
    a = sub.add_parser("ascunde", help="ascunde un mesaj intr-o poza")
    a.add_argument("gazda", help="poza gazda (ex. probe/foto.jpg)")
    a.add_argument("iesire", help="poza rezultat (ex. stego.png, format PNG!)")
    a.add_argument("mesaj", help="mesajul de ascuns")
    b = sub.add_parser("arata", help="dezvaluie mesajul dintr-o poza")
    b.add_argument("poza", help="poza cu mesaj ascuns (ex. stego.png)")
    return p


def main(argv=None):
    a = construieste_parser().parse_args(argv)
    if a.comanda == "ascunde":
        ascunde(a.gazda, a.mesaj, a.iesire)
        print(f"mesaj ascuns in {a.iesire}")
    elif a.comanda == "arata":
        print(dezvaluie(a.poza))


if __name__ == "__main__":
    main()
