# Laboratorul 6 — Informații invizibile: forensics și steganografie

Toate țintele sunt fișiere generate local cu `probe/pregateste.py` (repetabil,
aceleași pentru toată lumea). Nicio unealtă de aici nu a fost rulată pe
fișierele altcuiva — diferența dintre munca legală și accesul neautorizat
este permisiunea (Cod penal RM, capitolul XI).

## Pregătire

```console
$ python probe/pregateste.py
[mesaj.txt] clar='FLAG{straturi_multiple_decodate}' | hex->b64->url, lungime=92
[xor.bin] cheie=77 (0x4D), 58 octeti
[hashuri.txt] md5('letmein') = 0d107d09f5bbe40cade3de5c71e9e9b7
[hashuri.txt] sha1('qwerty') = b1b3773a05c0ed0176787a4f1574ff0075f7521e
[hashuri.txt] sha256('admin123') = 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9
[wordlist.txt] 20 cuvinte (contine parolele tinta)
[foto.jpg] 400x300 JPEG, GPS=47.0105N 28.8638E (DMS (47.0, 0.0, 37.8)N (28.0, 51.0, 49.68)E)
[ascuns.png] PNG 200x200 + ZIP lipit (235 octeti), contine secret.txt
[challenge.bin] hex(b64(xor(k=42))), sha256(clar)=dcf21b76f984153dfc1c0236b54a785439458079fad21cdeb1049de53dd24927
```

## Lucrarea A — decoderul universal (`arsenal/forensics/decode.py`)

A1: `b = "Salut".encode()` → `b'Salut'`, `b[0] == 83` (număr, nu literă);
`b.hex() == "53616c7574"`, invers cu `bytes.fromhex(...)`. Totul lucrează pe bytes.

A2: `ghici_strat` verifică în ordinea **url → hex → base64** (mai întâi `%xx`,
apoi hexul strict — lungime pară, doar `0-9a-f` — apoi base64, alfabetul cel
mai larg). Detaliu: un text clar ca `FLAG{...}` nu e confundat cu base64
pentru că `{`, `}` și `_` nu fac parte din alfabet.

A3–A4: `desfa` întoarce `(strat, bytes)`; `decodeaza_straturi` repetă până nu
se mai recunoaște niciun strat **sau** decodarea ar da octeți necitibili
(oprirea la primul text citibil ar fi greșită: și straturile intermediare
sunt citibile). Garda `max_pasi=8` ferește de bucla infinită.

**Mesajul cu straturi** (`probe/mesaj.txt` este `url(base64(hex(clar)))`):

```console
$ python -m arsenal.forensics.decode probe/mesaj.txt --fisier
straturi: url -> base64 -> hex
rezultat: 'FLAG{straturi_multiple_decodate}'
fisa salvata in arsenal/forensics/fisa.json
```

**XOR cu cheie de un octet** — forță brută peste cele 256 de valori, candidații
citibili sunt punctați (litere + spații + bonus `FLAG`):

```console
$ python -m arsenal.forensics.decode probe/xor.bin --fisier --xor
cheie: 77 'Mesaj secret de laborator: FLAG{xor_cu_cheie_de_un_octet}!'
...
cea mai probabila cheie: 77 'Mesaj secret de laborator: FLAG{xor_cu_cheie_de_un_octet}!'
```

Cheia este **77 (0x4D)**. Observație: filtrul „citibil" singur dă 13 candidați
falși (`Bj|ne/...` etc.) — departajarea prin scor a fost necesară.

**Hash-uri sparte prin dicționar** (algoritmul după lungime: 32 md5 / 40 sha1 /
64 sha256; nu „decriptăm", hașuim fiecare cuvânt și comparăm):

```console
$ python -m arsenal.forensics.decode 0d107d09f5bbe40cade3de5c71e9e9b7 --hash --wordlist probe/wordlist.txt
hash: 0d107d09f5bbe40cade3de5c71e9e9b7 (md5) -> 'letmein'
hash: b1b3773a05c0ed0176787a4f1574ff0075f7521e (sha1) -> 'qwerty'
hash: 240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9 (sha256) -> 'admin123'
```

Parole sparte: **letmein (md5), qwerty (sha1), admin123 (sha256)**.

A7: fișa JSON e în `arsenal/forensics/fisa.json`; testele (`teste/test_decode.py`,
8 teste: base64/hex/url, ordinea ghicirii, `citibil`, straturi multiple, XOR,
hash) trec 8/8 — rulate cu un executor manual, fiindcă `pytest` nu e instalat
în acest mediu (testele rămân compatibile `pytest`).

## Lucrarea B — forensics pe fișiere (`arsenal/forensics/forensics.py`, `stego.py`)

B1 — tipul real (magic bytes, citire mereu în `"rb"`):

```console
$ python -m arsenal.forensics.forensics probe/foto.jpg --doar tip
[B1] tip real: jpeg
$ python -m arsenal.forensics.forensics probe/ascuns.png --doar tip
[B1] tip real: png
```

B2 — `strings` pe `probe/ascuns.png` (regex pe octeți `rb"[ -~]{4,}"`):
printre secvențe apare indiciul **`secret.txt`** (plus `IEND`, `IHDR` din PNG).

B3 — EXIF și GPS din `probe/foto.jpg`:

```console
[B3] EXIF:
    ImageDescription = Laboratorul 6 - forensics si steganografie
    Make = UTM FCIM
    Model = Camera de laborator
    Software = Python Pillow
    DateTime = 2026:10:13 10:00:00
[B3] GPS: lat=47.010500 lon=28.863800
```

GPS: **47.010500 N, 28.863800 E (Chișinău)** — se pot pune pe hartă (valoare
OSINT); de aceea se șterge EXIF înainte de a publica poze. Coordonatele vin ca
DMS + emisferă și se convertesc cu `grade + minute/60 + secunde/3600`.

B4 — carving: `probe/ascuns.png` are un ZIP lipit la coadă:

```console
$ python -m arsenal.forensics.forensics probe/ascuns.png --doar carve --carve-out gasit.zip
[B4] arhiva extrasa de la octetul 652 -> gasit.zip (235 octeti)
[B4] continut arhiva: ['secret.txt']
```

Arhiva conține `secret.txt` → **`FLAG{fisier_ascuns_prin_carving}`**.

B5–B6 — steganografie LSB (`stego.png`, salvat obligatoriu PNG — JPEG-ul
recompresează și distruge biții):

```console
$ python -m arsenal.forensics.stego ascunde probe/foto.jpg stego.png "FLAG{ascuns_in_pixeli}"
mesaj ascuns in stego.png
$ python -m arsenal.forensics.stego arata stego.png
FLAG{ascuns_in_pixeli}
```

Doar 55 din 120 000 de pixeli diferă — imaginea arată identic cu originalul.
Mesajul dezvăluit: **`FLAG{ascuns_in_pixeli}`**.
