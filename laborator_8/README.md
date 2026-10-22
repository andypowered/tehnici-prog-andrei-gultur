# Laboratorul 8 - GitHub pas cu pas + unealta reparata cu git

Fisierele din acest folder sunt o copie a celor doua depozite de exercitiu.
Depozitele reale, cu toata istoria git, sunt publice aici:

- https://github.com/andypowered/exercitiu-git
- https://github.com/andypowered/exercitiu-2

## exercitiu-git

Contine `README.md`, `salut.py`, `.gitignore` si `depanare/` cu
`inventar.py` reparat, `tinte.json` si `raport_inventar.json`.

Istoria are 16 commit-uri: 4 de la Lucrarea A, apoi:

```
Pornire: inventar.py stricat
SyntaxError: lipseste ':' la def citeste_tinte
IndentationError: indentationea la citirea tintelor
NameError tinta: numele corect e tinte
TypeError la afisare: str() in jurul lui len
ValueError la port: folosesc port_valid
KeyError servicii: folosesc .get cu rezerva
AttributeError NoneType: adaug return in servicii
TypeError la prag: type=int in argparse
Rezultat gol: return rezultat, nu []
Lista incompleta: append in loc de suprascriere
Raportul uneltei reparate
```

## exercitiu-2

Pornit cu `git init`, contine `README.md` si un singur commit:
`Primul commit`.

## Rulare

```console
cd depanare
python inventar.py tinte.json --prag 1000
python inventar.py tinte.json
```
