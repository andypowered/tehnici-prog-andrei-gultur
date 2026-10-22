# Teste pentru decoderul universal (Lucrarea A, pasul A7).
# Rulare (din directorul laborator_6/):  python -m pytest teste/ -v
from arsenal.forensics.decode import (
    cea_mai_buna,
    citibil,
    decodeaza_straturi,
    desfa,
    ghici_strat,
    identifica_hash,
    sparge_hash,
    sparge_xor,
)


def test_base64():
    strat, b = desfa("U2FsdXQ=")
    assert strat == "base64"
    assert b == b"Salut"


def test_hex():
    strat, b = desfa("48656c6c6f")
    assert strat == "hex"
    assert b == b"Hello"


def test_url():
    strat, b = desfa("%2Fetc")
    assert strat == "url"
    assert b == b"/etc"


def test_ordinea_ghicirii():
    # "%" castiga in fata hex/base64; hexul strict castiga in fata base64
    assert ghici_strat("%2Fetc") == "url"
    assert ghici_strat("48656c6c6f") == "hex"
    assert ghici_strat("U2FsdXQ=") == "base64"
    assert ghici_strat("FLAG{nu-e-codare}") == "necunoscut"


def test_citibil():
    assert citibil(b"Salut 123!")
    assert not citibil(bytes([0, 255, 10]))


def test_straturi_multiple():
    # hex("Hi") = 4869 -> base64 -> "NDg2OQ=="
    rezultat, istoric = decodeaza_straturi("NDg2OQ==")
    assert rezultat == "Hi"
    assert istoric == ["base64", "hex"]


def test_xor_cheie_un_octet():
    clar = b"FLAG{test_xor}"
    cheie = 77
    criptat = bytes(b ^ cheie for b in clar)
    gasite = sparge_xor(criptat)
    assert (cheie, "FLAG{test_xor}") in gasite
    assert cea_mai_buna(gasite) == (cheie, "FLAG{test_xor}")


def test_hash_dupa_lungime_si_dictionar():
    assert identifica_hash("0" * 32) == "md5"
    assert identifica_hash("0" * 40) == "sha1"
    assert identifica_hash("0" * 64) == "sha256"
    import hashlib
    tinta = hashlib.md5("letmein".encode()).hexdigest()
    assert sparge_hash(tinta, ["password", "letmein", "qwerty"]) == "letmein"
    assert sparge_hash(tinta, ["password", "qwerty"]) is None
