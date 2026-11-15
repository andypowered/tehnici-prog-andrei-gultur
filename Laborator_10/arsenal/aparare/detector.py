"""Detector de brute force peste un jurnal auth.log.

Refoloseste citeste_esecuri() din parse_auth si decide ce adrese sunt
suspecte, dupa un prag reglabil.
"""

import argparse
import json
from collections import Counter
from pathlib import Path

from arsenal.aparare.parse_auth import citeste_esecuri

CALE_IMPLICITA = Path(__file__).resolve().parent / "start" / "auth.log"


def suspecti(counts, prag=10):
    """Intoarce [(ip, n), ...] cu n >= prag, sortat descrescator dupa n."""
    if prag < 1:
        raise ValueError(f"prag invalid: {prag} (cel putin 1)")

    perechi = ((ip, n) for ip, n in counts.items() if n >= prag)
    return sorted(perechi, key=lambda pereche: (-pereche[1], pereche[0]))


def main(argv=None):
    p = argparse.ArgumentParser(description="Detecteaza brute force in auth.log.")
    p.add_argument("log", nargs="?", default=str(CALE_IMPLICITA), help="calea catre auth.log")
    p.add_argument("--prag", type=int, default=10, help="numarul minim de esecuri (implicit 10)")
    p.add_argument("--json", action="store_true", help="scoate raportul in format JSON")
    a = p.parse_args(argv)

    esecuri = citeste_esecuri(a.log)
    counts = Counter(e["ip"] for e in esecuri)
    sus = suspecti(counts, a.prag)

    if a.json:
        raport = {
            "esecuri": len(esecuri),
            "pe_ip": dict(counts),
            "suspecti": [{"ip": ip, "incercari": n} for ip, n in sus],
        }
        print(json.dumps(raport, ensure_ascii=False, indent=2))
        return 0

    print(f"Esecuri de autentificare: {len(esecuri)}")
    for ip, n in counts.most_common():
        print(f"  {ip}: {n}")
    print(f"Suspecti (prag {a.prag}):")
    if sus:
        for ip, n in sus:
            print(f"  {ip}  ({n} incercari)  BRUTE FORCE")
    else:
        print("  (niciunul)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
