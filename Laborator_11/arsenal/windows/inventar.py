"""Inventar de procese si jurnal de evenimente Windows, modelate ca obiecte.

Rulare:
    python -m arsenal.windows.inventar arsenal/windows/start
    python -m arsenal.windows.inventar arsenal/windows/start --json
"""

from dataclasses import asdict, dataclass
import json

CAI_SUSPECTE = ("\\Temp\\", "\\Roaming\\")
SUSPECTE_ID = {4625, 1102, 7045}


@dataclass
class Proces:
    pid: int
    nume: str
    user: str
    cale: str

    def e_suspect(self) -> bool:
        """True daca procesul ruleaza dintr-un folder de utilizator uzual abuzat."""
        return any(cale in self.cale for cale in CAI_SUSPECTE)


@dataclass
class Eveniment:
    id: int
    nivel: str
    sursa: str
    cont: str
    mesaj: str

    def e_suspect(self) -> bool:
        """True daca ID-ul e cunoscut ca periculos sau nivelul e critical."""
        return self.id in SUSPECTE_ID or self.nivel == "critical"


def procese_din_json(cale: str) -> list[Proces]:
    """Citeste un JSON si transforma fiecare dicționar intr-un obiect Proces."""
    with open(cale, encoding="utf-8") as f:
        return [Proces(**d) for d in json.load(f)]


def evenimente_din_json(cale: str) -> list[Eveniment]:
    """Citeste un JSON si transforma fiecare dicționar intr-un obiect Eveniment."""
    with open(cale, encoding="utf-8") as f:
        return [Eveniment(**d) for d in json.load(f)]


@dataclass
class Inventar:
    procese: list[Proces]

    @classmethod
    def din_json(cls, cale: str) -> "Inventar":
        """Constructor alternativ: umple inventarul direct din fisierul JSON."""
        with open(cale, encoding="utf-8") as f:
            return cls([Proces(**d) for d in json.load(f)])

    def __len__(self) -> int:
        return len(self.procese)

    def suspecte(self) -> list[Proces]:
        """Procesele care se declara singure suspecte."""
        return [p for p in self.procese if p.e_suspect()]

    def pe_user(self) -> dict[str, list[str]]:
        """Grupeaza numele proceselor pe utilizator."""
        grupuri: dict[str, list[str]] = {}
        for p in self.procese:
            grupuri.setdefault(p.user, []).append(p.nume)
        return grupuri


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Inventar de procese si jurnal de evenimente Windows."
    )
    parser.add_argument("capturi", help="folderul cu procese.json si evenimente.json")
    parser.add_argument("--json", action="store_true", help="afiseaza raportul JSON")
    args = parser.parse_args()

    inventar = Inventar.din_json(args.capturi + "/procese.json")
    evenimente = evenimente_din_json(args.capturi + "/evenimente.json")
    suspecte = inventar.suspecte()
    alarma = [e for e in evenimente if e.e_suspect()]

    if args.json:
        raport = {
            "procese": len(inventar),
            "suspecte": [asdict(p) for p in suspecte],
            "evenimente": len(evenimente),
            "alarma": [asdict(e) for e in alarma],
        }
        print(json.dumps(raport, ensure_ascii=False, indent=2))
        return

    print(f"Procese: {len(inventar)} | suspecte: {len(suspecte)}")
    for p in suspecte:
        print(f"  [{p.pid}] {p.nume}  ({p.user})  {p.cale}")

    print(f"Evenimente: {len(evenimente)} | alarma: {len(alarma)}")
    for e in alarma:
        print(f"  {e.id} [{e.nivel}] {e.cont}: {e.mesaj}")


if __name__ == "__main__":
    main()
