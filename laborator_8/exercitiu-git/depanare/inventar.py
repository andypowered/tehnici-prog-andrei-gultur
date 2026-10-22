import argparse
import json


def citeste_tinte(cale):
    with open(cale, encoding="utf-8") as f:
        return json.load(f)


def servicii(tinta):
    return tinta.get("servicii", {})


def port_valid(port):
    try:
        return int(port)
    except (TypeError, ValueError):
        return None


def grupeaza(tinte):
    grupuri = {}
    for tinta in tinte:
        ip = tinta["ip"]
        servicii_tinta = tinta.get("servicii", {})
        for serviciu, porturi in servicii_tinta.items():
            for port in porturi:
                numar = port_valid(port)
                if numar is None:
                    print("sar peste", ip, ":", "port invalid", port)
                    continue
                grupuri.setdefault(serviciu, []).append(numar)
    return grupuri


def peste_prag(tinte, prag):
    rezultat = []
    for tinta in tinte:
        ip = tinta["ip"]
        lista = servicii(tinta).values()
        porturi = []
        for porturi_serviciu in lista:
            for port in porturi_serviciu:
                numar = port_valid(port)
                if numar is not None:
                    porturi.append(numar)
        if porturi and max(porturi) > prag:
            rezultat.append(ip)
    return rezultat


def scrie_raport(cale, date):
    with open(cale, "w", encoding="utf-8") as f:
        json.dump(date, f, indent=2)
    print("Raport salvat in", cale)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("fisier")
    p.add_argument("--prag", type=int, default=1024)
    a = p.parse_args()

    tinte = citeste_tinte(a.fisier)
    print("Tinte citite: " + str(len(tinte)))

    grupuri = grupeaza(tinte)
    for serviciu, porturi in grupuri.items():
        print(serviciu + ":", porturi)

    peste = peste_prag(tinte, a.prag)
    print("Peste " + str(a.prag) + ":", peste)
    scrie_raport("raport_inventar.json", {"tinte": len(tinte), "grupuri": grupuri, "peste_prag": peste})


if __name__ == "__main__":
    main()
