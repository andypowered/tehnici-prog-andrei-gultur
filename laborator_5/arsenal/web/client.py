import requests

from arsenal.comun import TIMEOUT


def cere(url, **kw):
    kw.setdefault("timeout", TIMEOUT)
    return requests.get(url, **kw)


def exista(url):
    try:
        return cere(url).status_code == 200
    except requests.RequestException:
        return False
