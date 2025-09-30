import os
import readline
import glob
import requests
from urllib.parse import urlparse

def complete(text, state):
    return (glob.glob(text + '*') + [None])[state]

readline.set_completer_delims(' \t\n;')
readline.parse_and_bind("tab: complete")
readline.set_completer(complete)

def normalize_url(url):
    url = url.strip()
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except:
        return None

def is_live(domain):
    for proto in ["https://", "http://"]:
        try:
            r = requests.head(proto + domain, timeout=5, allow_redirects=True)
            if 200 <= r.status_code < 600:
                return True
        except:
            continue
    return False

MESSAGES = {
    "en": {
        "enter_file1": "Enter path for 1st file: ",
        "enter_file2": "Enter path for 2nd file: ",
        "file_not_found": "[-] One or both files not found!",
        "starting_live": "[*] Starting live check...",
        "comparison_done": "[+] Comparison completed",
        "common_domains": "Common domains ->",
        "unique_domains": "Unique domains ->",
        "live_domains": "Live domains ->",
        "notlive_domains": "Not live domains ->"
    },
    "fr": {
        "enter_file1": "Entrez le chemin du 1er fichier : ",
        "enter_file2": "Entrez le chemin du 2ème fichier : ",
        "file_not_found": "[-] Un ou les deux fichiers sont introuvables !",
        "starting_live": "[*] Début de la vérification des sites actifs...",
        "comparison_done": "[+] Comparaison terminée",
        "common_domains": "Domaines communs ->",
        "unique_domains": "Domaines uniques ->",
        "live_domains": "Domaines actifs ->",
        "notlive_domains": "Domaines inactifs ->"
    }
}

def compare_url_files(file1, file2, lang='en',
                      common_file="common.txt",
                      unique_file="unique.txt",
                      live_file="live.txt",
                      notlive_file="notlive.txt"):

    msg = MESSAGES[lang]

    with open(file1, "r", encoding="utf-8") as f:
        urls1 = {normalize_url(line) for line in f if normalize_url(line)}

    with open(file2, "r", encoding="utf-8") as f:
        urls2 = {normalize_url(line) for line in f if normalize_url(line)}

    common = urls1.intersection(urls2)
    unique = urls1.symmetric_difference(urls2)

    with open(common_file, "w", encoding="utf-8") as f:
        for url in sorted(common):
            f.write(url + "\n")
        f.write(f"\n# Total: {len(common)} domains\n")

    with open(unique_file, "w", encoding="utf-8") as f:
        for url in sorted(unique):
            f.write(url + "\n")
        f.write(f"\n# Total: {len(unique)} domains\n")

    all_domains = common.union(unique)
    live_domains, notlive_domains = [], []

    print(msg["starting_live"])
    for domain in sorted(all_domains):
        if is_live(domain):
            live_domains.append(domain)
        else:
            notlive_domains.append(domain)

    with open(live_file, "w", encoding="utf-8") as f:
        for url in live_domains:
            f.write(url + "\n")
        f.write(f"\n# Total: {len(live_domains)} domains\n")

    with open(notlive_file, "w", encoding="utf-8") as f:
        for url in notlive_domains:
            f.write(url + "\n")
        f.write(f"\n# Total: {len(notlive_domains)} domains\n")

    print(f"\n{msg['comparison_done']}: {file1} & {file2}")
    print(f"{msg['common_domains']} {common_file} ({len(common)})")
    print(f"{msg['unique_domains']} {unique_file} ({len(unique)})")
    print(f"{msg['live_domains']} {live_file} ({len(live_domains)})")
    print(f"{msg['notlive_domains']} {notlive_file} ({len(notlive_domains)})")

if __name__ == "__main__":
    lang_choice = input("Select language / Sélectionnez la langue (en/fr): ").strip().lower()
    if lang_choice not in ["en", "fr"]:
        lang_choice = "en"

    file1 = input(MESSAGES[lang_choice]["enter_file1"])
    file2 = input(MESSAGES[lang_choice]["enter_file2"])

    if os.path.exists(file1) and os.path.exists(file2):
        compare_url_files(file1, file2, lang=lang_choice)
    else:
        print(MESSAGES[lang_choice]["file_not_found"])
