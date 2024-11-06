import requests
import sys

def verifier_endpoint(base_url, endpoint):
    url = f"{base_url}{endpoint}"
    try:
        response = requests.get(url, timeout=5)
        status_code = response.status_code
        if status_code == 200:
            print(f"[+] {endpoint} est présent et accessible.")

            try:
                print("Réponse:", response.json())
            except ValueError:
                print("La réponse n'est pas au format JSON.")
        elif status_code == 403:
            print(f"[-] {endpoint} est présent mais l'accès est refusé.")
        elif status_code == 404:
            print(f"[-] {endpoint} n'existe pas (Erreur 404).")
        else:
            print(f"[-] {endpoint} est inaccessible (Code d'état : {status_code}).")
    except requests.exceptions.Timeout:
        print(f"[!] Erreur : le délai de connexion a expiré pour {endpoint}.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur de connexion pour {endpoint} : {e}")

def tester_endpoints(base_url, endpoints):
    print(f"Test des endpoints Actuator sur : {base_url}\n")
    for endpoint in endpoints:
        verifier_endpoint(base_url, endpoint)
        print("-" * 50)  

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Utilisation : python Spring_Actuator.py <url>")
        sys.exit(1)

    BASE_URL = sys.argv[1]
    
    endpoints = [
        "/actuator",
        "/actuator/health",
        "/actuator/info",
        "/actuator/metrics",
        "/actuator/logfile",
        "/actuator/env",
        "/actuator/configprops",
        "/actuator/beans",
        "/actuator/mappings",
        "/actuator/threaddump",
        "/actuator/heapdump",
        "/actuator/loggers",
        "/actuator/auditevents",
        "/actuator/httptrace",
        "/actuator/scheduledtasks",
        "/actuator/caches"
    ]

    tester_endpoints(BASE_URL, endpoints)
