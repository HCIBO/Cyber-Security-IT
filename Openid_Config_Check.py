import requests
from colorama import Fore, Style, init

init(autoreset=True)

def get_oidc_configuration(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(Fore.RED + f"Erreur : Impossible d'obtenir la configuration OpenID : {e}")
        return None

def check_response_types(config):
    response_types = config.get("response_types_supported", [])
    insecure_types = [rtype for rtype in response_types if rtype in ["token", "id_token", "code token", "code id_token"]]
    
    if insecure_types:
        print(Fore.RED + "\nAlerte : Types de réponse non sécurisés détectés !")
        print(Fore.YELLOW + "Types de réponse non sécurisés :", insecure_types)
        print(Fore.MAGENTA + "Raison : 'token' ou 'id_token' peuvent renvoyer des jetons d'accès directement au client, exposant ainsi les informations sensibles.")
        print(Fore.YELLOW + "Conseil : N'acceptez que 'code' comme type de réponse. Il offre une sécurité accrue en n'envoyant qu'un code d'autorisation.")
    else:
        print(Fore.GREEN + "\nLes types de réponse sont sécurisés.")

def check_signing_algorithms(config):
    algorithms = config.get("id_token_signing_alg_values_supported", [])
    if "RS256" not in algorithms:
        print(Fore.RED + "\nAlerte : Algorithme de signature non sécurisé détecté.")
        print(Fore.YELLOW + "Raison : RS256 est un algorithme asymétrique sécurisé. Les algorithmes symétriques (comme HS256) exposent la clé secrète.")
        print(Fore.GREEN + "Conseil : Utilisez uniquement des algorithmes asymétriques comme RS256.")
    else:
        print(Fore.GREEN + "\nL'algorithme de signature est sécurisé (RS256 trouvé).")

def check_scopes(config):
    scopes = config.get("scopes_supported", [])
    if "openid" not in scopes:
        print(Fore.RED + "\nAlerte : Le scope 'openid' est manquant.")
        print(Fore.YELLOW + "Raison : Le scope 'openid' est obligatoire pour OpenID Connect afin de garantir l'authentification.")
    if "email" in scopes or "profile" in scopes:
        print(Fore.MAGENTA + "\nLes scopes 'email' et 'profile' peuvent contenir des informations sensibles.")
        print(Fore.YELLOW + "Raison : Ces informations sont personnelles et doivent être utilisées uniquement lorsque nécessaire.")
    print(Fore.GREEN + "\nLes scopes ont été vérifiés.")

def check_code_challenge_methods(config):
    methods = config.get("code_challenge_methods_supported", [])
    if "plain" in methods:
        print(Fore.RED + "\nAlerte : La méthode 'plain' PKCE est utilisée !")
        print(Fore.YELLOW + "Raison : La méthode 'plain' est vulnérable car elle ne chiffre pas le code d'autorisation.")
        print(Fore.GREEN + "Conseil : Utilisez uniquement la méthode 'S256', qui applique un hachage sécurisé sur le code.")
    else:
        print(Fore.GREEN + "\nLa méthode PKCE est sécurisée ('plain' non supportée).")

def check_auth_methods(config):
    auth_methods = config.get("token_endpoint_auth_methods_supported", [])
    if "client_secret_post" in auth_methods:
        print(Fore.RED + "\nAlerte : La méthode 'client_secret_post' est utilisée !")
        print(Fore.YELLOW + "Raison : 'client_secret_post' envoie le secret client dans le corps de la requête HTTP, exposant ainsi la clé.")
        print(Fore.GREEN + "Conseil : Utilisez la méthode 'client_secret_basic', qui envoie le secret dans l'en-tête HTTP de manière plus sécurisée.")
    else:
        print(Fore.GREEN + "\nLa méthode d'authentification est sécurisée.")

def check_grant_types(config):
    grant_types = config.get("grant_types_supported", [])
    if "authorization_code" not in grant_types:
        print(Fore.RED + "\nAlerte : Le type de grant 'authorization_code' est manquant.")
        print(Fore.YELLOW + "Raison : Le type 'authorization_code' est plus sécurisé car il permet d'échanger un code d'autorisation pour un jeton.")
    if "implicit" in grant_types:
        print(Fore.RED + "\nAlerte : Le type de grant 'implicit' est utilisé.")
        print(Fore.YELLOW + "Raison : Le flux 'implicit' renvoie directement un jeton d'accès au client, augmentant ainsi les risques de fuite.")
    print(Fore.GREEN + "\nLes types de grant ont été vérifiés.")

def main():
    url = input(Fore.CYAN + "Entrez l'URL de la configuration OpenID Connect : ").strip()
    config = get_oidc_configuration(url)
    
    if config:
        print(Fore.GREEN + "\nDébut de la vérification de la configuration OpenID Connect\n")
        check_response_types(config)
        check_signing_algorithms(config)
        check_scopes(config)
        check_code_challenge_methods(config)
        check_auth_methods(config)
        check_grant_types(config)
        print(Fore.GREEN + "\nVérification de la configuration terminée.")
    else:
        print(Fore.RED + "Impossible d'obtenir le fichier de configuration.")

if __name__ == "__main__":
    main()
