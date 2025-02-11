import boto3
import subprocess
import json

def run_aws_command(command, no_sign=False, description=""):
    if no_sign:
        command.append("--no-sign-request")
    print(f"[+] Exécution: {' '.join(command)}")
    print(f"Description: {description}")
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else f"[!] Erreur: {result.stderr}"

def check_iam():
    print("\nVérification des paramètres IAM...")
    print(run_aws_command(["aws", "iam", "list-users"], description="Liste tous les utilisateurs IAM dans le compte AWS."))
    print(run_aws_command(["aws", "iam", "list-roles"], description="Liste tous les rôles IAM disponibles dans le compte AWS."))
    print(run_aws_command(["aws", "iam", "list-policies"], description="Liste toutes les politiques IAM appliquées dans le compte."))
    print(run_aws_command(["aws", "iam", "list-mfa-devices"], description="Vérifie si l'authentification multi-facteurs (MFA) est activée pour les utilisateurs IAM."))
    print(run_aws_command(["aws", "iam", "get-account-summary"], description="Fournit un aperçu des limites et de l'utilisation des ressources IAM."))
    print(run_aws_command(["aws", "iam", "list-account-aliases"], description="Liste l'alias associé au compte AWS."))

def check_s3():
    print("\nVérification des paramètres S3...")
    print(run_aws_command(["aws", "s3api", "list-buckets"], description="Liste tous les buckets S3 dans le compte AWS."))
    print(run_aws_command(["aws", "s3api", "get-public-access-block", "--bucket", "example-bucket"], description="Vérifie si l'accès public est bloqué pour un bucket S3 donné."))
    print(run_aws_command(["aws", "s3api", "get-bucket-encryption", "--bucket", "example-bucket"], description="Vérifie si le chiffrement est activé pour un bucket S3."))
    print(run_aws_command(["aws", "s3api", "get-bucket-lifecycle-configuration", "--bucket", "example-bucket"], description="Vérifie si des politiques de cycle de vie sont configurées pour un bucket S3."))
    print(run_aws_command(["aws", "s3api", "get-bucket-policy-status", "--bucket", "example-bucket"], description="Détermine si une politique de bucket rend le bucket accessible publiquement."))

def check_cloudtrail():
    print("\n Vérification des journaux CloudTrail...")
    print(run_aws_command(["aws", "cloudtrail", "describe-trails"], description="Liste toutes les traces CloudTrail configurées dans le compte AWS."))
    print(run_aws_command(["aws", "cloudtrail", "get-trail-status", "--name", "Default"], description="Vérifie l'état d'enregistrement des journaux d'une trace CloudTrail spécifique."))

def check_guardduty():
    print("\n Vérification des paramètres GuardDuty...")
    print(run_aws_command(["aws", "guardduty", "list-detectors"], description="Vérifie si AWS GuardDuty est activé pour la détection des menaces."))

def check_securityhub():
    print("\n Vérification des paramètres Security Hub...")
    print(run_aws_command(["aws", "securityhub", "get-findings"], description="Liste toutes les failles de sécurité détectées par AWS Security Hub."))

def check_rds():
    print("\n Vérification des paramètres RDS...")
    print(run_aws_command(["aws", "rds", "describe-db-instances"], description="Liste toutes les instances RDS et leurs paramètres de sécurité."))
    print(run_aws_command(["aws", "rds", "describe-db-snapshots"], description="Liste toutes les sauvegardes RDS et leur statut de chiffrement."))

def check_ec2():
    print("\n Vérification des paramètres EC2...")
    print(run_aws_command(["aws", "ec2", "describe-instances"], description="Liste toutes les instances EC2 en cours d'exécution avec leurs groupes de sécurité."))
    print(run_aws_command(["aws", "ec2", "describe-security-groups"], description="Liste tous les groupes de sécurité et leurs règles associées."))

def main():
    print(" Démarrage de l'audit de sécurité AWS...")
    check_iam()
    check_s3()
    check_cloudtrail()
    check_guardduty()
    check_securityhub()
    check_rds()
    check_ec2()
    print("Audit terminé !")

if __name__ == "__main__":
    main()
