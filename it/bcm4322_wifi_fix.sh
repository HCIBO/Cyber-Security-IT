#!/bin/bash
set -e

echo "===> Starting BCM4322 WiFi fix..."
echo "===> Démarrage du correctif WiFi BCM4322..."

echo "===> Installing required packages..."
echo "===> Installation des paquets nécessaires..."
sudo apt update
sudo apt install -y b43-fwcutter wget

echo "===> Downloading firmware..."
echo "===> Téléchargement du firmware..."
wget -O broadcom-wl-5.100.138.tar.bz2 https://github.com/minios-linux/b43-firmware/releases/download/v1.0/broadcom-wl-5.100.138.tar.bz2

echo "===> Extracting archive..."
echo "===> Extraction de l'archive..."
tar xvjf broadcom-wl-5.100.138.tar.bz2

echo "===> Installing firmware..."
echo "===> Installation du firmware..."
sudo b43-fwcutter -w /lib/firmware broadcom-wl-5.100.138/linux/wl_apsta.o

echo "===> Removing wl driver (to prevent conflicts)..."
echo "===> Suppression du pilote wl (pour éviter les conflits)..."
sudo modprobe -r wl
echo "blacklist wl" | sudo tee -a /etc/modprobe.d/blacklist-bcm43.conf

echo "===> Reloading b43 driver..."
echo "===> Rechargement du pilote b43..."
sudo modprobe -r b43
sudo modprobe b43

echo "Done! Now check your WiFi."
echo "Terminé ! Vérifiez maintenant votre WiFi."
echo "Recommendation: Restart your computer to make changes permanent."
echo "Recommandation : Redémarrez votre ordinateur pour rendre les changements permanents."
