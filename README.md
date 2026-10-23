# Wifi-scan

Petit scanner pour vérifier son réseau Wi-Fi domestique. Il fonctionne avec un
seul fichier Python, sans rien installer d'autre (Python 3.8 ou plus récent, sur Windows, macOS
ou Linux).

## Utilisation

1. Copiez `wifi_scan.py` sur un ordinateur connecté au Wi-Fi à vérifier.
2. Ouvrez un terminal dans ce dossier et tapez :

   ```
   python wifi_scan.py --web        (Windows)
   python3 wifi_scan.py --web       (Mac / Linux)
   ```

3. Le navigateur s'ouvre : cliquez sur **Lancer le scan** (10 à 60 secondes).
4. Pour chaque appareil que vous reconnaissez, cliquez sur **Je le connais** et
   donnez-lui un nom. Les scans suivants signaleront tout appareil inconnu.

Sans `--web`, le résultat s'affiche directement dans le terminal (`--json` pour
un résultat en JSON). L'interface n'est accessible que depuis l'ordinateur
lui-même (`127.0.0.1`).

## Ce qui est vérifié

- **Appareils connectés** : adresse IP, adresse MAC, nom réseau, connu ou non.
- **Services sensibles ouverts**, sur la box comme sur les autres appareils :
  Telnet, débogage Android (ADB), proxy SOCKS, bureau à distance (RDP), VNC,
  FTP, TR-069 (gestion à distance du fournisseur)…
- **Serveurs DNS** : un serveur DNS inconnu est un signe classique de box
  piratée (sauf si c'est celui de votre fournisseur d'accès).

## Limites

- Seuls les appareils connectés **au moment du scan** sont visibles.
- Certains appareils ne répondent pas (pare-feu) et peuvent passer inaperçus.
- Les téléphones récents utilisent une adresse MAC « privée » qui peut changer :
  ils peuvent réapparaître comme inconnus.
- « Rien de suspect » ne garantit pas que le réseau est sain.

## En cas de doute

1. Changez le mot de passe Wi-Fi **et** le mot de passe d'administration de la box.
2. Mettez à jour le logiciel (firmware) de la box.
3. Désactivez le WPS et l'administration à distance dans les réglages de la box.
4. Vérifiez que les serveurs DNS configurés dans la box sont ceux du fournisseur.
5. Si le doute persiste, réinitialisez la box aux réglages d'usine et
   reconfigurez-la avec de nouveaux mots de passe.

## Tests

```
python3 -m unittest test_wifi_scan
```
