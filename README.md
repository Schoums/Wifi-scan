# Wifi-scan

Petit scanner pour vérifier son réseau Wi-Fi domestique. Il fonctionne avec un
seul fichier Python, sans rien installer d'autre (Python 3.8 ou plus récent, sur Windows, macOS,
Linux ou Android avec Termux).

## Utilisation sur ordinateur

1. Copiez `wifi_scan.py` sur un ordinateur connecté au Wi-Fi à vérifier.
2. Ouvrez un terminal dans ce dossier et tapez :

   ```
   python wifi_scan.py --web        (Windows)
   python3 wifi_scan.py --web       (Mac / Linux)
   ```

3. Le navigateur s'ouvre. Si vous avez une **Bbox**, entrez son mot de passe
   d'administration (celui de mabbox.bytel.fr), puis cliquez sur **Lancer le scan**.
4. Pour chaque appareil que vous reconnaissez, cliquez sur **Je le connais** et
   donnez-lui un nom. Les scans suivants signaleront tout appareil inconnu.

Sans `--web`, le résultat s'affiche dans le terminal (`--bbox` pour donner le
mot de passe de la Bbox, `--json` pour un résultat en JSON). L'interface n'est
accessible que depuis l'appareil lui-même (`127.0.0.1`).

## Utilisation sur Android (Termux)

1. Installez **Termux** et **Termux:API** depuis F-Droid.
2. Dans Termux :

   ```
   pkg install python curl termux-api
   curl -LO https://raw.githubusercontent.com/Schoums/Wifi-scan/claude/wifi-scan-web-interface-w24mhm/wifi_scan.py
   python wifi_scan.py --web
   ```

3. Ouvrez **http://127.0.0.1:8765** dans Chrome et lancez le scan.
4. Pour l'analyse des canaux, autorisez la localisation pour Termux:API
   (Android l'exige pour lister les réseaux Wi-Fi voisins).

Android empêche les applis de lire les adresses MAC des autres appareils : avec
une Bbox et son mot de passe, le scanner les obtient directement auprès de la box.

## Ce qui est vérifié

- **Appareils connectés** : recherche par ping, ports TCP, Bonjour (Mac, iPhone),
  NetBIOS (PC Windows) et UPnP (box TV, imprimantes). Les Mac et iPhone en veille
  ou protégés par un pare-feu peuvent ne répondre à rien : la Bbox, elle, les voit.
- **Avec une Bbox** (mot de passe d'administration) :
  - la liste complète des appareils connectés, avec leur type de connexion
    (Wi-Fi 2,4 GHz, 5 GHz ou câble) ;
  - l'**historique** des appareils déjà connectés puis partis (un intrus qui
    s'est déjà déconnecté y apparaît) ;
  - les **tentatives de connexion** à l'interface de la box, depuis Internet ou
    depuis la maison ;
  - les réglages à risque : WPS, chiffrement faible, mot de passe d'origine,
    réseau « compatibilité », accès à distance, UPnP, pare-feu.
- **Services sensibles ouverts**, sur la box comme sur les autres appareils :
  Telnet, débogage Android (ADB), proxy SOCKS, bureau à distance (RDP), VNC,
  FTP, TR-069…
- **Faux point d'accès** : un autre émetteur qui diffuse le nom de votre Wi-Fi.
- **Serveurs DNS** : un serveur DNS inconnu est un signe classique de box
  piratée (sauf si c'est celui de votre fournisseur d'accès).
- **Canaux Wi-Fi** : encombrement des canaux 1, 6 et 11 en 2,4 GHz et des blocs
  de canaux en 5 GHz d'après les réseaux voisins, avec un canal conseillé.

Le mot de passe de la Bbox ne sert qu'au scan en cours et n'est jamais
enregistré. Le scanner essaie une seule fois de se connecter, car plusieurs
erreurs bloquent l'interface de la box pendant quelques minutes. Il ne modifie
aucun réglage de la box : il se contente de les lire.

## Faut-il séparer les bandes 2,4 et 5 GHz ?

En général, non. Le Wi-Fi unifié (un seul nom) laisse la box placer chaque
appareil sur la meilleure bande. Séparez-les seulement si un appareil (caméra,
prise connectée, imprimante, vieil ordinateur) n'arrive pas à se connecter ou
décroche souvent : connectez-le alors au réseau 2,4 GHz.

## Limites

- Sans accès à la box, seuls les appareils qui répondent **au moment du scan**
  sont visibles.
- Les téléphones récents utilisent une adresse MAC « privée » qui peut changer :
  ils peuvent réapparaître comme inconnus.
- « Rien de suspect » ne garantit pas que le réseau est sain.

## En cas de doute

1. Changez le mot de passe Wi-Fi **et** le mot de passe d'administration de la box.
2. Désactivez le WPS et l'administration à distance dans les réglages de la box.
3. Mettez à jour le logiciel (firmware) de la box.
4. Vérifiez que les serveurs DNS configurés dans la box sont ceux du fournisseur.
5. Si le doute persiste, réinitialisez la box aux réglages d'usine et
   reconfigurez-la avec de nouveaux mots de passe.

## Tests

```
python3 -m unittest test_wifi_scan
```
