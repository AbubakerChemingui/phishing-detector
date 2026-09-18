# Guide d'utilisation du système de détection d'emails de phishing (Français)

## Introduction
Ce guide explique comment utiliser le système de détection d'emails de phishing, qui comprend une interface graphique de bureau, une interface en ligne de commande, un pare-feu email (scanner IMAP) et une application web basée sur Streamlit. Le système détecte les emails de phishing à l'aide d'un modèle Random Forest pré‑entraîné avec vectorisation TF‑IDF.

## Configuration requise
- Python 3.8 ou supérieur
- Paquets requis : tkinter, scikit-learn, joblib, numpy, pandas, streamlit (pour l'application web)
- Les fichiers de modèle `random_forest_model.pkl` et `random_forest_vectorizer.pkl` doivent être présents dans le répertoire de l'application.

## Installation
1. Assurez-vous que Python est installé.
2. Installez les dépendances (si ce n'est pas déjà fait) :
   ```bash
   pip install scikit-learn joblib numpy pandas streamlit
   ```
3. Placez les fichiers de modèle dans le même dossier que les scripts.
4. Aucune autre installation n'est nécessaire.

## Utilisation

### 1. Interface graphique de bureau (Tkinter)
Lancez l'interface graphique :
```bash
python gui_app.py
```
Fonctionnalités :
- **Sélection de la langue** : choisissez l'anglais, le français ou l'arabe dans le menu déroulant du volet Options.
- **Thème** : basculez le mode sombre avec `Alt+D` ou changez la couleur d'accent avec `Alt+A` (ou les touches 1‑5).
- **Analyser un email** :
  1. Collez l'email complet (y compris les en‑têtes) dans le volet de gauche.
  2. Activez éventuellement le **Renforcement** pour détecter les techniques d'obfuscation.
  3. Ajustez les seuils **Moyen** et **Élevé** via les curseurs (par défaut 0,65 et 0,85).
  4. Cliquez sur **Vérifier l'email** ou appuyez sur `Ctrl+Entrée`.
  5. Les résultats apparaissent dans le volet de droite :
     - Prédiction (Phishing/Légitime)
     - Pourcentage de confiance
     - Niveau d'alerte (SAFE, LIKELY SAFE, LOW CONFIDENCE, etc.)
     - Mots contributeurs principaux (TF‑IDF × importance des caractéristiques)
- **Boutons supplémentaires** :
  - **Ouvrir .eml/.txt** : charger un fichier email.
  - **Effacer** : réinitialiser l'entrée et les résultats.
  - **CSV par lot** : analyser un fichier CSV contenant des textes d'email (une ligne par email).
  - **Sauvegarder le rapport** : exporter l'analyse actuelle vers un fichier texte.
- **Raccourcis clavier** :
  - `Ctrl+Entrée` : analyser l'email
  - `Alt+D` : basculer le thème (noir / gris foncé)
  - `Alt+A` : changer la couleur d'accent
  - `1‑5` : sélectionner directement la couleur d'accent
  - `F1` ou `?` : afficher la feuille de triche
  - `Esc` : réinitialiser le focus (retour à la fenêtre principale)
  - `Entrée` dans la zone de saisie : analyse rapide (identique à Ctrl+Entrée)

### 2. Interface en ligne de commande (CLI)
Utilisez `demo.py` pour analyser un email depuis l'entrée standard :
```bash
echo "Subject: Test\n\nHello world" | python demo.py
```
L'outil affiche la prédiction (PHISHING ou LEGITIMATE) et la confiance.

### 3. Pare‑feu email (scanner IMAP)
`email_firewall.py` surveille une boîte aux lettres IMAP et signale les emails de phishing.
- Modifiez le script pour définir votre serveur IMAP, votre email et votre mot de passe (ou utilisez des variables d'environnement).
- Exécutez :
  ```bash
  python email_firewall.py
  ```
- Le script analysera les emails entrants et affichera ceux détectés comme du phishing.

### 4. Interface web (Streamlit)
Lancez l'application Streamlit :
```bash
streamlit run app.py
```
Fonctionnalités :
- Zone de texte pour la saisie de l'email.
- Options de la barre latérale : activer le renforcement, ajuster les seuils.
- Bouton **Analyser l'email** pour lancer l'analyse.
- Affiche la prédiction, la confiance, le niveau d'alerte et les mots contributeurs principaux.

## Fonctionnalités
- **Prétraitement** : conversion en minuscules, remplacement des URL, suppression de la ponctuation, normalisation des espaces.
- **Options de renforcement** (facultatives) : normalisation Unicode NFKC, remplacement des homoglyphes, décodage leet‑speak, suppression des caractères de largeur nulle.
- **Explicabilité** : montre les mots contributeurs principaux pour comprendre pourquoi un email a été signalé.
- **Seuils configurables** : ajustez les niveaux de risque moyen et élevé selon votre environnement.
- **Prise en charge multilingue** : la langue de l'interface graphique peut être changée à la volée (anglais, français, arabe).
- **Multiples interfaces** : choisissez l'interface qui convient le mieux à votre flux de travail.

## Dépannage
- **Modèle introuvable** : assurez‑vous que `random_forest_model.pkl` et `random_forest_vectorizer.pkl` se trouvent dans le même répertoire que le script.
- **L'interface graphique ne démarre pas** : vérifiez que tkinter est installé (généralement inclus avec Python).
- **Échec de Streamlit** : installez streamlit avec `pip install streamlit`.
- **Pas de texte dans l'interface graphique** : assurez‑vous d'avoir collé le contenu de l'email ; le texte de résumé disparaît lorsqu'il reçoit le focus.
- **Erreurs CSV par lot** : assurez‑vous que le CSV contient une colonne avec le texte de l'email (nommée text, email, content ou body) ou la première colonne sera utilisée.

## Support
Pour des problèmes ou des questions, consultez le fichier `SYSTEM_REPORT.md` pour les détails techniques et les résultats des tests.

--- 

*Fin du guide*