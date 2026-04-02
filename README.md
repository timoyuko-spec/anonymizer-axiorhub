# Anonymizer-Axiorhub

**Anonymizer-Axiorhub** est un outil spécifique pour **Open WebUI** ( https://docs.openwebui.com/) qui permet d’anonymiser et de désanonymiser des données personnelles avant leur envoi à un modèle de langage (LLM / IA), qu’il s’agisse d’un service commercial comme OpenAI, Gemini ou Claude, ou d’un modèle local via Ollama.

L’outil s’appuie sur **Microsoft Presidio** pour détecter certaines données personnelles (PII), sur un **mapping persistant SQLite** pour permettre une éventuelle réinjection des valeurs originales en sortie, ainsi que sur des règles spécifiques pour des entités françaises sensibles, notamment :
- NIR
- SIRET
- SIREN
- RCS
- adresses e-mail
- IBAN
- numéros de téléphone

L’outil peut également regrouper les données personnelles par individu (`PERSON_1`, `PERSON_2`, etc.) afin de limiter les confusions du modèle entre plusieurs personnes mentionnées dans un même texte.

---

## Qu’est-ce qu’Open WebUI ?

**Open WebUI** est une interface web open source permettant d’interagir avec des modèles de langage, qu’ils soient locaux (via Ollama, par exemple) ou distants (OpenAI, Gemini, etc.).

Open WebUI permet d’ajouter des outils Python capables de prétraiter ou de post-traiter les prompts et les réponses : recherche, anonymisation, extraction, envoi d’e-mails, création d’événements de calendrier, etc.

**Anonymizer-Axiorhub** peut être utilisé comme l’un de ces outils.

---

## Fonctionnalités

### Détection et anonymisation de données personnelles

L’outil prend notamment en charge :

- NIR (numéro de sécurité sociale français)
- SIRET
- SIREN
- RCS
- adresses e-mail
- IBAN
- numéros de téléphone français

Selon la configuration de l’environnement, il peut aussi utiliser certaines entités génériques de Presidio, par exemple :
- `PERSON`
- `LOCATION`
- `DATE_TIME`
- `PHONE_NUMBER`

### Regroupement par personne

Les données personnelles proches dans un même texte peuvent être regroupées sous des identifiants du type :
- `[PERSON_1_NAME_1]`
- `[PERSON_1_EMAIL_1]`
- `[PERSON_1_IBAN_1]`


### Mapping persistant SQLite

Chaque anonymisation génère :
- un identifiant de mapping (`mapping_id`)
- une série de tokens anonymisés

Ces correspondances sont stockées dans une base SQLite afin de permettre, si nécessaire, une désanonymisation ultérieure.

---

## Architecture recommandée

Il existe **deux modes d’utilisation**.

### 1. Tool Open WebUI uniquement

Dans ce mode, le modèle reçoit d’abord le prompt brut, puis appelle éventuellement le tool pour anonymiser certains éléments avant de poursuivre son traitement.

Ce mode peut être utile pour forcer le modèle à raisonner ensuite sur des placeholders, mais **il ne protège pas la confidentialité du prompt initial**, puisque le modèle a déjà reçu les données personnelles.

### 2. Proxy FastAPI devant Open WebUI

C’est le mode recommandé si l’objectif est d’empêcher le LLM de voir les données personnelles en clair.

Dans cette architecture :
1. le navigateur ou le client envoie le message au proxy ;
2. le proxy reçoit le texte brut ;
3. le proxy anonymise le contenu avant transmission ;
4. Open WebUI et le modèle ne reçoivent que la version anonymisée.

Dans ce scénario, **le LLM ne voit jamais les données personnelles en clair**, à condition que tout le trafic passe effectivement par le proxy.

Ce README décrit donc :
- d’abord l’installation en tant que tool dans Open WebUI ;
- puis la mise en place d’un proxy FastAPI devant Open WebUI.

---

## Installation

### Étape 1. Cloner le dépôt

```bash
sudo git clone https://gitlab.com/Arthur-Llevelys/anonymizer-axiorhub.git
cd anonymizer-axiorhub
```
### Étape 2. Installation dans Open WebUI (mode tool interne)

** 2.1. Lancer le conteneur Open WebUI **

Exemple :
```bash
docker run -d \
  -p 8080:8080 \
  --env WEBUI_SECRET_KEY='SK-1111' \
  --env ENABLE_CHANNELS=true \
  --env ENABLE_ADMIN_CHAT_ACCESS=true \
  --env BYPASS_MODEL_ACCESS_CONTROL=true \
  --env ENABLE_WEBSOCKET_SUPPORT=true \
  --env DATABASE_ENABLE_SQLITE_WAL=true \
  --env BYPASS_ADMIN_ACCESS_CONTROL=true \
  --env ENABLE_MARKDOWN_HEADER_TEXT_SPLITTER=true \
  --env ENABLE_QUERIES_CACHE=true \
  --env ENABLE_ONEDRIVE_PERSONAL=true \
  --env ENABLE_ONEDRIVE_BUSINESS=true \
  --env AIOHTTP_CLIENT_TIMEOUT_OPENAI_MODEL_LIST=5 \
  --env OLLAMA_HOST=0.0.0.0 \
  --env OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  --env OLLAMA_API_BASE_URL=http://host.docker.internal:11434 \
  --add-host=host.docker.internal:host-gateway \
  --network ai-stack \
  -v open-webui:/app/backend/data \
  -v pii-mapping:/data \
  -v "$(pwd)/tools:/app/backend/data/tools" \
  --name open-webui \
  --restart always \
  ghcr.io/open-webui/open-webui:main
```

**Volumes utilisés :**
- open-webui:/app/backend/data : données et configuration d’Open WebUI
- pii-mapping:/data : base SQLite de mapping des données anonymisées
- $(pwd)/tools:/app/backend/data/tools : dossier contenant les fichiers Python des tools

Si vous souhaitez utiliser un dossier local pour y déposer le tool :

```bash
mkdir -p tools
cp anonymizer_axiorhub.py tools/
```

Puis relancer le conteneur avec le volume :

```bash
-v "$(pwd)/tools:/app/backend/data/tools"
```
Si le conteneur open-webui existe déjà, inutile de le recréer : il suffit de le redémarrer si nécessaire.

**2.2. Installer les dépendances Python dans le conteneur**

Depuis l’hôte :
```bash
docker exec -it open-webui pip install pydantic
docker exec -it open-webui pip install regex
docker exec -it open-webui pip install presidio-anonymizer
docker exec -it open-webui pip install presidio-analyzer
```
Ces paquets installent Microsoft Presidio et les bibliothèques nécessaires à la détection et à l’anonymisation des données personnelles.

### Étape 3. Créer le tool dans Open WebUI

Dans l’interface Open WebUI :
- Aller dans Espace de travail → Outils
- Cliquer sur Nouvel outil
- Ouvrir le fichier Python du tool et copier-coller son contenu dans l’éditeur Open WebUI
- Enregistrer

Recharger les plugins ou redémarrer le conteneur si nécessaire :

```bash
docker restart open-webui
```

Vérifier ensuite dans Espace de travail → Outils que le tool Anonymizer-Axiorhub apparaît bien et est activé.

### Étape 4. Configurer un modèle dans Open WebUI

4.1. Aller dans Panneau d’administration → Réglages → Modèles

4.2. Choisir le modèle LLM cible

4.3. Ajouter, par exemple, dans le prompt système :

"Utilise le tool Anonymizer-Axiorhub pour anonymiser les données personnelles de l’utilisateur avant de poursuivre le traitement."

4.4. Activer le tool Anonymizer-Axiorhub 

4.5. Enregistrer la configuration

Dans ce mode, le modèle peut appeler le tool pour anonymiser certains éléments, mais il aura déjà reçu le prompt brut. Ce point est important : ce mode ne garantit donc pas la confidentialité complète des données personnelles.

### Étape 5. Mettre en place un proxy FastAPI devant Open WebUI

Pour empêcher le modèle de voir les données personnelles en clair, il est recommandé de placer un proxy FastAPI entre le client et Open WebUI.

** 5.1. Principe **

Le flux est le suivant :
- l’utilisateur envoie son message au proxy ;
- le proxy reçoit le texte brut ;
- le proxy anonymise le contenu ;
- le proxy transmet à Open WebUI uniquement la version anonymisée ;
- le modèle traite le prompt anonymisé.

Si nécessaire, le proxy peut ensuite désanonymiser certaines sorties à partir du mapping_id.

** 5.2. Préparer les fichiers du proxy **

Dans le dépôt cloné, vérifier la présence des fichiers suivants :
- anonymizer_axiorhub.py : implémentation du moteur d’anonymisation
- proxy.py : serveur FastAPI
- Dockerfile : configuration de l’image Docker

VOus pouvez les laisser à la racine du dépôt ou les organiser dans un sous-dossier, à condition d’adapter le Dockerfile en conséquence.

** 5.3. Lancer Open WebUI et le proxy sur le même réseau Docker **

Depuis le dossier du dépôt :

```bash
docker build -t pii-proxy .
docker run -d \
  --name pii-proxy \
  --network ai-stack \
  -p 8004:8000 \
  -v pii-mapping:/data \
  pii-proxy
```

Le proxy pourra alors communiquer avec Open WebUI via :

http://open-webui:8080

Les deux services peuvent partager le volume pii-mapping si vous souhaitez mutualiser la même base SQLite.

---

### Exemple de fonctionnement :

Au lieu d’appeler directement Open WebUI, le client envoie une requête au proxy :

```bash
POST http://localhost:8004/chat
Content-Type: application/json

{
  "model": "meta-llama/llama-3.1-8b-instruct",
  "messages": [
    {
      "role": "user",
      "content": "Bonjour, je suis Jean Dupont, né le 12/03/1985 à Lyon. Mon email est jean.dupont@example.com et mon IBAN est FR76 ..."
    }
  ]
}
```
Le proxy anonymise alors le contenu avant de le transmettre.

** Exemple de prompt transmis au modèle : **

```
Bonjour, je suis [PERSON_1_NAME_1], né le [PERSON_1_DATE_1] à [PERSON_1_LOCATION_1].
Mon email est [PERSON_1_EMAIL_1] et mon IBAN est [PERSON_1_IBAN_1].
```
Le modèle ne reçoit donc que des tokens anonymisés.

Selon l’architecture retenue, la réponse peut ensuite :
- être renvoyée telle quelle avec les tokens ;
- ou être désanonymisée côté proxy avant affichage.

---

## Limites :

Le mode tool interne Open WebUI ne protège pas le prompt initial.

Le niveau réel de détection dépend des règles configurées et de l’environnement Presidio.

Si un mapping SQLite contient encore des données sensibles, la protection du proxy ne dispense pas de sécuriser le stockage local.
L’anonymisation réduit l’exposition des données au modèle, mais ne remplace ni une analyse de conformité, ni une politique de sécurité adaptée.

---

## Tests :

Pour tester :
```bashpytest -q test_anonymizer.py --cache-clear
```
---

## Remarque :

Une IA de codage a été utilisée pour assister la conception de cet outil, notamment pour :
- l’intégration de Presidio
- la définition des expressions régulières
- la gestion du mapping SQLite
- le regroupement par personne
