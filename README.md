# Drupal Security Updates

Outil d'audit automatisé des mises à jour de sécurité pour des projets Drupal basés sur Composer et Git.

Le script inspecte une liste de dépôts, met à jour ou clone leurs sources, exécute `composer audit` sur leur fichier `composer.lock`, et génère un rapport Markdown clair et consolidé.

---

## Fonctionnalités

- **Clonage et mise à jour incrémentale** :
  - Si le projet n'existe pas encore en local, il est cloné.
  - S'il est déjà présent, le dépôt est mis à jour (`git fetch` + `git pull`) afin d'accélérer drastiquement les analyses suivantes.
- **Détection automatique de branche** :
  - Si le paramètre `branch` est omis pour un projet, le script recherche automatiquement toutes les branches `release/*` et sélectionne la plus récente (par version sémantique et date de commit).
- **Ciblage Drupal par défaut (`drupal/*`)** :
  - Filtre automatiquement le bruit des dépendances PHP externes pour se concentrer sur Drupal Core et les modules/thèmes contrib.
  - Option `--all-packages` disponible pour auditer l'ensemble des bibliothèques PHP tierces.
- **Consolidation par composant** :
  - Récupère la version actuellement installée depuis `composer.lock`.
  - Dédoublonne les avis pour n'afficher qu'une seule ligne par paquet à mettre à jour, complétée d'un volet rétractable (`<details>`) listant toutes les CVE associées.
- **Auto-update et publication de branche** :
  - Si `auto_update` est activé pour un projet et que des failles sont détectées, une branche `security-update/date` est créée, les paquets sont mis à niveau via `composer require`, commités et poussés sur le dépôt distant.
- **Notifications Slack par projet** :
  - Possibilité de spécifier un webhook Slack différent par projet (`slack_webhook`). Une notification riche est automatiquement envoyée sur le channel du projet lorsqu'une branche de mise à jour est créée et poussée.
- **Rapports Markdown horodatés** :
  - Génération automatique de rapports structurés dans le dossier `reports/` : un rapport global regroupant tous les projets, ainsi qu'un rapport individuel par projet (voir [Fichiers de rapport](#fichiers-de-rapport)).

---

## Prérequis

1. **Python** : Python 3.9 ou supérieur.
2. **Git** : avec clés SSH configurées pour accéder aux dépôts distants (ex. GitLab / GitHub).
3. **Composer** : `composer` doit être installé et accessible dans votre variable d'environnement `PATH`.

---

## Configuration (`projects.json`)

Créez ou modifiez le fichier `projects.json` à la racine :

```json
[
  {
    "name": "Mon Projet avec branche fixe",
    "repository": "git@gitlab.exemple.com:groupe/mon-projet.git",
    "branch": "main",
    "auto_update": false
  },
  {
    "name": "Mon Projet avec auto-update et Slack",
    "repository": "git@gitlab.exemple.com:groupe/autre-projet.git",
    "auto_update": true,
    "slack_webhook": "$SLACK_WEBHOOK_AUTRE_PROJET"
  }
]
```

### Champs de configuration :
| Champ | Requis | Description |
|---|---|---|
| `name` | **Oui** | Nom identifiant le projet (utilisé pour le dossier local `projects/<name>`). |
| `repository` | **Oui** | URL Git du dépôt (privilégier SSH, ex. `git@...`). |
| `branch` | Non | Branche cible. Si omise, la branche `release/*` la plus récente est sélectionnée automatiquement. |
| `auto_update` | Non | Booléen (`true`/`false`, défaut: `false`). Si activé et que des failles existent, crée la branche `security-update/date`, applique les mises à jour et pousse la branche sur origin. |
| `slack_webhook` | Non | URL du webhook entrant Slack pour notifier le channel dédié du projet. Accepte une URL directe (`https://hooks.slack.com/...`) ou une variable d'environnement débutant par `$` (ex. `$SLACK_WEBHOOK_PROJET`). |

---

## Utilisation

### Analyse standard (Composants Drupal uniquement)
```bash
python3 main.py
```

### Spécifier un autre fichier de configuration
```bash
python3 main.py --config mes-projets.json
```

### Forcer l'auto-update pour tous les projets nécessitant des mises à jour
```bash
python3 main.py --auto-update
```

### Auditer toutes les dépendances PHP (y compris outils tiers et vendors)
```bash
python3 main.py --all-packages
```

---

## Structure du projet

```text
DrupalSecurityUpdates/
├── main.py                  # Script principal d'audit et de génération de rapport
├── projects.json.example    # Modèle d'exemple de configuration
├── projects.json            # Configuration locale (ignorée par Git)
├── README.md                # Documentation du projet
├── projects/                # Dépôts Git clonés et mis à jour localement (ignoré)
└── reports/                 # Rapports d'audit Markdown générés (ignoré sauf .gitkeep)
```

---

## Fichiers de rapport

Chaque exécution génère, dans le dossier `reports/`, plusieurs fichiers partageant le même horodatage (`AAAA-MM-JJ-HH-MM-SS`) :

| Fichier | Contenu |
|---|---|
| `<horodatage>-global-report.md` | Rapport global : résumé et détails de **tous** les projets analysés. |
| `<horodatage>-<projet>-report.md` | Rapport individuel d'un projet : même structure que le rapport global (en-tête, résumé, détails), restreinte à ce seul projet. |

Exemple pour une exécution sur deux projets :

```text
reports/
├── 2026-10-22-11-33-18-global-report.md
├── 2026-10-22-11-33-18-ccb-irf-report.md
└── 2026-10-22-11-33-18-ccb-safeonweb-report.md
```

- `<projet>` est dérivé du champ `name` de `projects.json` : passage en minuscules, et toute suite de caractères non alphanumériques est remplacée par un tiret (ex. `CCB - Safeonweb` → `ccb-safeonweb`).
- Si deux projets produisent le même nom, un suffixe numérique est ajouté (`-2`, `-3`, …) pour éviter tout écrasement.
- Un rapport individuel est généré pour **chaque** projet, y compris ceux sans mise à jour requise ou en erreur.
- Les chemins de tous les rapports générés sont affichés dans la console en fin d'exécution.

---

## Exemple de rapport généré

```markdown
# Drupal Security Report

Date: `2026-10-14 11:01:06`
Scope: `Drupal components (drupal/*)`

## Summary

- Projects analyzed: `4`
- Projects requiring updates: `3`
- Components to update: `6`

## Details

### Mon Projet

- Repository: `git@gitlab.exemple.com:groupe/mon-projet.git`
- Branch: `release/2.2.12.1`

> 🚀 **Auto-update successful:** Branch `security-update/2026-10-14` was created, committed, and pushed to origin.
> - 💬 **Slack notification:** Sent to channel.

#### Required Security Updates

> **Combined require command for this project:**
> ```bash
> composer require drupal/core-recommended:11.4.7 drupal/core-composer-scaffold:11.4.7 drupal/core-project-message:11.4.7 'drupal/webform:^6.3.1' --update-with-all-dependencies
> ```

| Package | Current Version | Affected Versions | Target Version | Composer Command (require) | Primary Advisory | Link |
|---|---|---|---|---|---|---|
| `drupal/core` | `11.4.4` | `>=11.4.0 <11.4.7` | `11.4.7` | `composer require drupal/core-recommended:11.4.7 drupal/core-composer-scaffold:11.4.7 drupal/core-project-message:11.4.7 --update-with-all-dependencies` | Drupal core - Moderately critical - Third-party libraries - SA-CORE-2026-013 | [View](...) |
| `drupal/webform` | `6.3.0-beta7` | `<6.2.12 \|\| >=6.3.0 <6.3.1` | `6.3.1` | `composer require 'drupal/webform:^6.3.1' --update-with-all-dependencies` | Webform - Critical - Remote Code Execution - SA-CONTRIB-2026-175 *(+19 other advisories)* | [View](...) |

<details>
<summary>Detailed list of all detected advisories for this project</summary>
...
</details>
```
