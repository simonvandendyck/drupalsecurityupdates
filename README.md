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
- **Rapports Markdown horodatés** :
  - Génération automatique de rapports structurés dans le dossier `reports/`.

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
    "branch": "main"
  },
  {
    "name": "Mon Projet avec détection release",
    "repository": "git@gitlab.exemple.com:groupe/autre-projet.git"
  }
]
```

### Champs :
| Champ | Requis | Description |
|---|---|---|
| `name` | **Oui** | Nom identifiant le projet (utilisé pour le dossier local `projects/<name>`). |
| `repository` | **Oui** | URL Git du dépôt (privilégier SSH, ex. `git@...`). |
| `branch` | Non | Branche cible. Si omise, la branche `release/*` la plus récente est sélectionnée automatiquement. |

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

### Auditer toutes les dépendances PHP (y compris outils tiers et vendors)
```bash
python3 main.py --all-packages
```

---

## Structure du projet

```text
DrupalSecurityUpdates/
├── main.py              # Script principal d'audit et de génération de rapport
├── projects.json        # Liste des projets à surveiller
├── README.md            # Documentation du projet
├── projects/            # Dépôts Git clonés et mis à jour localement
└── reports/             # Rapports d'audit Markdown générés (report-AAAA-MM-JJ-HH-MM-SS.md)
```

---

## Exemple de rapport généré

```markdown
# Rapport de sécurité Drupal

Date : `2026-10-14 10:32:40`
Périmètre : `Composants Drupal (drupal/*)`

## Résumé

- Projets analysés : `4`
- Projets nécessitant des mises à jour : `3`
- Composants à mettre à jour : `6`

## Détails

### Mon Projet

- Repository : `git@gitlab.exemple.com:groupe/mon-projet.git`
- Branche : `release/2.2.12.1`

#### Mises à jour de sécurité requises

| Package | Version actuelle | Versions affectées | Avis principal | Lien |
|---|---|---|---|---|
| `drupal/core` | `11.4.4` | `>=11.4.0 <11.4.7` | Drupal core - Moderately critical - Third-party libraries - SA-CORE-2026-013 | [Voir](...) |
| `drupal/webform` | `6.3.0-beta7` | `<6.2.12 \|\| >=6.3.0 <6.3.1` | Webform - Critical - Remote Code Execution - SA-CONTRIB-2026-175 *(+19 autres failles)* | [Voir](...) |

<details>
<summary>Détail de toutes les failles détectées pour ce projet</summary>
...
</details>
```
