"""
Drupal Security Updates Auditor
===============================

This script automates security auditing for a collection of Drupal projects
managed via Composer and Git.

Core capabilities:
1. Git repository management:
   - Clones projects initially, or performs incremental updates (`fetch` and `pull`)
     if the local clone already exists to optimize execution speed.
   - Automatically detects the highest/latest `release/*` branch if no branch
     is specified in the configuration.
2. Dependency version extraction:
   - Inspects `composer.lock` to determine exact installed package versions.
3. Vulnerability auditing:
   - Runs `composer audit --format=json --locked` to detect known CVEs and security advisories.
   - Robustly handles PHP warnings or non-zero audit return codes.
4. Report generation:
   - By default, focuses on Drupal components (`drupal/*` core, contrib modules, and themes).
   - Deduplicates and consolidates advisories per package (1 line per package to update).
   - Generates a timestamped Markdown report with summary tables and collapsible CVE details.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path


# Base filesystem paths relative to this script
BASE_DIR = Path(__file__).parent.resolve()
PROJECTS_DIR = BASE_DIR / "projects"
REPORTS_DIR = BASE_DIR / "reports"


def run_command(command, cwd=None, env=None):
    """
    Execute an external shell command securely and capture its standard output/error.

    Environment Sanitization:
    -------------------------
    Certain IDE or runner environments (e.g., JetBrains ACP, CI runners) may inject
    GIT_CONFIG_* environment variables (such as an empty `core.sshCommand`), which can
    break Git SSH connectivity with errors like 'unable to fork'.
    We strip any GIT_CONFIG_* variables from the subprocess environment so that Git
    relies on the user's authentic system and SSH configuration.

    :param command: List of command arguments (e.g. ['git', 'pull']).
    :param cwd: Optional working directory for the subprocess.
    :param env: Optional dictionary of environment variables to add or override.
    :return: A dictionary containing 'returncode', 'stdout', and 'stderr'.
    """
    clean_env = os.environ.copy()

    # Remove conflicting Git config environment overrides
    for key in list(clean_env.keys()):
        if key.startswith("GIT_CONFIG_") or key in (
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_NOSYSTEM",
        ):
            del clean_env[key]

    # Apply any custom environment variable overrides passed by the caller
    if env:
        clean_env.update(env)

    result = subprocess.run(
        command,
        cwd=cwd,
        env=clean_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    return {
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def parse_release_version(branch_name):
    """
    Parse a release branch name into a comparable list of tokens for semantic sorting.

    Why this is needed:
    -------------------
    Standard alphabetical sorting places 'release/1.4' AFTER 'release/1.11.4', or
    'release/2.2.9.1' AFTER 'release/2.2.12.1' because '1' < '4' or '9' > '1'.
    This function splits the version string (e.g. 'release/2.2.12.1') into integer and
    string tuples: (0, 2), (0, 2), (0, 12), (0, 1).
    This ensures that Python's natural tuple comparison sorts versions numerically.

    :param branch_name: Branch name string (e.g. 'origin/release/2.2.12.1' or 'release/1.8.4').
    :return: A list of tuples (type_flag, value) that can be compared with other version lists.
    """
    # Strip remote prefix and 'release/' directory prefix
    clean = branch_name.replace("origin/", "").replace("refs/heads/", "")
    if clean.startswith("release/"):
        clean = clean[len("release/"):]

    tokens = []
    # Split by standard delimiters: dots, dashes, underscores
    for part in re.split(r"[-._]", clean):
        if not part:
            continue
        if part.isdigit():
            # Integer segments: flag 0 gives them priority over alphabetic qualifiers
            tokens.append((0, int(part)))
        else:
            # Handle alphanumeric parts like '12b' or 'rc2' by splitting numbers and letters
            for sub in re.findall(r"\d+|\D+", part):
                if sub.isdigit():
                    tokens.append((0, int(sub)))
                else:
                    # String segments (e.g. 'alpha', 'beta', 'rc')
                    tokens.append((1, sub.lower()))

    return tokens


def detect_latest_release_branch_local(project_path):
    """
    Inspect local Git references to identify the most recent 'release/*' branch.

    Ranking Criteria:
    -----------------
    1. Highest semantic version number (e.g. 2.2.12.1 beats 2.2.9.1).
    2. Commit timestamp as a tie-breaker.

    :param project_path: Path to the local git repository.
    :return: The selected branch name (e.g. 'release/2.2.12.1'), or None if none found.
    """
    result = run_command(
        [
            "git",
            "for-each-ref",
            "--sort=-committerdate",
            "--format=%(refname:short)|%(committerdate:unix)",
            "refs/remotes/origin/release/*",
        ],
        cwd=project_path,
    )

    if result["returncode"] != 0 or not result["stdout"]:
        return None

    candidates = []
    for line in result["stdout"].splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        ref = parts[0]
        timestamp = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        # Normalize by removing remote 'origin/' prefix
        branch_name = ref.replace("origin/", "")
        candidates.append((branch_name, timestamp))

    if not candidates:
        return None

    # Sort primarily by semantic version, secondarily by commit timestamp (highest first)
    candidates.sort(
        key=lambda item: (parse_release_version(item[0]), item[1]),
        reverse=True,
    )
    return candidates[0][0]


def detect_latest_release_branch_remote(repository):
    """
    Query a remote repository using `git ls-remote` to find the highest 'release/*' branch
    before cloning it locally.

    :param repository: Remote Git repository URL (e.g. 'git@gitlab...').
    :return: The selected branch name (e.g. 'release/1.11.4'), or None if none found.
    """
    result = run_command(
        ["git", "ls-remote", "--heads", repository, "refs/heads/release/*"]
    )

    if result["returncode"] != 0 or not result["stdout"]:
        return None

    branches = []
    for line in result["stdout"].splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            ref = parts[1]
            if ref.startswith("refs/heads/release/"):
                branches.append(ref[len("refs/heads/"):])

    if not branches:
        return None

    # Sort by semantic version and pick the highest one
    branches.sort(key=parse_release_version, reverse=True)
    return branches[0]


def load_projects(config_path):
    """
    Load and validate project specifications from a JSON configuration file.

    Expected JSON format:
    [
      {
        "name": "Project Name",
        "repository": "git@gitlab.com:org/repo.git",
        "branch": "optional-branch-name"
      }
    ]

    Note:
    - 'branch' is optional. If omitted or null, the latest release/* branch will be resolved.

    :param config_path: Path to the JSON configuration file.
    :return: List of project dictionaries.
    """
    with open(config_path, "r", encoding="utf-8") as file:
        projects = json.load(file)

    if not isinstance(projects, list):
        raise ValueError("The JSON configuration must contain a list of projects.")

    for project in projects:
        if "name" not in project:
            raise ValueError("Each project entry must define a 'name' field.")

        if "repository" not in project:
            raise ValueError(
                f"Project '{project.get('name')}' is missing the 'repository' field."
            )

    return projects


def clone_or_update_project(project):
    """
    Ensure the target repository is locally available and checked out to the desired branch.

    Workflow:
    ---------
    Case A: The repository already exists locally (.git is present):
      1. Synchronize remote URL to match configuration.
      2. Fetch all remote changes with pruning (`git fetch --prune origin`).
      3. If no branch was specified, determine the latest `release/*` branch from fetched refs.
      4. Checkout the target branch.
      5. Pull the latest commits from origin (`git pull origin <branch>`).

    Case B: The repository is not present or corrupted:
      1. Clean up invalid directories if necessary.
      2. If no branch was specified, query remote branches via `git ls-remote`.
      3. Perform a clean clone directly on the target branch (`git clone -b <branch>`).

    :param project: Project dictionary with 'name', 'repository', and optional 'branch'.
    :return: Dictionary with 'success', 'path', 'branch', and optional 'error'.
    """
    project_name = project["name"]
    repository = project["repository"]
    branch = project.get("branch")

    project_path = PROJECTS_DIR / project_name

    # --- CASE A: Incremental update of existing local repository ---
    if (project_path / ".git").is_dir():
        print(f"[{project_name}] Project repository already exists locally. Updating...")

        # Ensure the remote origin URL points to the configured repository
        run_command(["git", "remote", "set-url", "origin", repository], cwd=project_path)

        # Fetch latest branches and tags from origin
        fetch_result = run_command(
            ["git", "fetch", "--prune", "origin"],
            cwd=project_path,
        )

        if fetch_result["returncode"] != 0:
            return {
                "success": False,
                "path": project_path,
                "branch": branch,
                "error": fetch_result["stderr"] or fetch_result["stdout"],
            }

        # If branch is not specified, auto-detect the latest release/* branch
        if not branch:
            print(f"[{project_name}] No branch specified. Detecting the latest 'release/*' branch...")
            branch = detect_latest_release_branch_local(project_path)
            if not branch:
                return {
                    "success": False,
                    "path": project_path,
                    "branch": None,
                    "error": "No branch matching 'release/*' was found on this repository.",
                }
            print(f"[{project_name}] Auto-selected release branch: {branch}")

        print(f"[{project_name}] Checking out branch '{branch}'...")

        checkout_result = run_command(
            ["git", "checkout", branch],
            cwd=project_path,
        )

        if checkout_result["returncode"] != 0:
            return {
                "success": False,
                "path": project_path,
                "branch": branch,
                "error": checkout_result["stderr"] or checkout_result["stdout"],
            }

        print(f"[{project_name}] Pulling latest changes from origin/{branch}...")

        pull_result = run_command(
            ["git", "pull", "origin", branch],
            cwd=project_path,
        )

        if pull_result["returncode"] != 0:
            return {
                "success": False,
                "path": project_path,
                "branch": branch,
                "error": pull_result["stderr"] or pull_result["stdout"],
            }

    # --- CASE B: Initial clone of repository ---
    else:
        # If directory exists but without a valid .git directory, remove it
        if project_path.exists():
            print(f"[{project_name}] Directory exists but is not a valid Git repo. Recreating...")
            shutil.rmtree(project_path)

        # If branch is not specified, inspect remote refs to find the latest release/* branch
        if not branch:
            print(f"[{project_name}] No branch specified. Querying remote for latest 'release/*' branch...")
            branch = detect_latest_release_branch_remote(repository)
            if not branch:
                return {
                    "success": False,
                    "path": project_path,
                    "branch": None,
                    "error": "No remote branch matching 'release/*' was found on the remote repository.",
                }
            print(f"[{project_name}] Auto-selected remote release branch: {branch}")

        print(f"[{project_name}] Cloning repository on branch '{branch}'...")

        clone_result = run_command(
            ["git", "clone", "-b", branch, repository, str(project_path)]
        )

        if clone_result["returncode"] != 0:
            return {
                "success": False,
                "path": project_path,
                "branch": branch,
                "error": clone_result["stderr"] or clone_result["stdout"],
            }

    return {
        "success": True,
        "path": project_path,
        "branch": branch,
        "error": None,
    }


def composer_files_exist(project_path):
    """
    Check if both `composer.json` and `composer.lock` exist in the project directory.

    :param project_path: Path to the project root.
    :return: Tuple (bool composer_json_exists, bool composer_lock_exists).
    """
    composer_json = project_path / "composer.json"
    composer_lock = project_path / "composer.lock"

    return composer_json.exists(), composer_lock.exists()


def get_installed_versions(project_path):
    """
    Extract installed package versions from the project's `composer.lock` file.

    Both production packages (`packages`) and development packages (`packages-dev`)
    are parsed to ensure complete coverage.

    :param project_path: Path to the project root.
    :return: Dictionary mapping package name to installed version string (e.g. {'drupal/core': '11.4.4'}).
    """
    lock_file = project_path / "composer.lock"
    if not lock_file.exists():
        return {}

    try:
        with open(lock_file, "r", encoding="utf-8") as file:
            data = json.load(file)

        packages = {}
        all_pkgs = data.get("packages", []) + data.get("packages-dev", [])
        for pkg in all_pkgs:
            if isinstance(pkg, dict) and "name" in pkg and "version" in pkg:
                packages[pkg["name"]] = pkg["version"]

        return packages
    except Exception:
        return {}


def run_composer_audit(project_path):
    """
    Run Composer's security audit on the locked packages.

    Command Details:
    ----------------
    `composer audit --format=json --locked`
    - `--locked` analyzes `composer.lock` without requiring `vendor/` to be installed.
    - `--format=json` outputs machine-readable vulnerability advisories.

    Composer Exit Codes:
    --------------------
    Composer audit uses bitwise flags for return codes:
    - 0: No vulnerabilities or abandoned packages found.
    - 1: Audit command failed / execution error.
    - 2: Abandoned packages found.
    - 4: Vulnerabilities found (this is standard and expected when advisories exist).
    Therefore, a non-zero returncode does NOT mean the audit failed as long as valid JSON
    was produced.

    Resilience:
    -----------
    If PHP notices or deprecations are prepended/appended to stdout, we extract the substring
    between the first '{' and the last '}' to reliably parse the JSON payload.

    :param project_path: Working directory of the target project.
    :return: Dictionary with 'success', 'raw' (parsed JSON data), and optional 'error'.
    """
    result = run_command(
        ["composer", "audit", "--format=json", "--locked"],
        cwd=project_path,
    )

    stdout = result["stdout"]
    if not stdout:
        return {
            "success": result["returncode"] == 0,
            "raw": None,
            "error": result["stderr"] or f"Composer error (exit code {result['returncode']})",
        }

    try:
        audit_data = json.loads(stdout)
    except json.JSONDecodeError:
        # Extract JSON substring if extraneous PHP warnings/notices polluted stdout
        start = stdout.find("{")
        end = stdout.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                audit_data = json.loads(stdout[start : end + 1])
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "raw": None,
                    "error": stdout or result["stderr"],
                }
        else:
            return {
                "success": False,
                "raw": None,
                "error": stdout or result["stderr"],
            }

    return {
        "success": True,
        "raw": audit_data,
        "error": None,
    }


def parse_num_version(v):
    """
    Parse a version string into a comparable tuple of integers (e.g. '11.4.4' -> (11, 4, 4, 0)).
    """
    if not v or v == "-":
        return (0, 0, 0, 0)
    clean = re.split(r"[-+]", v)[0]
    parts = []
    for p in clean.split("."):
        if p.isdigit():
            parts.append(int(p))
        else:
            break
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def determine_target_version(installed_ver, affected_constraints_list):
    """
    Deduce the minimum safe target version that resolves the vulnerabilities.

    Logic:
    ------
    From the list of affected version constraints (e.g. '<6.2.12 || >=6.3.0 <6.3.1'):
    1. Parse clauses and identify upper-bound limits (<X.Y.Z).
    2. Prioritize candidate boundaries matching the currently installed major.minor branch.
    3. Return the exact safe version that exceeds the vulnerable range.

    :param installed_ver: Currently installed version string (e.g. '6.3.0-beta7').
    :param affected_constraints_list: List of affected version expressions from advisories.
    :return: Recommended target version string (e.g. '6.3.1') or None.
    """
    if not installed_ver or installed_ver == "-":
        return None

    inst_tuple = parse_num_version(installed_ver)
    candidate_targets = []

    for full_constraint in affected_constraints_list:
        clauses = re.split(r"\|\||\|", full_constraint)
        for clause in clauses:
            clause = clause.strip()
            lower_m = re.search(r">=?\s*([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?)\b", clause)
            upper_m = re.search(r"<\s*([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?)\b", clause)

            lower_v = lower_m.group(1) if lower_m else None
            upper_v = upper_m.group(1) if upper_m else None

            if upper_v:
                up_tuple = parse_num_version(upper_v)
                low_tuple = parse_num_version(lower_v) if lower_v else (0, 0, 0, 0)

                # Priority 1: same major and minor branch (e.g. installed 6.3.x and upper bound 6.3.1)
                if (inst_tuple[0], inst_tuple[1]) == (up_tuple[0], up_tuple[1]):
                    candidate_targets.append((1, up_tuple, upper_v))
                # Priority 2: same major, installed is lower
                elif inst_tuple[0] == up_tuple[0] and inst_tuple < up_tuple:
                    candidate_targets.append((2, up_tuple, upper_v))
                # Priority 3: falls between lower and upper
                elif low_tuple <= inst_tuple < up_tuple:
                    candidate_targets.append((3, up_tuple, upper_v))
                else:
                    candidate_targets.append((4, up_tuple, upper_v))

    if not candidate_targets:
        return None

    # Sort: lowest priority rank first, then highest version numbers
    candidate_targets.sort(key=lambda x: (x[0], -x[1][0], -x[1][1], -x[1][2], -x[1][3]))
    return candidate_targets[0][2]


def extract_package_updates(audit_data, installed_versions, drupal_only=True):
    """
    Process raw audit data into clean, consolidated package update recommendations.

    Why consolidation is essential:
    -------------------------------
    `composer audit` outputs one advisory per CVE. If a package (like `drupal/webform`)
    has 20 past CVEs, raw output repeats the package 20 times.
    In practice, a single `composer require` resolves all of them.
    This function groups all advisories by package, displays the installed version,
    the affected version range, the deduced target safe version, and the most recent advisory.

    Handling Composer JSON Structure:
    ---------------------------------
    Composer serializes PHP arrays with associative or non-sequential keys as JSON objects
    (e.g., `{"1": {...}}`) instead of JSON lists `[{...}]`. We support both formats.

    :param audit_data: Parsed JSON dictionary returned by composer audit.
    :param installed_versions: Dictionary mapping package names to installed versions.
    :param drupal_only: If True, only include packages starting with 'drupal/'.
    :return: List of consolidated package update dictionaries.
    """
    if not audit_data:
        return []

    advisories = audit_data.get("advisories", {})
    package_updates = []

    for package_name, package_advisories in advisories.items():
        # Filter out non-Drupal packages if requested (e.g. php_codesniffer, commonmark)
        if drupal_only and not package_name.startswith("drupal/"):
            continue

        # Handle both list and dict representations of advisories from PHP JSON output
        if isinstance(package_advisories, dict):
            advisory_list = list(package_advisories.values())
        elif isinstance(package_advisories, list):
            advisory_list = package_advisories
        else:
            continue

        valid_advisories = [adv for adv in advisory_list if isinstance(adv, dict)]
        if not valid_advisories:
            continue

        installed_version = installed_versions.get(package_name, "-")

        # Collect unique affected version constraints
        affected_list = []
        for adv in valid_advisories:
            aff = adv.get("affectedVersions", "")
            if aff and aff not in affected_list:
                affected_list.append(aff)
        affected_versions = " ; ".join(affected_list) if affected_list else "-"

        # Deduce the exact target safe version
        target_version = determine_target_version(installed_version, affected_list)

        # Sort advisories by report date in descending order (most recent first)
        sorted_advisories = sorted(
            valid_advisories,
            key=lambda a: a.get("reportedAt", "") or "",
            reverse=True,
        )

        main_advisory = sorted_advisories[0]
        main_title = main_advisory.get("title", "Untitled")
        main_link = main_advisory.get("link", "")

        package_updates.append(
            {
                "package": package_name,
                "installed_version": installed_version,
                "affected_versions": affected_versions,
                "target_version": target_version,
                "total_advisories": len(valid_advisories),
                "main_title": main_title,
                "main_link": main_link,
                "all_advisories": [
                    {
                        "title": adv.get("title", "Untitled"),
                        "cve": adv.get("cve", ""),
                        "link": adv.get("link", ""),
                        "affected_versions": adv.get("affectedVersions", ""),
                    }
                    for adv in sorted_advisories
                ],
            }
        )

    # Sort packages alphabetically by name
    package_updates.sort(key=lambda p: p["package"])
    return package_updates


def get_package_require_args(package_name, target_version, installed_packages):
    """
    Build the exact CLI argument(s) for a package to be updated via `composer require`.

    Drupal Core Special Handling:
    -----------------------------
    If the project uses `drupal/core-recommended`, Drupal best practices require
    updating `core-recommended`, `core-composer-scaffold`, and `core-project-message`
    together to identical pinned versions.

    Contrib Modules:
    ----------------
    Contrib modules use caret constraints (e.g. `'drupal/webform:^6.3.1'`).

    :param package_name: Name of the package (e.g. 'drupal/core' or 'drupal/webform').
    :param target_version: Deduce target version (e.g. '11.4.7' or '6.3.1').
    :param installed_packages: Dict of installed package names in the project.
    :return: List of package:version argument strings.
    """
    if package_name in ("drupal/core", "drupal/core-recommended"):
        ver = target_version or "latest"
        if "drupal/core-recommended" in installed_packages:
            args = [f"drupal/core-recommended:{ver}"]
            if "drupal/core-composer-scaffold" in installed_packages:
                args.append(f"drupal/core-composer-scaffold:{ver}")
            if "drupal/core-project-message" in installed_packages:
                args.append(f"drupal/core-project-message:{ver}")
            return args
        else:
            return [f"'drupal/core:^{ver}'" if target_version else "drupal/core"]

    if target_version:
        return [f"'{package_name}:^{target_version}'"]
    return [package_name]


def get_package_require_command(package_name, target_version, installed_packages):
    """
    Generate the precise `composer require` CLI command for an individual package.

    :param package_name: Name of the package.
    :param target_version: Deduced safe version.
    :param installed_packages: Dict of all installed package names.
    :return: Formatted Composer CLI command string.
    """
    args = get_package_require_args(package_name, target_version, installed_packages)
    return f"composer require {' '.join(args)} --update-with-all-dependencies"


def get_project_require_command(updates, installed_packages):
    """
    Generate a single combined `composer require` command with all required security
    updates for the entire project.

    :param updates: List of package update dictionaries.
    :param installed_packages: Dict of all installed package names in the project.
    :return: Combined Composer CLI command string.
    """
    all_args = []
    seen = set()

    for u in updates:
        args = get_package_require_args(
            u["package"],
            u.get("target_version"),
            installed_packages,
        )
        for arg in args:
            if arg not in seen:
                seen.add(arg)
                all_args.append(arg)

    if not all_args:
        return ""

    return f"composer require {' '.join(all_args)} --update-with-all-dependencies"


def perform_auto_update(project_path, original_branch, updates, installed_packages, project_name=""):
    """
    Perform automated security updates on a dedicated Git branch and push to origin if successful.

    Workflow:
    ---------
    1. Formulate branch name: 'security-update/YYYY-MM-DD'.
       If already exists locally, append timestamp suffix.
    2. Check out new branch from the current clean base branch.
    3. Run `composer require` with exact target versions.
    4. If successful:
       - Commit changes (composer.json, composer.lock, and any scaffolded assets).
       - Push branch to remote repository (`git push -u origin <branch>`).
       - Return to original base branch.
       - Return success status.
    5. If unsuccessful:
       - Rollback changes (`git reset --hard`).
       - Switch back to base branch and delete the temporary branch.
       - Return error details.

    :param project_path: Path to the local repository.
    :param original_branch: Base branch that was checked out.
    :param updates: List of package update dicts.
    :param installed_packages: Dict of installed package names.
    :param project_name: Project name for console logs.
    :return: Dict with 'success', 'branch', and optional 'error' / 'commit'.
    """
    now = datetime.now()
    base_branch_name = f"security-update/{now.strftime('%Y-%m-%d')}"
    branch_name = base_branch_name

    # Check if branch exists locally
    check_branch = run_command(["git", "branch", "--list", branch_name], cwd=project_path)
    if check_branch["stdout"].strip():
        branch_name = f"security-update/{now.strftime('%Y-%m-%d-%H%M%S')}"

    print(f"[{project_name}] Creating update branch '{branch_name}' from '{original_branch}'...")
    checkout_res = run_command(["git", "checkout", "-b", branch_name], cwd=project_path)
    if checkout_res["returncode"] != 0:
        # Fallback with timestamp in case of naming conflict
        branch_name = f"security-update/{now.strftime('%Y-%m-%d-%H%M%S')}"
        checkout_res = run_command(["git", "checkout", "-b", branch_name], cwd=project_path)
        if checkout_res["returncode"] != 0:
            return {
                "success": False,
                "branch": branch_name,
                "error": f"Failed to create branch '{branch_name}': {checkout_res['stderr'] or checkout_res['stdout']}",
            }

    # Extract raw package require arguments without shell quotes
    all_raw_args = []
    seen = set()
    for u in updates:
        args = get_package_require_args(
            u["package"],
            u.get("target_version"),
            installed_packages,
        )
        for arg in args:
            clean_arg = arg.strip("'\"")
            if clean_arg not in seen:
                seen.add(clean_arg)
                all_raw_args.append(clean_arg)

    if not all_raw_args:
        run_command(["git", "checkout", original_branch], cwd=project_path)
        return {
            "success": False,
            "branch": branch_name,
            "error": "No packages to require.",
        }

    composer_cmd = ["composer", "require", *all_raw_args, "--update-with-all-dependencies", "--no-interaction"]
    print(f"[{project_name}] Running: {' '.join(composer_cmd)}...")

    require_res = run_command(composer_cmd, cwd=project_path)

    if require_res["returncode"] != 0:
        print(f"[{project_name}] Composer require failed. Rolling back changes...")
        run_command(["git", "reset", "--hard"], cwd=project_path)
        run_command(["git", "checkout", original_branch], cwd=project_path)
        run_command(["git", "branch", "-D", branch_name], cwd=project_path)
        return {
            "success": False,
            "branch": branch_name,
            "error": require_res["stderr"] or require_res["stdout"],
        }

    # Check git status for modifications
    status_res = run_command(["git", "status", "--porcelain"], cwd=project_path)
    if not status_res["stdout"].strip():
        print(f"[{project_name}] No changes detected after require. Returning to '{original_branch}'...")
        run_command(["git", "checkout", original_branch], cwd=project_path)
        run_command(["git", "branch", "-D", branch_name], cwd=project_path)
        return {
            "success": True,
            "branch": branch_name,
            "message": "Already up to date, no files were modified.",
            "error": None,
        }

    print(f"[{project_name}] Committing changes on branch '{branch_name}'...")
    run_command(["git", "add", "-A"], cwd=project_path)

    packages_str = ", ".join([u["package"] for u in updates])
    commit_msg = f"Security updates: {packages_str}"
    commit_res = run_command(["git", "commit", "-m", commit_msg], cwd=project_path)

    if commit_res["returncode"] != 0:
        print(f"[{project_name}] Commit failed. Rolling back...")
        run_command(["git", "reset", "--hard"], cwd=project_path)
        run_command(["git", "checkout", original_branch], cwd=project_path)
        run_command(["git", "branch", "-D", branch_name], cwd=project_path)
        return {
            "success": False,
            "branch": branch_name,
            "error": f"Failed to commit changes: {commit_res['stderr'] or commit_res['stdout']}",
        }

    print(f"[{project_name}] Pushing branch '{branch_name}' to origin...")
    push_res = run_command(["git", "push", "-u", "origin", branch_name], cwd=project_path)

    # Always return to original branch
    run_command(["git", "checkout", original_branch], cwd=project_path)

    if push_res["returncode"] != 0:
        print(f"[{project_name}] Push failed!")
        return {
            "success": False,
            "branch": branch_name,
            "error": f"Push failed: {push_res['stderr'] or push_res['stdout']}",
        }

    print(f"[{project_name}] Successfully pushed '{branch_name}' to origin.")
    return {
        "success": True,
        "branch": branch_name,
        "commit": commit_msg,
        "error": None,
    }


def generate_report(results, drupal_only=True):
    """
    Generate a comprehensive, structured Markdown report from the audit results.

    Report Structure:
    -----------------
    1. Header & Metadata (Date, Audited Scope).
    2. Executive Summary (total projects, vulnerable projects, packages to update).
    3. Per-Project Details:
       - Repository & active Branch.
       - Execution errors if any.
       - Missing Composer file warnings if any.
       - Combined Composer command to update all project packages at once.
       - Clean, consolidated table of packages to update (Package, Installed, Affected, Update Command, Primary Advisory, Link).
       - Collapsible `<details>` section containing every individual CVE/advisory with links.

    Markdown Table Safety:
    ----------------------
    Pipe characters (`|`) in advisory titles or version constraints (e.g. `<3.13|>=4.0`)
    are escaped as `\\|` to preserve table column alignments.

    :param results: List of project analysis dictionaries.
    :param drupal_only: Whether the analysis was filtered to Drupal packages only.
    :return: Path to the generated Markdown file.
    """
    REPORTS_DIR.mkdir(exist_ok=True)

    now = datetime.now()
    report_name = f"report-{now.strftime('%Y-%m-%d-%H-%M-%S')}.md"
    report_path = REPORTS_DIR / report_name

    total_projects = len(results)
    projects_with_updates = sum(
        1 for result in results if result.get("updates")
    )
    total_packages_to_update = sum(
        len(result.get("updates", [])) for result in results
    )

    scope_text = "Drupal components (`drupal/*`)" if drupal_only else "All packages"

    lines = [
        "# Drupal Security Report",
        "",
        f"Date: `{now.strftime('%Y-%m-%d %H:%M:%S')}`",
        f"Scope: `{scope_text}`",
        "",
        "## Summary",
        "",
        f"- Projects analyzed: `{total_projects}`",
        f"- Projects requiring updates: `{projects_with_updates}`",
        f"- Components to update: `{total_packages_to_update}`",
        "",
        "## Details",
        "",
    ]

    for result in results:
        project_name = result["name"]
        branch = result["branch"]
        repository = result["repository"]

        lines.extend(
            [
                f"### {project_name}",
                "",
                f"- Repository: `{repository}`",
                f"- Branch: `{branch}`",
                "",
            ]
        )

        # Handle any critical execution/git errors
        if result.get("error"):
            lines.extend(
                [
                    "#### Error",
                    "",
                    "```text",
                    result["error"],
                    "```",
                    "",
                ]
            )
            continue

        # Handle missing composer.json
        if not result.get("composer_json_exists"):
            lines.extend(
                [
                    "⚠️ No `composer.json` file found.",
                    "",
                ]
            )
            continue

        # Handle missing composer.lock
        if not result.get("composer_lock_exists"):
            lines.extend(
                [
                    "⚠️ No `composer.lock` file found.",
                    "",
                ]
            )
            continue

        updates = result.get("updates", [])

        # Clean project with no detected vulnerabilities
        if not updates:
            lines.extend(
                [
                    "✅ No Drupal security updates required.",
                    "",
                ]
            )
            continue

        # Auto-update status block if executed
        auto_up = result.get("auto_update_result")
        if auto_up:
            if auto_up.get("success"):
                up_branch = auto_up.get("branch")
                lines.extend(
                    [
                        f"> 🚀 **Auto-update successful:** Branch `{up_branch}` was created, committed, and pushed to origin.",
                        "",
                    ]
                )
            else:
                err_msg = auto_up.get("error", "Unknown error")
                lines.extend(
                    [
                        f"> ❌ **Auto-update failed:** `{err_msg}`",
                        "",
                    ]
                )

        # Combined command for updating all packages at once
        installed_packages = result.get("installed_packages", {})
        combined_cmd = get_project_require_command(updates, installed_packages)

        # Table of required package updates
        lines.extend(
            [
                "#### Required Security Updates",
                "",
                "> **Combined require command for this project:**",
                f"> ```bash\n> {combined_cmd}\n> ```",
                "",
                "| Package | Current Version | Affected Versions | Target Version | Composer Command (require) | Primary Advisory | Link |",
                "|---|---|---|---|---|---|---|",
            ]
        )

        for update in updates:
            package = update["package"]
            installed = update["installed_version"]
            # Escape pipe symbols to prevent breaking markdown tables
            affected = str(update["affected_versions"]).replace("|", "\\|")
            target_ver = update.get("target_version") or "-"
            update_cmd = f"`{get_package_require_command(package, update.get('target_version'), installed_packages)}`"

            count = update["total_advisories"]
            main_title = str(update["main_title"]).replace("|", "\\|")
            if count > 1:
                title_display = f"{main_title} *(+{count - 1} other{'s' if count > 2 else ''} advisory/advisories)*"
            else:
                title_display = main_title

            link = update["main_link"] or "-"
            link_display = f"[View]({link})" if link != "-" else "-"

            lines.append(
                f"| `{package}` | `{installed}` | `{affected}` | `{target_ver}` | {update_cmd} | {title_display} | {link_display} |"
            )

        lines.append("")

        # Collapsible details section for granular advisory breakdown
        lines.extend(
            [
                "<details>",
                "<summary>Detailed list of all detected advisories for this project</summary>",
                "",
            ]
        )
        for update in updates:
            lines.append(f"**`{update['package']}`** ({update['total_advisories']} advisories):")
            lines.append("")
            for adv in update["all_advisories"]:
                adv_title = adv["title"]
                adv_cve = f" - `{adv['cve']}`" if adv.get("cve") else ""
                adv_link = f" - [Link]({adv['link']})" if adv.get("link") else ""
                lines.append(f"- {adv_title}{adv_cve}{adv_link}")
            lines.append("")
        lines.extend(["</details>", ""])

    with open(report_path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))

    return report_path


def analyze_project(project, drupal_only=True, auto_update=False):
    """
    Coordinate the end-to-end security analysis for a single project.

    Steps:
    1. Clone or update the Git repository and determine the active branch.
    2. Check for existence of composer.json and composer.lock.
    3. Extract currently installed versions from composer.lock.
    4. Run `composer audit`.
    5. Filter and consolidate security update advisories.

    :param project: Project specification dictionary.
    :param drupal_only: Whether to restrict the audit to Drupal packages.
    :return: Analysis result dictionary.
    """
    project_name = project["name"]

    print(f"\nAnalyzing project: {project_name}")

    clone_result = clone_or_update_project(project)

    # Use the branch resolved by the clone/update process
    detected_branch = clone_result.get("branch") or project.get("branch") or "-"

    result = {
        "name": project["name"],
        "repository": project["repository"],
        "branch": detected_branch,
        "composer_json_exists": False,
        "composer_lock_exists": False,
        "updates": [],
        "error": None,
    }

    if not clone_result["success"]:
        result["error"] = clone_result["error"]
        return result

    project_path = clone_result["path"]

    composer_json_exists, composer_lock_exists = composer_files_exist(project_path)

    result["composer_json_exists"] = composer_json_exists
    result["composer_lock_exists"] = composer_lock_exists

    if not composer_json_exists:
        result["error"] = "composer.json file not found."
        return result

    if not composer_lock_exists:
        result["error"] = "composer.lock file not found."
        return result

    # Read installed package versions from composer.lock
    installed_versions = get_installed_versions(project_path)
    result["installed_packages"] = installed_versions

    print(f"[{project_name}] Running composer audit...")

    audit_result = run_composer_audit(project_path)

    if not audit_result["success"]:
        result["error"] = (
            audit_result["error"]
            or "Unknown error while executing composer audit."
        )
        return result

    # Consolidate advisories per package
    result["updates"] = extract_package_updates(
        audit_result["raw"],
        installed_versions,
        drupal_only=drupal_only,
    )

    should_auto_update = auto_update or project.get("auto_update", False)
    if should_auto_update and result["updates"]:
        print(f"[{project_name}] 'auto_update' is enabled. Initiating automated branch creation and update...")
        auto_update_res = perform_auto_update(
            project_path=project_path,
            original_branch=detected_branch,
            updates=result["updates"],
            installed_packages=installed_versions,
            project_name=project_name,
        )
        result["auto_update_result"] = auto_update_res

    return result


def main():
    """
    Entry point for CLI execution.
    Parses arguments, initializes directories, processes projects, and generates the report.
    """
    parser = argparse.ArgumentParser(
        description="Audit Drupal project security updates via Composer."
    )

    parser.add_argument(
        "--config",
        default="projects.json",
        help="Path to JSON configuration file containing the list of projects (default: projects.json).",
    )

    parser.add_argument(
        "--all-packages",
        action="store_true",
        help="Audit all third-party PHP packages instead of targeting only Drupal packages (drupal/*).",
    )

    parser.add_argument(
        "--auto-update",
        action="store_true",
        help="Enable automated branch creation, update execution, and publication for projects requiring updates.",
    )

    args = parser.parse_args()
    config_path = Path(args.config)
    drupal_only = not args.all_packages

    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}"
        )

    # Ensure output directories exist
    PROJECTS_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)

    projects = load_projects(config_path)
    results = []

    for project in projects:
        result = analyze_project(
            project,
            drupal_only=drupal_only,
            auto_update=args.auto_update,
        )
        results.append(result)

    report_path = generate_report(results, drupal_only=drupal_only)

    print("")
    print(f"Report generated: {report_path}")


if __name__ == "__main__":
    main()
