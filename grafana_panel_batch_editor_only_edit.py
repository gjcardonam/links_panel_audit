#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
grafana_panel_batch_editor.py

Edits ONE panel across companies:
- Dashboard title is read from config per environment: grafana.dashboard_to_edit
- Panel to update is matched by `type` and `title` extracted from the provided panel template JSON
- Merges template onto the existing panel, preserving gridPos (and id by default)
- Only edits the dashboard whose title matches config AND that sits in the folder titled exactly as the company name

Usage:
  python grafana_panel_batch_editor.py \
    -c replication.json \
    --panel-json panel_template.json \
    --preserve-keys gridPos id \
    --message "Batch edit" \
    --dry-run
"""

import os, sys, json, time, argparse
from typing import Any, Dict, List, Optional, Iterator, Set
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth

# ---------------- util ----------------

# ---------------- util ----------------
def progress_bar(done: int, total: int, prefix: str = "", width: int = 46) -> None:
    if total <= 0:
        total = 1
    ratio = max(0.0, min(1.0, done / total))
    filled = int(width * ratio)
    bar = "█" * filled + "░" * (width - filled)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total} ({ratio*100:5.1f}%)")
    sys.stdout.flush()

def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path: str, payload: dict) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

def norm(s: Optional[str]) -> str:
    return (s or "").strip().casefold()

def _bool_env_default(val, default_true=True):
    if isinstance(val, bool): return val
    if val is None: return default_true
    return str(val).lower() not in {"0","false","no"}

# ---------------- config ----------------

def _resolve_grafana_fields(env_block: dict) -> Dict[str, Any]:
    g = env_block.get("grafana", {}) if env_block else {}
    return {
        "url": (g.get("url") or os.getenv("GRAFANA_URL","")).rstrip("/"),
        "username": os.getenv("GRAFANA_USERNAME", g.get("username","")),
        "password": os.getenv("GRAFANA_PASSWORD", g.get("password","")),
        "verify_ssl": _bool_env_default(os.getenv("VERIFY_SSL", g.get("verify_ssl", True)), True),
        "companies_inline": g.get("companies"),
        "companies_file": os.getenv("COMPANIES_FILE", g.get("companies_file","companies.json")),
        # NEW: dashboard title to edit (required for this script)
        "dashboard_to_edit": g.get("dashboard_to_edit"),
    }

def build_config(args) -> Dict[str, Any]:
    try:
        from dotenv import load_dotenv, find_dotenv
        load_dotenv(find_dotenv(), override=False)
    except Exception:
        pass
    cfg = load_json(args.config)
    if "environments" not in cfg:
        env_name = cfg.get("env_name", os.getenv("ENV_NAME","dev"))
        environments = [{"name": env_name, "grafana": cfg.get("grafana", {})}]
    else:
        environments = cfg["environments"]

    envs_resolved = []
    for env in environments:
        envs_resolved.append({"name": env.get("name") or "dev", "grafana": _resolve_grafana_fields(env)})

    # NEW: support for progress.bar_width (defaults to 46)
    bar_width = int((cfg.get("progress") or {}).get("bar_width", 46))

    return {"environments": envs_resolved, "bar_width": bar_width}


# ---------------- grafana http ----------------

def make_session(url: str, user: str, passwd: str, verify_ssl: bool):
    s = requests.Session()
    s.headers.update({"Accept": "application/json"})
    if user:
        s.auth = HTTPBasicAuth(user, passwd)
    s.verify = verify_ssl
    return s, url

def switch_organization(session: requests.Session, base_url: str, org_id: int) -> None:
    r = session.post(f"{base_url}/user/using/{org_id}")
    if r.status_code != 200:
        raise RuntimeError(f"Switch org {org_id} failed: {r.status_code} {r.text}")

def search_folders(session: requests.Session, base_url: str, q: str) -> List[Dict[str, Any]]:
    r = session.get(f"{base_url}/search", params={"type":"dash-folder","query":q,"limit":5000})
    r.raise_for_status()
    return r.json() or []

def find_company_folder(session, base_url: str, company_name: str) -> Optional[Dict[str, Any]]:
    for it in search_folders(session, base_url, company_name):
        if norm(it.get("title")) == norm(company_name):
            return it
    return None

def find_dashboard_in_folder(session, base_url: str, folder_title: str, dashboard_title: str) -> Optional[str]:
    r = session.get(f"{base_url}/search", params={"type":"dash-db","query":dashboard_title,"limit":5000})
    r.raise_for_status()
    for it in (r.json() or []):
        if norm(it.get("title")) == norm(dashboard_title) and norm(it.get("folderTitle")) == norm(folder_title):
            return it.get("uid")
    return None

def get_dashboard_by_uid(session: requests.Session, base_url: str, uid: str) -> Dict[str, Any]:
    r = session.get(f"{base_url}/dashboards/uid/{uid}")
    r.raise_for_status()
    return r.json()

def write_dashboard(session: requests.Session, base_url: str, dashboard_payload: Dict[str, Any], message: str, folder_id: Optional[int] = None, overwrite: bool = True):
    body = {"dashboard": dashboard_payload, "overwrite": overwrite, "message": message or ""}
    if folder_id is not None:
        body["folderId"] = folder_id
    r = session.post(f"{base_url}/dashboards/db", json=body)
    if r.status_code not in (200, 202):
        raise RuntimeError(f"Write dashboard failed: {r.status_code} {r.text}")
    return r.json()

# ---------------- panel helpers ----------------

def iter_all_panels(panels: List[Dict[str, Any]]):
    if not panels:
        return
    for p in panels:
        yield p
        inner = p.get("panels")
        if isinstance(inner, list) and inner:
            yield from iter_all_panels(inner)

def find_panel_by_type_and_title(dashboard: Dict[str, Any], panel_type: str, panel_title: str) -> Optional[Dict[str, Any]]:
    for p in iter_all_panels(dashboard.get("panels", []) or []):
        if norm(p.get("type")) == norm(panel_type) and norm(p.get("title")) == norm(panel_title):
            return p
    return None

def diff_only_merge(existing: Any, template: Any, preserve_keys: Set[str]) -> Tuple[Any, int]:
    """
    Return (merged_obj, changes_count).

    Rules:
    - Dicts: update only keys present in BOTH; recurse; never add or delete keys.
    - Lists: do NOT change length. Update indices [0..min(len(existing), len(template))-1].
             Recurse on dict elements; for scalars, replace only if different.
    - Scalars: replace only if different.
    - Always preserve keys listed in `preserve_keys` from `existing` (for dict level).

    Notes:
    - We copy 'existing' first so original reference is not mutated during diffing.
    - 'changes_count' accumulates every scalar replacement and any nested changes.
    """
    from copy import deepcopy

    def _merge(a: Any, b: Any, at_dict_level_preserve: Optional[Set[str]]) -> Tuple[Any, int]:
        # Scalars or mismatched types → replace if different (but caller controls dict-level preserves)
        if not isinstance(a, (dict, list)) or type(a) is not type(b):
            if a != b:
                return (deepcopy(b), 1)
            return (a, 0)

        # Dict case
        if isinstance(a, dict):
            result = deepcopy(a)
            changes = 0
            # Apply only intersecting keys
            common_keys = set(a.keys()) & set(b.keys())
            for k in common_keys:
                if at_dict_level_preserve and k in at_dict_level_preserve:
                    # strictly preserve
                    continue
                merged_val, ch = _merge(a.get(k), b.get(k), None)
                if ch > 0:
                    result[k] = merged_val
                    changes += ch
            # do NOT add keys only in template; do NOT remove keys only in existing
            # Re-apply preservation explicitly (in case a == dict and template tried to alter)
            if at_dict_level_preserve:
                for k in at_dict_level_preserve:
                    if k in a:
                        result[k] = a[k]
                    else:
                        result.pop(k, None)
            return (result, changes)

        # List case (same type ensured)
        if isinstance(a, list):
            result = deepcopy(a)
            changes = 0
            limit = min(len(a), len(b))
            for i in range(limit):
                av, bv = a[i], b[i]
                # recurse for dicts/lists; replace scalar if different
                if isinstance(av, dict) and isinstance(bv, dict):
                    merged_val, ch = _merge(av, bv, None)
                    if ch > 0:
                        result[i] = merged_val
                        changes += ch
                elif isinstance(av, list) and isinstance(bv, list):
                    merged_val, ch = _merge(av, bv, None)
                    if ch > 0:
                        result[i] = merged_val
                        changes += ch
                else:
                    if av != bv:
                        result[i] = deepcopy(bv)
                        changes += 1
            # do NOT change length (no append/pop)
            return (result, changes)

        # Fallback (shouldn't reach)
        return (deepcopy(b), 0)

    # Kick off; if both are dicts, enforce dict-level preserves
    preserve_here = preserve_keys if isinstance(existing, dict) else None
    merged, changes = _merge(existing, template, preserve_here)
    return merged, changes

def backup_dashboard(env_name: str, org_name: str, uid: str, full_payload: Dict[str, Any]):
    dash = full_payload.get("dashboard") or {}
    save_json(f"backups/{env_name}/{org_name}/{uid}.json", dash)

# ---------------- per-environment run ----------------

def run_for_environment(
    env_cfg: Dict[str, Any],
    template_panel: Dict[str, Any],
    preserve_keys: Set[str],
    message: str,
    dry_run: bool,
    bar_width: int
) -> Dict[str, Any]:

    g = env_cfg["grafana"]
    env_name = env_cfg["name"]

    dashboard_title = g.get("dashboard_to_edit")
    if not dashboard_title:
        raise ValueError(f"[{env_name}] Missing grafana.dashboard_to_edit in config.")

    # panel match comes from template
    tpl_type = template_panel.get("type")
    tpl_title = template_panel.get("title")
    if not tpl_type or not tpl_title:
        raise ValueError("Template panel JSON must include 'type' and 'title'.")

    companies = g["companies_inline"] if g["companies_inline"] else load_json(g["companies_file"])
    total_tasks = len(companies)
    tasks_done = 0

    session, base_url = make_session(g["url"], g["username"], g["password"], g["verify_ssl"])

    stats = {"orgs": 0, "found": 0, "edited": 0, "skipped": 0, "errors": 0}
    results: List[Dict[str, Any]] = []

    print(f"\n[{env_name}] Dashboard='{dashboard_title}' | Panel to match: title='{tpl_title}', type='{tpl_type}' | Orgs={len(companies)}")
    progress_bar(0, total_tasks, prefix=f"[{env_name}] Progreso", width=bar_width)

    for company in companies:
        org_name = company.get("name")
        org_id = company.get("id")
        try:
            switch_organization(session, base_url, org_id)
            stats["orgs"] += 1

            folder = find_company_folder(session, base_url, org_name)
            if not folder:
                results.append({"org": org_name, "status": "no_folder"})
                stats["skipped"] += 1
                continue

            uid = find_dashboard_in_folder(session, base_url, folder.get("title"), dashboard_title)
            if not uid:
                results.append({"org": org_name, "status": "dashboard_not_found"})
                stats["skipped"] += 1
                continue

            dash_payload = get_dashboard_by_uid(session, base_url, uid)
            dashboard = dash_payload.get("dashboard") or {}
            meta = dash_payload.get("meta") or {}

            panel = find_panel_by_type_and_title(dashboard, tpl_type, tpl_title)
            if not panel:
                results.append({"org": org_name, "dashboard_uid": uid, "status": "panel_not_found"})
                stats["skipped"] += 1
                continue

            stats["found"] += 1

            # diff-only merge (no add/remove, only update intersecting diffs)
            new_panel, change_count = diff_only_merge(panel, template_panel, preserve_keys)

            if change_count == 0:
                results.append({"org": org_name, "dashboard_uid": uid, "status": "no_change"})
                stats["skipped"] += 1
            else:
                panel.clear()
                panel.update(new_panel)

            backup_dashboard(env_name, org_name, uid, dash_payload)

            if dry_run:
                results.append({"org": org_name, "dashboard_uid": uid, "status": "dry_run_success", "changes": change_count})
                continue

            if change_count == 0:
                # Nothing to write
                continue

            write_dashboard(
                session,
                base_url,
                dashboard,
                message=message or f"Batch update panel '{tpl_title}' ({tpl_type})",
                folder_id=meta.get("folderId"),
                overwrite=True,
            )
            results.append({"org": org_name, "dashboard_uid": uid, "status": "edited", "changes": change_count})
            stats["edited"] += 1

        except Exception as e:
            results.append({"org": org_name, "status":"error", "error": str(e)})
            stats["errors"] += 1
        finally:
            tasks_done += 1
            progress_bar(tasks_done, total_tasks, prefix=f"[{env_name}] Progreso", width=bar_width)

    print()
    return {"summary": {"environment": env_name, **stats}, "results": results}

# ---------------- CLI ----------------

def main():
    ap = argparse.ArgumentParser(description="Batch-edit one panel across companies using a panel template.")
    ap.add_argument("-c", "--config", required=True, help="Path to config JSON (must include grafana.dashboard_to_edit per environment).")
    ap.add_argument("--panel-json", required=True, help="Path to the panel template JSON (must include 'type' and 'title').")
    ap.add_argument("--preserve-keys", nargs="*", default=["gridPos","id"], help="Panel keys to preserve from existing. Default: gridPos id")
    ap.add_argument("--message", default="", help="Dashboard save message.")
    ap.add_argument("--dry-run", action="store_true", help="Do not write changes.")
    args = ap.parse_args()

    cfg = build_config(args)
    template_panel = load_json(args.panel_json)
    preserve_keys = set(args.preserve_keys or [])

    all_out = {"summaries": [], "environments": {}}
    stamp = time.strftime("%Y%m%d_%H%M%S")

    for env in cfg["environments"]:
        res = run_for_environment(
            env_cfg=env,
            template_panel=template_panel,
            preserve_keys=preserve_keys,
            message=args.message,
            dry_run=args.dry_run,
            bar_width=cfg["bar_width"]
        )
        all_out["summaries"].append(res["summary"])
        all_out["environments"][env["name"]] = res

    save_json(f"panel_edit_summary_{stamp}.json", all_out)
    print("Done. Summary ->", f"panel_edit_summary_{stamp}.json")
    for s in all_out["summaries"]:
        print(s)

if __name__ == "__main__":
    main()
