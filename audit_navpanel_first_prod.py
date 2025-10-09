#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, time, json, uuid
import argparse
import requests
from requests.auth import HTTPBasicAuth
from typing import Dict, Any, List, Iterator, Optional, Tuple
from urllib.parse import urlparse
from collections import defaultdict

import psycopg2
import psycopg2.extras

# ---------------------- Utilidades básicas ----------------------
def progress_bar(done: int, total: int, prefix: str = "", width: int = 46) -> None:
    if total <= 0: total = 1
    ratio = max(0.0, min(1.0, done / total))
    filled = int(width * ratio)
    bar = "█" * filled + "░" * (width - filled)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total} ({ratio*100:5.1f}%)")
    sys.stdout.flush()

def fmt_sec(s: float) -> int:
    return int(s if s >= 0 else 0)

def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------------------- Carga de configuración ----------------------
def build_config(args) -> Dict[str, Any]:

    try:
        from dotenv import load_dotenv, find_dotenv
        load_dotenv(find_dotenv(), override=False)  # no pisa vars ya definidas (útil en Jenkins)
    except Exception:
        pass

    cfg = load_json(args.config)

    # --- Grafana ---
    g = cfg.get("grafana", {})
    grafana_url = os.getenv("GRAFANA_URL", g.get("url", ""))
    grafana_user = os.getenv("GRAFANA_USERNAME", g.get("username", ""))
    grafana_pass = os.getenv("GRAFANA_PASSWORD", g.get("password", ""))
    verify_ssl   = (os.getenv("VERIFY_SSL", str(g.get("verify_ssl", True))).lower() not in {"0","false","no"})
    companies_file = os.getenv("COMPANIES_FILE", g.get("companies_file", "companies.json"))
    companies_inline = g.get("companies")  # opcional: lista [{"id":..,"name":..}]

    # dashboards y filtro de nombres desde JSON (o ENV separado por "|")
    dashboards = (os.getenv("DASHBOARD_TITLES") or "|".join(g.get("dashboards", []))).split("|") if (os.getenv("DASHBOARD_TITLES") or g.get("dashboards")) else []
    dashboards = [d for d in (d.strip() for d in dashboards) if d]
    names_filter = set()
    nf_json = g.get("names_filter", [])
    nf_env  = os.getenv("NAMES_FILTER", "")
    if nf_env.strip():
        names_filter = {x for x in (t.strip() for t in nf_env.split("|")) if x}
    elif nf_json:
        names_filter = set(nf_json)

    # --- Reglas ---
    r = cfg.get("rules", {})
    rule_require_include_vars = bool(r.get("require_include_variables", True))
    rule_forbid_url_params    = bool(r.get("forbid_url_params", True))
    panel_type = (r.get("panel_type") or "volkovlabs-links-panel").lower()
    pick_panel_strategy = (r.get("pick") or "first").lower()  # 'first' por gridPos

    # --- DB ---
    d = cfg.get("db", {})
    db_host   = os.getenv("DB_HOST", d.get("host", ""))
    db_port   = int(os.getenv("DB_PORT", str(d.get("port", 5432))))
    db_name   = os.getenv("DB_NAME", d.get("name", "postgres"))
    db_schema = os.getenv("DB_SCHEMA", d.get("schema", "public"))
    # Por seguridad, user/pass desde ENV (si vienen en JSON, se usan solo si el env está vacío)
    db_user   = os.getenv("DB_USER", d.get("user", ""))
    db_pass   = os.getenv("DB_PASSWORD", d.get("password", ""))
    env_name  = os.getenv("ENV_NAME", cfg.get("env_name", "dev"))

    # --- Progreso ---
    p = cfg.get("progress", {})
    bar_width = int(p.get("bar_width", 46))

    return {
        "grafana": {
            "url": grafana_url,
            "username": grafana_user,
            "password": grafana_pass,
            "verify_ssl": verify_ssl,
            "companies_file": companies_file,
            "companies_inline": companies_inline,
            "dashboards": dashboards,
            "names_filter": names_filter,
        },
        "rules": {
            "require_include_variables": rule_require_include_vars,
            "forbid_url_params": rule_forbid_url_params,
            "panel_type": panel_type,
            "pick": pick_panel_strategy,
        },
        "db": {
            "host": db_host, "port": db_port, "name": db_name,
            "schema": db_schema, "user": db_user, "password": db_pass
        },
        "env_name": env_name,
        "progress": {"bar_width": bar_width},
    }

# ---------------------- HTTP/Grafana helpers ----------------------
def make_session(url: str, user: str, passwd: str, verify_ssl: bool):
    s = requests.Session()
    s.headers.update({"Accept": "application/json"})
    if user:
        s.auth = HTTPBasicAuth(user, passwd)
    s.verify = verify_ssl
    # sanity for url
    if url.endswith("/"):
        url = url[:-1]
    return s, url

def switch_organization(session: requests.Session, base_url: str, org_id: int) -> None:
    r = session.post(f"{base_url}/user/using/{org_id}")
    if r.status_code != 200:
        raise RuntimeError(f"Switch org {org_id} failed: {r.status_code} {r.text}")

def search_dashboard_by_title(session: requests.Session, base_url: str, title: str) -> List[Dict[str, Any]]:
    r = session.get(f"{base_url}/search", params={"type": "dash-db", "query": title})
    r.raise_for_status()
    results = r.json() or []
    exact = [it for it in results if it.get("title") == title]
    return exact if exact else [it for it in results if str(it.get("title","")).lower() == title.lower()]

def get_dashboard(session: requests.Session, base_url: str, uid: str) -> Dict[str, Any]:
    r = session.get(f"{base_url}/dashboards/uid/{uid}")
    r.raise_for_status()
    return r.json()

def iter_all_panels(panels: List[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
    if not panels: return
    for p in panels:
        yield p
        inner = p.get("panels")
        if isinstance(inner, list) and inner:
            yield from iter_all_panels(inner)

def pick_panel(dashboard: Dict[str, Any], panel_type: str, strategy: str = "first") -> Optional[Dict[str, Any]]:
    candidates = []
    for p in iter_all_panels(dashboard.get("panels", []) or []):
        if (p.get("type") or "").lower() == panel_type:
            gp = p.get("gridPos") or {}
            candidates.append(((gp.get("y", 1<<30), gp.get("x", 1<<30)), p))
    if not candidates:
        return None
    candidates.sort(key=lambda t: t[0])
    return candidates[0][1]  # 'first' por y,x mínimos

def extract_items_from_volkov_panel(panel: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    out: List[Tuple[str, Dict[str, Any]]] = []
    opts = panel.get("options") or {}
    for grp in (opts.get("groups") or []):
        for it in (grp.get("items") or []):
            out.append(("group", it))
    for dd in (opts.get("dropdowns") or []):
        for it in (dd.get("items") or []):
            out.append(("dropdown", it))
    return out

# ---------------------- Validaciones ----------------------
def url_has_params(u: Optional[str]) -> bool:
    s = (u or "").strip()
    return bool(urlparse(s).query) if s else False

def include_vars_is_true(item: Dict[str, Any]) -> bool:
    return bool(item.get("includeVariables") is True)

def should_check_name(name: str, names_filter: set) -> bool:
    return (not names_filter) or (name in names_filter)

# ---------------------- DB helpers ----------------------
DDL_RUNS = """
CREATE TABLE IF NOT EXISTS {schema}.panel_audit_runs (
  run_id UUID PRIMARY KEY,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at   TIMESTAMPTZ,
  environment TEXT,
  org_count INTEGER,
  dashboard_count INTEGER,
  items_checked INTEGER,
  violations_count INTEGER,
  elapsed_seconds INTEGER
);
"""
DDL_VIOLS = """
CREATE TABLE IF NOT EXISTS {schema}.panel_audit_violations (
  id BIGSERIAL PRIMARY KEY,
  run_id UUID REFERENCES {schema}.panel_audit_runs(run_id) ON DELETE CASCADE,
  org TEXT,
  dashboard TEXT,
  dashboard_uid TEXT,
  folder_title TEXT,
  folder_id BIGINT,
  folder_url TEXT,
  panel_id BIGINT,
  item_source TEXT,
  item_id TEXT,
  item_name TEXT,
  url TEXT,
  include_variables BOOLEAN,
  issue TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

def db_connect(cfg_db: dict):
    return psycopg2.connect(
        host=cfg_db["host"], port=cfg_db["port"], dbname=cfg_db["name"],
        user=cfg_db["user"], password=cfg_db["password"]
    )

def db_prepare(conn, schema: str):
    with conn.cursor() as cur:
        cur.execute(DDL_RUNS.format(schema=schema))
        cur.execute(DDL_VIOLS.format(schema=schema))
    conn.commit()

def db_insert_run_start(conn, schema: str, run_id, env_name: str, orgs: int, dashboards: int):
    with conn.cursor() as cur:
        cur.execute(
            f"INSERT INTO {schema}.panel_audit_runs(run_id, environment, org_count, dashboard_count) "
            "VALUES (%s,%s,%s,%s)",
            (run_id, env_name, orgs, dashboards)
        )
    conn.commit()

def db_update_run_end(conn, schema: str, run_id, items: int, viols: int, elapsed: int):
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE {schema}.panel_audit_runs "
            "SET ended_at = now(), items_checked=%s, violations_count=%s, elapsed_seconds=%s "
            "WHERE run_id=%s",
            (items, viols, elapsed, run_id)
        )
    conn.commit()

def db_bulk_insert_violations(conn, schema: str, run_id, viols: List[Dict[str, Any]]):
    if not viols: return
    rows = [
        (run_id, v.get("org"), v.get("dashboard"), v.get("dashboard_uid"),
         v.get("folder_title"), v.get("folder_id"), v.get("folder_url"),
         v.get("panel_id"), v.get("item_source"), v.get("item_id"),
         v.get("item_name"), v.get("url"), v.get("includeVariables"), v.get("issue"))
        for v in viols
    ]
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            f"""INSERT INTO {schema}.panel_audit_violations
                (run_id, org, dashboard, dashboard_uid, folder_title, folder_id, folder_url,
                 panel_id, item_source, item_id, item_name, url, include_variables, issue)
                VALUES %s""",
            rows,
            page_size=500,
        )
    conn.commit()

# ---------------------- Main ----------------------
def main():
    ap = argparse.ArgumentParser(description="Audit first volkovlabs-links-panel using JSON config.")
    ap.add_argument("-c", "--config", required=True, help="Ruta al archivo JSON de configuración")
    args = ap.parse_args()

    cfg = build_config(args)
    g, r, d = cfg["grafana"], cfg["rules"], cfg["db"]

    # Cargar compañías
    if g["companies_inline"]:
        companies = g["companies_inline"]
    else:
        companies = load_json(g["companies_file"])
    total_orgs = len(companies)
    dashboards = g["dashboards"]
    total_tasks = total_orgs * len(dashboards)

    # HTTP session
    session, base_url = make_session(g["url"], g["username"], g["password"], g["verify_ssl"])

    # DB
    conn = db_connect(d)
    db_prepare(conn, d["schema"])
    run_id = str(uuid.uuid4())
    db_insert_run_start(conn, d["schema"], run_id, cfg["env_name"], total_orgs, len(dashboards))

    # Progreso
    start_ts = time.time()
    tasks_done = 0
    items_checked = 0
    violations: List[Dict[str, Any]] = []

    print(f"Auditor ({cfg['env_name']}): {total_orgs} orgs × {len(dashboards)} dashboards")
    progress_bar(0, total_tasks, prefix="Progreso", width=cfg["progress"]["bar_width"])

    for company in companies:
        org_id = company["id"]
        try:
            switch_organization(session, base_url, org_id)
        except Exception:
            # avanzar tareas de esta org aunque falle
            for _ in dashboards:
                tasks_done += 1
                progress_bar(tasks_done, total_tasks, prefix="Progreso", width=cfg["progress"]["bar_width"])
            continue

        for title in dashboards:
            try:
                search = search_dashboard_by_title(session, base_url, title)
                for m in search:
                    uid = m.get("uid")
                    if not uid:
                        continue
                    payload = get_dashboard(session, base_url, uid)
                    dash = payload.get("dashboard") or {}
                    meta = payload.get("meta") or {}

                    folder_title = (meta.get("folderTitle") or "").strip()
                    if folder_title.lower() == "test":
                        continue

                    panel = pick_panel(dash, r["panel_type"], r["pick"])
                    if not panel:
                        continue

                    items = extract_items_from_volkov_panel(panel)
                    for source, it in items:
                        # ⬇⬇⬇ ignorar dropdowns
                        if (source or "").lower() == "dropdown":
                            continue

                        name = it.get("name") or it.get("dropdownName") or ""
                        if not should_check_name(name, g["names_filter"]):
                            continue
                        url = (it.get("url") or "").strip()

                        issues = []
                        if r["require_include_variables"] and not include_vars_is_true(it):
                            issues.append("includeVariables_false_or_missing")
                        if r["forbid_url_params"] and url_has_params(url):
                            issues.append("url_has_params")

                        items_checked += 1
                        if issues:
                            violations.append({
                                "org": company["name"],
                                "dashboard": dash.get("title"),
                                "dashboard_uid": dash.get("uid") or meta.get("uid"),
                                "folder_title": meta.get("folderTitle"),
                                "folder_id": meta.get("folderId"),
                                "folder_url": meta.get("folderUrl"),
                                "panel_id": panel.get("id"),
                                "item_source": source,
                                "item_id": it.get("id"),
                                "item_name": name,
                                "url": url,
                                "includeVariables": it.get("includeVariables"),
                                "issue": ",".join(issues),
                            })
            except Exception:
                pass
            finally:
                tasks_done += 1
                progress_bar(tasks_done, total_tasks, prefix="Progreso", width=cfg["progress"]["bar_width"])

    # Persistencia
    db_bulk_insert_violations(conn, d["schema"], run_id, violations)
    elapsed = fmt_sec(time.time() - start_ts)
    db_update_run_end(conn, d["schema"], run_id, items_checked, len(violations), elapsed)
    conn.close()

    print(f"\nOK | items={items_checked} viols={len(violations)} dur={elapsed}s run_id={run_id}")

if __name__ == "__main__":
    # Ejemplo: python3 audit_navpanel_first_prod.py -c configs/dev.json
    main()
