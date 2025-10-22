#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, time, json, uuid, argparse
from typing import Dict, Any, List, Iterator, Optional, Tuple, Set
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth

# BD opcional
try:
    import psycopg2, psycopg2.extras
except Exception:
    psycopg2 = None

# ---------- util ----------
def progress_bar(done: int, total: int, prefix: str = "", width: int = 46) -> None:
    if total <= 0: total = 1
    ratio = max(0.0, min(1.0, done / total))
    filled = int(width * ratio)
    bar = "█" * filled + "░" * (width - filled)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total} ({ratio*100:5.1f}%)")
    sys.stdout.flush()

def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

def fmt_sec(s: float) -> int:
    return int(s if s >= 0 else 0)

def norm(s: Optional[str]) -> str:
    return (s or "").strip().casefold()

# ---------- config ----------
DEFAULT_LINK_TARGETS = {
    "Executive":    "Executive",
    "Benchmark":    "Benchmark",
    "Status":       "24 Hour Status Summary",   # Nota: tu dev.json usa "Daily ESP Status"
    "Shutdowns":    "Shutdowns and Faults",
    "Production":   "Production History",
    "Single-Axis":  "Real Time: Trends",
    "Multi-axis":   "Real Time: Multi-axis",
    "Quick View":   "Real Time: Quick View",
    "Health Check": "Health Check",
    "Setpoints":    "Setpoints",
    "Reports":      "Reports",
}

def _bool_env_default(val, default_true=True):
    if isinstance(val, bool): return val
    if val is None: return default_true
    return str(val).lower() not in {"0", "false", "no"}

def _resolve_grafana_fields(env_block: dict) -> Dict[str, Any]:
    """
    Resuelve credenciales/campos por ambiente. Si existen variables de entorno específicas
    como GRAFANA_URL, GRAFANA_USERNAME, etc. se respetan; si no, toma del bloque.
    """
    g = env_block.get("grafana", {}) if env_block else {}
    grafana_url  = os.getenv("GRAFANA_URL", g.get("url", "")).rstrip("/")
    grafana_user = os.getenv("GRAFANA_USERNAME", g.get("username", ""))
    grafana_pass = os.getenv("GRAFANA_PASSWORD", g.get("password", ""))
    verify_ssl   = _bool_env_default(os.getenv("VERIFY_SSL", g.get("verify_ssl", True)), True)

    companies_inline = g.get("companies")
    companies_file   = os.getenv("COMPANIES_FILE", g.get("companies_file", "companies.json"))

    dashboards = (os.getenv("DASHBOARD_TITLES") or "|".join(g.get("dashboards", []))).split("|") if (os.getenv("DASHBOARD_TITLES") or g.get("dashboards")) else []
    dashboards = [d.strip() for d in dashboards if d.strip()]

    nf_env = os.getenv("NAMES_FILTER", "")
    names_filter = set([s.strip() for s in nf_env.split("|") if s.strip()]) or set(g.get("names_filter", []))

    return {
        "url": grafana_url,
        "username": grafana_user,
        "password": grafana_pass,
        "verify_ssl": verify_ssl,
        "companies_inline": companies_inline,
        "companies_file": companies_file,
        "dashboards": dashboards,
        "names_filter": names_filter
    }

def _resolve_rules(cfg_rules: dict) -> Dict[str, Any]:
    r = cfg_rules or {}
    mode = (r.get("mode") or "PANEL_LINKS").upper()  # LINKS | PANEL_LINKS
    panel_type = (r.get("panel_type") or "volkovlabs-links-panel").lower()
    link_targets = r.get("link_targets") or DEFAULT_LINK_TARGETS
    ignore_folders = [s.lower() for s in r.get("ignore_folders", ["Test"])]
    ignore_dropdowns = bool(r.get("ignore_dropdowns", True))

    # mismas reglas en ambos modos
    require_include_vars = True if (r.get("require_include_vars") is None) else bool(r.get("require_include_vars"))
    forbid_params = True if (r.get("forbid_url_params_any") is None) else bool(r.get("forbid_url_params_any"))

    return {
        "mode": mode,
        "panel_type": panel_type,
        "link_targets": link_targets,
        "ignore_folders": ignore_folders,
        "ignore_dropdowns": ignore_dropdowns,
        "require_include_vars": require_include_vars,
        "forbid_params": forbid_params
    }

def _resolve_db(cfg_db: dict) -> Dict[str, Any]:
    d = cfg_db or {}
    return {
        "enabled": bool(d.get("enabled", False)),
        "host": os.getenv("DB_HOST", d.get("host", "")),
        "port": int(os.getenv("DB_PORT", str(d.get("port", 5432)))),
        "name": os.getenv("DB_NAME", d.get("name", "postgres")),
        "schema": os.getenv("DB_SCHEMA", d.get("schema", "public")),
        "user": os.getenv("DB_USER", d.get("user", "")),
        "password": os.getenv("DB_PASSWORD", d.get("password", "")),
    }

def build_config(args) -> Dict[str, Any]:
    try:
        from dotenv import load_dotenv, find_dotenv
        load_dotenv(find_dotenv(), override=False)
    except Exception:
        pass

    cfg = load_json(args.config)

    # Retrocompatibilidad (formato viejo con un solo bloque):
    if "environments" not in cfg:
        env_name = cfg.get("env_name", os.getenv("ENV_NAME", "dev"))
        env_block = {
            "name": env_name,
            "grafana": cfg.get("grafana", {}),
        }
        environments = [env_block]
    else:
        environments = cfg["environments"]

    # Resolver y normalizar cada ambiente
    envs_resolved = []
    for env in environments:
        name = env.get("name") or os.getenv("ENV_NAME", "dev")
        grafana = _resolve_grafana_fields(env)
        envs_resolved.append({
            "name": name,
            "grafana": grafana
        })

    rules = _resolve_rules(cfg.get("rules", {}))
    db = _resolve_db(cfg.get("db", {}))
    progress = {"bar_width": int(cfg.get("progress", {}).get("bar_width", 46))}

    return {"environments": envs_resolved, "rules": rules, "db": db, "progress": progress}

# ---------- grafana http ----------
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

def search_dashboard_by_title(session: requests.Session, base_url: str, title: str) -> List[Dict[str, Any]]:
    r = session.get(f"{base_url}/search", params={"type": "dash-db", "query": title})
    r.raise_for_status()
    res = r.json() or []
    exact = [it for it in res if it.get("title") == title]
    return exact if exact else [it for it in res if str(it.get("title","")).lower() == title.lower()]

def get_dashboard(session: requests.Session, base_url: str, uid: str) -> Dict[str, Any]:
    r = session.get(f"{base_url}/dashboards/uid/{uid}")
    r.raise_for_status()
    return r.json()

def search_folders(session: requests.Session, base_url: str, q: str) -> List[Dict[str, Any]]:
    r = session.get(f"{base_url}/search", params={"type": "dash-folder", "query": q, "limit": 5000})
    r.raise_for_status()
    return r.json() or []

# ---------- helpers modelo ----------
def iter_all_panels(panels: List[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
    if not panels: return
    for p in panels:
        yield p
        inner = p.get("panels")
        if isinstance(inner, list) and inner:
            yield from iter_all_panels(inner)

def collect_links_from_dashboard(dash_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    dashboard = dash_payload.get("dashboard") or {}
    meta = dash_payload.get("meta") or {}
    dash_title = dashboard.get("title") or ""
    dash_uid = dashboard.get("uid") or meta.get("uid")
    folder_title = meta.get("folderTitle")
    folder_id = meta.get("folderId")
    folder_url = meta.get("folderUrl")
    # Links a nivel dashboard
    for l in dashboard.get("links", []) or []:
        out.append({
            "scope": "dashboard", "dashboard_title": dash_title, "dashboard_uid": dash_uid,
            "folder_title": folder_title, "folder_id": folder_id, "folder_url": folder_url,
            "panel_id": None, "panel_title": None, "link": l
        })
    # Links a nivel panel
    for p in iter_all_panels(dashboard.get("panels", []) or []):
        for l in p.get("links", []) or []:
            out.append({
                "scope": "panel", "dashboard_title": dash_title, "dashboard_uid": dash_uid,
                "folder_title": folder_title, "folder_id": folder_id, "folder_url": folder_url,
                "panel_id": p.get("id"), "panel_title": p.get("title"), "link": l
            })
    return out

def pick_first_volkov_panel(dashboard: Dict[str, Any], panel_type: str) -> Optional[Dict[str, Any]]:
    cands = []
    for p in iter_all_panels(dashboard.get("panels", []) or []):
        if (p.get("type") or "").lower() == panel_type:
            gp = p.get("gridPos") or {}
            cands.append(((gp.get("y", 1<<30), gp.get("x", 1<<30)), p))
    if not cands: return None
    cands.sort(key=lambda t: t[0])
    return cands[0][1]

def extract_items_from_volkov(panel: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    out: List[Tuple[str, Dict[str, Any]]] = []
    opts = panel.get("options") or {}
    for grp in (opts.get("groups") or []):
        for it in (grp.get("items") or []):
            out.append(("group", it))
    for dd in (opts.get("dropdowns") or []):
        for it in (dd.get("items") or []):
            out.append(("dropdown", it))
    return out

# ---------- validaciones ----------
def url_has_params(u: Optional[str]) -> bool:
    s = (u or "").strip()
    return bool(urlparse(s).query) if s else False

def include_flag_ok(obj: Dict[str, Any], mode: str) -> bool:
    # LINKS -> includeVars | PANEL_LINKS -> includeVariables
    return bool(obj.get("includeVars") is True) if mode == "LINKS" else bool(obj.get("includeVariables") is True)

def extract_uid_from_grafana_url(u: str) -> Optional[str]:
    if not u: return None
    parsed = urlparse(u.strip())
    parts = [p for p in (parsed.path or u).split('/') if p]
    for i, seg in enumerate(parts):
        if seg in ("d", "d-solo") and i + 1 < len(parts):
            return parts[i + 1]
    return None

def find_company_folder(session, base_url: str, company_name: str) -> Optional[Dict[str, Any]]:
    for it in search_folders(session, base_url, company_name):
        if norm(it.get("title")) == norm(company_name):
            return it
    return None

def resolve_uid_in_company_folder(session, base_url: str, company_folder_title: str, expected_title: str) -> Optional[str]:
    r = session.get(f"{base_url}/search", params={"type": "dash-db", "query": expected_title, "limit": 5000})
    r.raise_for_status()
    for it in (r.json() or []):
        if norm(it.get("title")) == norm(expected_title) and norm(it.get("folderTitle")) == norm(company_folder_title):
            return it.get("uid")
    return None

def build_expected_uid_map_for_company(session, base_url: str, company_name: str, expected_titles: Set[str]) -> Tuple[Optional[str], Dict[str, Optional[str]]]:
    folder = find_company_folder(session, base_url, company_name)
    if not folder:
        return None, {t: None for t in expected_titles}
    folder_title = folder.get("title")
    mapping: Dict[str, Optional[str]] = {}
    for t in expected_titles:
        mapping[t] = resolve_uid_in_company_folder(session, base_url, folder_title, t)
    return folder_title, mapping

# ---------- BD ----------
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
);"""
DDL_VIOLS = """
CREATE TABLE IF NOT EXISTS {schema}.panel_audit_violations (
  id BIGSERIAL PRIMARY KEY,
  run_id UUID REFERENCES {schema}.panel_audit_runs(run_id) ON DELETE CASCADE,
  org TEXT, dashboard TEXT, dashboard_uid TEXT,
  folder_title TEXT, folder_id BIGINT, folder_url TEXT,
  panel_id BIGINT, item_source TEXT, item_id TEXT, item_name TEXT,
  url TEXT, include_variables BOOLEAN, issue TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);"""

def db_connect(cfg_db: dict):
    if not psycopg2:
        raise RuntimeError("psycopg2 no está instalado y db.enabled=true")
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
            f"INSERT INTO {schema}.panel_audit_runs(run_id, environment, org_count, dashboard_count) VALUES (%s,%s,%s,%s)",
            (run_id, env_name, orgs, dashboards)
        )
    conn.commit()

def db_update_run_end(conn, schema: str, run_id, items: int, viols: int, elapsed: int):
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE {schema}.panel_audit_runs SET ended_at=now(), items_checked=%s, violations_count=%s, elapsed_seconds=%s WHERE run_id=%s",
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
            rows, page_size=500
        )
    conn.commit()

# ---------- core auditor ----------
def run_for_environment(env_cfg: Dict[str, Any], rules: Dict[str, Any], db_cfg: Dict[str, Any], bar_width: int) -> Dict[str, Any]:
    g = env_cfg["grafana"]
    env_name = env_cfg["name"]

    # Cargar compañías
    companies = g["companies_inline"] if g["companies_inline"] else load_json(g["companies_file"])
    dashboards = g["dashboards"]
    expected_titles: Set[str] = set((rules["link_targets"] or {}).values())
    titles_to_visit = dashboards or list(expected_titles)
    total_tasks = len(companies) * max(1, len(titles_to_visit))

    # Session
    session, base_url = make_session(g["url"], g["username"], g["password"], g["verify_ssl"])

    # BD
    if db_cfg["enabled"]:
        conn = db_connect(db_cfg); db_prepare(conn, db_cfg["schema"])
        run_id = str(uuid.uuid4())
        db_insert_run_start(conn, db_cfg["schema"], run_id, env_name, len(companies), len(titles_to_visit))
    else:
        conn = None
        run_id = str(uuid.uuid4())  # para etiquetar outputs locales

    # Loop
    start = time.time()
    items_checked = 0
    violations: List[Dict[str, Any]] = []
    tasks_done = 0

    print(f"\nAuditor {rules['mode']} ({env_name}): {len(companies)} orgs × {max(1,len(titles_to_visit))} dashboards")
    progress_bar(0, total_tasks, f"Progreso {env_name}", bar_width)

    for company in companies:
        # cambiar de organización
        try:
            switch_organization(session, base_url, company["id"])
        except Exception:
            tasks_done += max(1, len(titles_to_visit))
            progress_bar(tasks_done, total_tasks, f"Progreso {env_name}", bar_width)
            continue

        # mapa "título esperado -> UID" dentro de la carpeta de la compañía
        company_folder_title, expected_uid_map = build_expected_uid_map_for_company(
            session, base_url, company["name"], expected_titles
        )

        for title in titles_to_visit:
            try:
                for m in search_dashboard_by_title(session, base_url, title):
                    uid = m.get("uid")
                    if not uid:
                        continue
                    payload = get_dashboard(session, base_url, uid)
                    dash = payload.get("dashboard") or {}
                    meta = payload.get("meta") or {}
                    folder_title = (meta.get("folderTitle") or "").strip().lower()
                    if folder_title in rules["ignore_folders"]:
                        continue

                    if rules["mode"] == "PANEL_LINKS":
                        panel = pick_first_volkov_panel(dash, rules["panel_type"])
                        if not panel:
                            continue
                        for source, it in extract_items_from_volkov(panel):
                            if rules["ignore_dropdowns"] and (source or "").lower() == "dropdown":
                                continue
                            name = it.get("name") or it.get("dropdownName") or ""
                            if g["names_filter"] and name not in g["names_filter"]:
                                continue
                            url = (it.get("url") or it.get("dashboardUrl") or "").strip()

                            issues = []
                            if rules["forbid_params"] and url_has_params(url):
                                issues.append("url_has_params")
                            if rules["require_include_vars"] and not include_flag_ok(it, "PANEL_LINKS"):
                                issues.append("includeVariables_false_or_missing")

                            expected_title = rules["link_targets"].get(name)
                            if expected_title:
                                if not company_folder_title:
                                    issues.append("company_folder_not_found")
                                else:
                                    uid_in_url = extract_uid_from_grafana_url(url)
                                    expected_uid = expected_uid_map.get(expected_title)
                                    if not uid_in_url:
                                        issues.append("url_missing_uid")
                                    elif not expected_uid:
                                        issues.append("target_dashboard_not_found")
                                    elif uid_in_url != expected_uid:
                                        issues.append("target_uid_mismatch")

                            items_checked += 1
                            if issues:
                                violations.append({
                                    "org": company["name"], "dashboard": dash.get("title"),
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
                    else:  # LINKS
                        for entry in collect_links_from_dashboard(payload):
                            link = entry["link"] or {}
                            name = link.get("title") or ""
                            if g["names_filter"] and name not in g["names_filter"]:
                                continue
                            url = (link.get("url") or "").strip()
                            issues = []
                            if rules["forbid_params"] and url_has_params(url):
                                issues.append("url_has_params")
                            if rules["require_include_vars"] and not include_flag_ok(link, "LINKS"):
                                issues.append("includeVars_false_or_missing")

                            expected_title = rules["link_targets"].get(name)
                            if expected_title:
                                if not company_folder_title:
                                    issues.append("company_folder_not_found")
                                else:
                                    uid_in_url = extract_uid_from_grafana_url(url)
                                    expected_uid = expected_uid_map.get(expected_title)
                                    if not uid_in_url:
                                        issues.append("url_missing_uid")
                                    elif not expected_uid:
                                        issues.append("target_dashboard_not_found")
                                    elif uid_in_url != expected_uid:
                                        issues.append("target_uid_mismatch")

                            items_checked += 1
                            if issues:
                                violations.append({
                                    "org": company["name"],
                                    "dashboard": entry["dashboard_title"],
                                    "dashboard_uid": entry["dashboard_uid"],
                                    "folder_title": entry["folder_title"],
                                    "folder_id": entry["folder_id"],
                                    "folder_url": entry["folder_url"],
                                    "panel_id": entry["panel_id"],
                                    "item_source": entry["scope"],      # dashboard|panel
                                    "item_id": link.get("title"),
                                    "item_name": name,
                                    "url": url,
                                    "includeVariables": link.get("includeVars"),
                                    "issue": ",".join(issues),
                                })
            finally:
                tasks_done += 1
                progress_bar(tasks_done, total_tasks, f"Progreso {env_name}", bar_width)

    elapsed = fmt_sec(time.time() - start)
    result = {
        "summary": {
            "environment": env_name,
            "mode": rules["mode"], "organizations": len(companies),
            "dashboards": len(titles_to_visit),
            "items_checked": items_checked,
            "violations": len(violations),
            "elapsed_seconds": elapsed
        },
        "violations": violations
    }

    # Outputs por ambiente
    save_json(f"links_audit_{env_name}.json", result)
    try:
        import csv
        with open(f"links_audit_{env_name}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["org","dashboard","dashboard_uid","folder_title","folder_id","folder_url",
                        "item_source","panel_id","item_id","item_name","url","includeVariables","issue"])
            for v in violations:
                w.writerow([v.get("org"), v.get("dashboard"), v.get("dashboard_uid"),
                            v.get("folder_title"), v.get("folder_id"), v.get("folder_url"),
                            v.get("item_source"), v.get("panel_id"), v.get("item_id"),
                            v.get("item_name"), v.get("url"), v.get("includeVariables"),
                            v.get("issue")])
    except Exception as e:
        print(f"\n⚠ No se pudo escribir links_audit_{env_name}.csv: {e}")

    # Persistencia BD
    if db_cfg["enabled"]:
        db_bulk_insert_violations(conn, db_cfg["schema"], run_id, violations)
        db_update_run_end(conn, db_cfg["schema"], run_id, items_checked, len(violations), elapsed)
        conn.close()

    print(f"\nOK {env_name} {rules['mode']} | items={items_checked} viols={len(violations)}")
    return result

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Audita LINKS o PANEL_LINKS en múltiples ambientes.")
    ap.add_argument("-c", "--config", required=True, help="Ruta al JSON de configuración")
    args = ap.parse_args()

    cfg = build_config(args)
    envs = cfg["environments"]
    rules = cfg["rules"]
    db_cfg = cfg["db"]
    barw = cfg["progress"]["bar_width"]

    all_results = {"summaries": [], "environments": {}}

    # Progreso total (todos los ambientes)
    # Estimación: sum(companies * max(1, dashboards))
    total_tasks = 0
    for env in envs:
        g = env["grafana"]
        companies = g["companies_inline"] if g["companies_inline"] else load_json(g["companies_file"])
        titles = g["dashboards"] or list((rules["link_targets"] or {}).values())
        total_tasks += len(companies) * max(1, len(titles))

    # Ejecutar ambiente por ambiente (cada uno con su barra separada para claridad)
    for env in envs:
        res = run_for_environment(env, rules, db_cfg, barw)
        all_results["summaries"].append(res["summary"])
        all_results["environments"][env["name"]] = res

    save_json("links_audit_all.json", all_results)
    print("\nResumen combinado escrito en links_audit_all.json")

if __name__ == "__main__":
    main()
