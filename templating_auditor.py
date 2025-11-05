#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditor de VARIABLES (templating list) para Grafana por ambientes/compañías.

Recorre todas las compañías (orgs) y todos los dashboards en la carpeta
principal (título de carpeta = nombre de la compañía). Valida el orden y
configuración de variables según reglas:

REGLAS
------
Orden y visibilidad:
1) Las dos primeras variables deben ser, en orden: 'schema', 'groupId'.
   - Ambas deben estar ocultas (hide != 0), porque sólo los filtros son visibles.
2) Desde la 3.ª variable hasta antes de encontrar 'nodeId' o 'all_nodeId'
   son "filters" (ej.: Area, County, Battery, Formation, ...). Para cada filter:
   - visible (hide == 0)
   - multi: true
   - includeAll: true
   - current: { selected: true, text: ["All"], value: ["$__all"] }
     (se acepta también text/value como strings en vez de arrays)
3) Después de los filtros (es decir, a partir de 'nodeId' o 'all_nodeId' y
   cualquier otra variable posterior), TODAS deben estar ocultas (hide != 0).
   Además:
   - 'all_nodeId' debe tener includeAll: true y current en All (como arriba)
   - 'nodeId' NO debe tener includeAll activo
   - Para ambas, se ignora el orden relativo entre 'nodeId' y 'all_nodeId'.

UID del dashboard de destino en links de variables: (no aplica aquí)

SALIDAS
-------
- templating_audit_{env}.json y templating_audit_{env}.csv
- (Opcional) Inserción en PostgreSQL (tablas: templating_audit_runs, templating_audit_violations)

CONFIG (config.json)
--------------------
{
  "environments": [
    {
      "name": "dev",
      "grafana": {
        "url": "https://dev.example.com/api",
        "username": "user",
        "password": "pass",
        "verify_ssl": true,
        "companies_file": "companies.dev.json"
      }
    }
  ],
  "rules": {
    "ignore_folders": ["Test"]
  },
  "db": { "enabled": false, "schema": "public" },
  "progress": { "bar_width": 46 }
}

companies.dev.json
------------------
[
  {"id": 1, "name": "Akakus"},
  {"id": 2, "name": "Apache"}
]
"""

import os, sys, json, time, uuid, argparse
from typing import Any, Dict, Iterator, List, Optional, Tuple

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

def _bool_env_default(val, default_true=True):
    if isinstance(val, bool): return val
    if val is None: return default_true
    return str(val).lower() not in {"0", "false", "no"}


def _resolve_grafana_fields(env_block: dict) -> Dict[str, Any]:
    g = env_block.get("grafana", {}) if env_block else {}
    grafana_url = (g.get("url") or os.getenv("GRAFANA_URL", "")).rstrip("/")
    grafana_user = os.getenv("GRAFANA_USERNAME", g.get("username", ""))
    grafana_pass = os.getenv("GRAFANA_PASSWORD", g.get("password", ""))
    verify_ssl   = _bool_env_default(os.getenv("VERIFY_SSL", g.get("verify_ssl", True)), True)

    companies_inline = g.get("companies")
    companies_file   = os.getenv("COMPANIES_FILE", g.get("companies_file", "companies.json"))

    return {
        "url": grafana_url,
        "username": grafana_user,
        "password": grafana_pass,
        "verify_ssl": verify_ssl,
        "companies_inline": companies_inline,
        "companies_file": companies_file,
    }


def _resolve_rules(cfg_rules: dict) -> Dict[str, Any]:
    r = cfg_rules or {}
    ignore_folders = [s.lower() for s in r.get("ignore_folders", ["Test"])]
    return {"ignore_folders": ignore_folders}


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

    if "environments" not in cfg:
        env_name = cfg.get("env_name", os.getenv("ENV_NAME", "dev"))
        env_block = {"name": env_name, "grafana": cfg.get("grafana", {})}
        environments = [env_block]
    else:
        environments = cfg["environments"]

    envs_resolved = []
    for env in environments:
        name = env.get("name") or os.getenv("ENV_NAME", "dev")
        grafana = _resolve_grafana_fields(env)
        envs_resolved.append({"name": name, "grafana": grafana})

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


def search_folders(session: requests.Session, base_url: str, q: str) -> List[Dict[str, Any]]:
    r = session.get(f"{base_url}/search", params={"type": "dash-folder", "query": q, "limit": 5000})
    r.raise_for_status()
    return r.json() or []


def search_dashboards_any(session: requests.Session, base_url: str) -> List[Dict[str, Any]]:
    r = session.get(f"{base_url}/search", params={"type": "dash-db", "limit": 5000})
    r.raise_for_status()
    return r.json() or []


def get_dashboard(session: requests.Session, base_url: str, uid: str) -> Dict[str, Any]:
    r = session.get(f"{base_url}/dashboards/uid/{uid}")
    r.raise_for_status()
    return r.json()

# ---------- helpers ----------

def find_company_folder(session, base_url: str, company_name: str) -> Optional[Dict[str, Any]]:
    for it in search_folders(session, base_url, company_name):
        if norm(it.get("title")) == norm(company_name):
            return it
    return None

# ---------- validaciones templating ----------

def as_list(value):
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def is_hidden(var: Dict[str, Any]) -> bool:
    # Grafana: hide 0=visible, 1=label only, 2=hidden
    return (var.get("hide", 0) or 0) != 0


def validate_variables(vars_list: List[Dict[str, Any]]) -> List[str]:
    issues: List[str] = []
    if vars_list is None:
        issues.append("templating_missing")
        return issues

    # Regla 1: primeras dos variables
    if len(vars_list) < 2:
        issues.append("vars_too_few_for_schema_groupId")
        return issues

    v0 = (vars_list[0].get("name") or "").strip()
    v1 = (vars_list[1].get("name") or "").strip()
    if v0 != "schema":
        issues.append("first_var_must_be_schema")
    if v1 != "groupId":
        issues.append("second_var_must_be_groupId")

    # Ambas ocultas (sólo filtros visibles)
    if not is_hidden(vars_list[0]):
        issues.append("schema_must_be_hidden")
    if not is_hidden(vars_list[1]):
        issues.append("groupId_must_be_hidden")

    # Encontrar índice de corte (primer nodeId o all_nodeId)
    cut_idx = len(vars_list)
    for i, v in enumerate(vars_list):
        n = (v.get("name") or "").strip()
        if n in ("nodeId", "all_nodeId"):
            cut_idx = i
            break

    # Filtros: desde idx=2 hasta cut_idx-1
    for i in range(2, cut_idx):
        v = vars_list[i]
        n = (v.get("name") or "").strip()
        # visibles
        if is_hidden(v):
            issues.append(f"filter_{n}_must_be_visible")
        # multi/includeAll
        if v.get("multi") is not True:
            issues.append(f"filter_{n}_multi_true")
        if v.get("includeAll") is not True:
            issues.append(f"filter_{n}_includeAll_true")
        # current All
        cur = v.get("current", {}) or {}
        txt = as_list(cur.get("text"))
        val = as_list(cur.get("value"))
        sel = bool(cur.get("selected", False))
        if not (sel and ("All" in txt) and ("$__all" in val)):
            issues.append(f"filter_{n}_current_must_be_All")

    # Resto (desde cut_idx hasta el final) ocultos + reglas de nodeId/all_nodeId
    for i in range(cut_idx, len(vars_list)):
        v = vars_list[i]
        n = (v.get("name") or "").strip()
        if not is_hidden(v):
            issues.append(f"nonfilter_{n}_must_be_hidden")
        if n == "all_nodeId":
            if v.get("includeAll") is not True:
                issues.append("all_nodeId_includeAll_true")
            cur = v.get("current", {}) or {}
            txt = as_list(cur.get("text"))
            val = as_list(cur.get("value"))
            sel = bool(cur.get("selected", False))
            if not (sel and ("All" in txt) and ("$__all" in val)):
                issues.append("all_nodeId_current_must_be_All")
        if n == "nodeId":
            # NO debe tener includeAll activo
            if v.get("includeAll") is True:
                issues.append("nodeId_includeAll_must_be_false")

    return issues

# ---------- núcleo ----------

def run_for_environment(env_cfg: Dict[str, Any], rules: Dict[str, Any], db_cfg: Dict[str, Any], bar_width: int) -> Dict[str, Any]:
    g = env_cfg["grafana"]
    env_name = env_cfg["name"]

    companies = g["companies_inline"] if g["companies_inline"] else load_json(g["companies_file"])
    session, base_url = make_session(g["url"], g["username"], g["password"], g["verify_ssl"])

    # BD
    if db_cfg["enabled"]:
        conn = psycopg2.connect(host=db_cfg["host"], port=db_cfg["port"], dbname=db_cfg["name"], user=db_cfg["user"], password=db_cfg["password"])
        with conn.cursor() as cur:
            cur.execute(f"""
CREATE TABLE IF NOT EXISTS {db_cfg['schema']}.templating_audit_runs (
  run_id UUID PRIMARY KEY,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at   TIMESTAMPTZ,
  environment TEXT,
  org_count INTEGER,
  dashboard_count INTEGER,
  violations_count INTEGER,
  elapsed_seconds INTEGER
);
""")
            cur.execute(f"""
CREATE TABLE IF NOT EXISTS {db_cfg['schema']}.templating_audit_violations (
  id BIGSERIAL PRIMARY KEY,
  run_id UUID REFERENCES {db_cfg['schema']}.templating_audit_runs(run_id) ON DELETE CASCADE,
  org TEXT, dashboard TEXT, dashboard_uid TEXT,
  folder_title TEXT, folder_id BIGINT, folder_url TEXT,
  issue TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
""")
        conn.commit()
        run_id = str(uuid.uuid4())
        with conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {db_cfg['schema']}.templating_audit_runs(run_id, environment, org_count, dashboard_count) VALUES (%s,%s,%s,%s)",
                (run_id, env_name, len(companies), 0),
            )
        conn.commit()
    else:
        conn = None
        run_id = str(uuid.uuid4())

    total_tasks = max(1, len(companies))
    tasks_done = 0
    dash_count = 0
    violations: List[Dict[str, Any]] = []

    print(f"\nAuditor TEMPLATING (env={env_name}): {len(companies)} orgs")
    progress_bar(0, total_tasks, f"Progreso {env_name}", bar_width)

    # buscar dashboards por carpeta
    def search_dashboards_any(sess, base):
        r = sess.get(f"{base}/search", params={"type": "dash-db", "limit": 5000})
        r.raise_for_status()
        return r.json() or []

    def get_dashboard(sess, base, uid):
        r = sess.get(f"{base}/dashboards/uid/{uid}")
        r.raise_for_status()
        return r.json()

    ignore_folders = (rules.get("ignore_folders") or [])

    for company in companies:
        try:
            switch_organization(session, base_url, company["id"])
        except Exception:
            tasks_done += 1
            progress_bar(tasks_done, total_tasks, f"Progreso {env_name}", bar_width)
            continue

        # carpeta principal
        folder = None
        for it in search_folders(session, base_url, company["name"]):
            if norm(it.get("title")) == norm(company["name"]):
                folder = it
                break
        if not folder:
            tasks_done += 1
            progress_bar(tasks_done, total_tasks, f"Progreso {env_name}", bar_width)
            continue

        all_dashes = search_dashboards_any(session, base_url)
        in_folder = [it for it in all_dashes if norm(it.get("folderTitle")) == norm(folder.get("title"))]

        dash_count += len(in_folder)
        if db_cfg["enabled"]:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE {db_cfg['schema']}.templating_audit_runs SET dashboard_count=%s WHERE run_id=%s",
                    (dash_count, run_id),
                )
            conn.commit()

        for meta in in_folder:
            uid = meta.get("uid")
            if not uid:
                continue
            try:
                payload = get_dashboard(session, base_url, uid)
            except Exception:
                continue

            dash = payload.get("dashboard") or {}
            dmeta = payload.get("meta") or {}
            folder_title = (dmeta.get("folderTitle") or "").strip().lower()
            if folder_title in ignore_folders:
                continue

            templ = (dash.get("templating") or {}).get("list")
            issues = validate_variables(templ or [])
            for iss in issues:
                violations.append({
                    "org": company.get("name"),
                    "dashboard": dash.get("title"),
                    "dashboard_uid": dash.get("uid") or dmeta.get("uid"),
                    "folder_title": dmeta.get("folderTitle"),
                    "folder_id": dmeta.get("folderId"),
                    "folder_url": dmeta.get("folderUrl"),
                    "issue": iss,
                })

        tasks_done += 1
        progress_bar(tasks_done, total_tasks, f"Progreso {env_name}", bar_width)

    elapsed = fmt_sec(time.time() - start)

    result = {
        "summary": {
            "environment": env_name,
            "organizations": len(companies),
            "dashboards": dash_count,
            "violations": len(violations),
            "elapsed_seconds": elapsed,
        },
        "violations": violations,
    }

    save_json(f"templating_audit_{env_name}.json", result)

    try:
        import csv
        with open(f"templating_audit_{env_name}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["org", "dashboard", "dashboard_uid", "folder_title", "folder_id", "folder_url", "issue"])
            for v in violations:
                w.writerow([v.get("org"), v.get("dashboard"), v.get("dashboard_uid"), v.get("folder_title"), v.get("folder_id"), v.get("folder_url"), v.get("issue")])
    except Exception as e:
        print(f"\n⚠ No se pudo escribir templating_audit_{env_name}.csv: {e}")

    if db_cfg["enabled"]:
        with conn.cursor() as cur:
            if violations:
                psycopg2.extras.execute_values(
                    cur,
                    f"""INSERT INTO {db_cfg['schema']}.templating_audit_violations
                    (run_id, org, dashboard, dashboard_uid, folder_title, folder_id, folder_url, issue)
                    VALUES %s""",
                    [
                        (
                            run_id,
                            v.get("org"), v.get("dashboard"), v.get("dashboard_uid"),
                            v.get("folder_title"), v.get("folder_id"), v.get("folder_url"),
                            v.get("issue"),
                        )
                        for v in violations
                    ],
                    page_size=500,
                )
            cur.execute(
                f"UPDATE {db_cfg['schema']}.templating_audit_runs SET ended_at=now(), violations_count=%s, elapsed_seconds=%s WHERE run_id=%s",
                (len(violations), elapsed, run_id),
            )
        conn.commit()
        conn.close()

    print(f"\nOK {env_name} TEMPLATING | dashboards={dash_count} viols={len(violations)}")
    return result

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="Audita VARIABLES (templating) de Grafana por ambientes/compañías.")
    ap.add_argument("-c", "--config", required=True, help="Ruta al JSON de configuración")
    args = ap.parse_args()

    cfg = build_config(args)
    envs = cfg["environments"]
    rules = cfg["rules"]
    db_cfg = cfg["db"]
    barw = cfg["progress"]["bar_width"]

    all_results = {"summaries": [], "environments": {}}

    total_tasks = max(1, len(envs))
    done = 0

    for env in envs:
        res = run_for_environment(env, rules, db_cfg, barw)
        all_results["summaries"].append(res["summary"])
        all_results["environments"][env["name"]] = res
        done += 1
        progress_bar(done, total_tasks, "Ambientes", barw)

    save_json("templating_audit_all.json", all_results)
    print("\nResumen combinado escrito en templating_audit_all.json")


if __name__ == "__main__":
    start = time.time()
    main()
