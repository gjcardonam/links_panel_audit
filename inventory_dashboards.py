#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, time, uuid
import argparse
from typing import Dict, Any, List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth

import psycopg2
import psycopg2.extras

# ---------------------- Utils ----------------------
def progress_bar(done: int, total: int, prefix: str = "", width: int = 46) -> None:
    total = total or 1
    ratio = max(0.0, min(1.0, done / total))
    filled = int(width * ratio)
    bar = "█" * filled + "░" * (width - filled)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total} ({ratio*100:5.1f}%)")
    sys.stdout.flush()

def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def fmt_bool(val, default: bool) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() not in {"0", "false", "no"}

# ---------------------- Config ----------------------
def build_config(args) -> Dict[str, Any]:
    # .env opcional (local/Jenkins)
    try:
        from dotenv import load_dotenv, find_dotenv
        load_dotenv(find_dotenv(), override=False)
    except Exception:
        pass

    cfg = load_json(args.config)

    # Espacio (nombre visible y URL base sin /api)
    space = cfg.get("space", {})
    space_name = os.getenv("SPACE_NAME", space.get("name", ""))
    space_url  = os.getenv("SPACE_URL",  space.get("url",  ""))  # ej: https://dev.enerview.site

    # Grafana API
    g = cfg.get("grafana", {})
    grafana_url = os.getenv("GRAFANA_URL", g.get("url", ""))     # ej: https://dev.enerview.site/api
    grafana_user = os.getenv("GRAFANA_USERNAME", g.get("username", ""))
    grafana_pass = os.getenv("GRAFANA_PASSWORD", g.get("password", ""))
    verify_ssl   = fmt_bool(os.getenv("VERIFY_SSL", g.get("verify_ssl", True)), True)

    companies_file   = os.getenv("COMPANIES_FILE", g.get("companies_file", "companies.json"))
    companies_inline = g.get("companies")  # lista [{"id":..,"name":..}] opcional

    # DB
    d = cfg.get("db", {})
    db_host   = os.getenv("DB_HOST", d.get("host", ""))
    db_port   = int(os.getenv("DB_PORT", str(d.get("port", 5432))))
    db_name   = os.getenv("DB_NAME", d.get("name", "postgres"))
    db_schema = os.getenv("DB_SCHEMA", d.get("schema", "public"))
    db_user   = os.getenv("DB_USER", d.get("user", ""))
    db_pass   = os.getenv("DB_PASSWORD", d.get("password", ""))

    # Progreso
    p = cfg.get("progress", {})
    bar_width = int(p.get("bar_width", 46))

    # Validaciones mínimas
    if not space_name or not space_url:
        raise SystemExit("Config inválida: 'space.name' y 'space.url' son requeridos.")
    if not grafana_url:
        raise SystemExit("Config inválida: 'grafana.url' (termina en /api) es requerido.")
    if not (grafana_user and grafana_pass):
        raise SystemExit("Faltan credenciales Grafana (GRAFANA_USERNAME/GRAFANA_PASSWORD).")
    if not (db_host and db_user and db_pass):
        raise SystemExit("Faltan credenciales DB (DB_HOST/DB_USER/DB_PASSWORD).")

    return {
        "space": {"name": space_name, "url": space_url.rstrip("/")},
        "grafana": {
            "url": grafana_url.rstrip("/"),
            "username": grafana_user,
            "password": grafana_pass,
            "verify_ssl": verify_ssl,
            "companies_file": companies_file,
            "companies_inline": companies_inline,
        },
        "db": {
            "host": db_host, "port": db_port, "name": db_name,
            "schema": db_schema, "user": db_user, "password": db_pass
        },
        "progress": {"bar_width": bar_width},
    }

# ---------------------- HTTP/Grafana ----------------------
def make_session(base_api: str, user: str, pwd: str, verify_ssl: bool):
    s = requests.Session()
    s.auth = HTTPBasicAuth(user, pwd)
    s.verify = verify_ssl
    s.headers.update({"Accept": "application/json"})
    return s, base_api

def switch_organization(session: requests.Session, base_api: str, org_id: int) -> None:
    r = session.post(f"{base_api}/user/using/{org_id}")
    if r.status_code != 200:
        raise RuntimeError(f"Switch org {org_id} failed: {r.status_code} {r.text}")

def list_dashboards(session: requests.Session, base_api: str) -> List[Dict[str, Any]]:
    """
    Usa /search para listar todos los dashboards de la org actual.
    Devolverá items con: id, uid, title, url, folderId, folderTitle, folderUid...
    """
    r = session.get(f"{base_api}/search", params={"type": "dash-db", "query": "", "limit": 5000})
    r.raise_for_status()
    return r.json() or []

# ---------------------- DB ----------------------
DDL = """
CREATE TABLE IF NOT EXISTS {schema}.grafana_dashboards_inventory (
  id BIGSERIAL PRIMARY KEY,
  run_id UUID NOT NULL,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  space_name TEXT NOT NULL,
  space_url  TEXT NOT NULL,
  org_id     BIGINT NOT NULL,
  org_name   TEXT   NOT NULL,
  folder_id    BIGINT,
  folder_title TEXT,
  dashboard_id   BIGINT,
  dashboard_uid  TEXT   NOT NULL,
  dashboard_title TEXT  NOT NULL,
  dashboard_path  TEXT,
  UNIQUE (space_name, org_id, dashboard_uid)
);
"""

def db_connect(dbcfg: dict):
    return psycopg2.connect(
        host=dbcfg["host"], port=dbcfg["port"], dbname=dbcfg["name"],
        user=dbcfg["user"], password=dbcfg["password"]
    )

def db_prepare(conn, schema: str):
    with conn.cursor() as cur:
        cur.execute(DDL.format(schema=schema))
    conn.commit()

def db_upsert_inventory(conn, schema: str, rows: List[Tuple]):
    if not rows:
        return
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            f"""
            INSERT INTO {schema}.grafana_dashboards_inventory
              (run_id, space_name, space_url, org_id, org_name,
               folder_id, folder_title, dashboard_id, dashboard_uid,
               dashboard_title, dashboard_path)
            VALUES %s
            ON CONFLICT (space_name, org_id, dashboard_uid) DO UPDATE SET
              collected_at    = now(),
              space_url       = EXCLUDED.space_url,
              org_name        = EXCLUDED.org_name,
              folder_id       = EXCLUDED.folder_id,
              folder_title    = EXCLUDED.folder_title,
              dashboard_id    = EXCLUDED.dashboard_id,
              dashboard_title = EXCLUDED.dashboard_title,
              dashboard_path  = EXCLUDED.dashboard_path;
            """,
            rows,
            page_size=1000
        )
    conn.commit()

# ---------------------- Main ----------------------
def main():
    ap = argparse.ArgumentParser(description="Inventario de dashboards por compañía/carpeta → Postgres")
    ap.add_argument("-c", "--config", required=True, help="Ruta al archivo JSON de configuración")
    args = ap.parse_args()

    cfg = build_config(args)
    space = cfg["space"]
    g     = cfg["grafana"]
    d     = cfg["db"]

    # compañías
    companies = g["companies_inline"] or load_json(g["companies_file"])
    total_orgs = len(companies)

    # HTTP
    session, base_api = make_session(g["url"], g["username"], g["password"], g["verify_ssl"])

    # DB
    conn = db_connect(d)
    db_prepare(conn, d["schema"])
    run_id = str(uuid.uuid4())

    # Progreso
    start = time.time()
    done = 0
    progress_bar(0, total_orgs, prefix="Inventario", width=cfg["progress"]["bar_width"])

    total_dash = 0
    for company in companies:
        org_id = int(company["id"])
        org_name = company["name"]

        try:
            switch_organization(session, base_api, org_id)
            items = list_dashboards(session, base_api)

            rows = []
            for it in items:
                # Campos típicos de /search
                dash_id    = it.get("id")
                dash_uid   = it.get("uid")
                dash_title = it.get("title")
                dash_path  = it.get("url")  # ej: /d/uid/name
                folder_id  = it.get("folderId")
                folder_t   = it.get("folderTitle")

                rows.append((
                    run_id,
                    space["name"], space["url"],
                    org_id, org_name,
                    folder_id, folder_t, dash_id, dash_uid,
                    dash_title, dash_path
                ))

            db_upsert_inventory(conn, d["schema"], rows)
            total_dash += len(rows)

        except requests.HTTPError as he:
            print(f"\n[{org_name}] HTTP error: {he}")
        except Exception as e:
            print(f"\n[{org_name}] Error: {e}")
        finally:
            done += 1
            progress_bar(done, total_orgs, prefix="Inventario", width=cfg["progress"]["bar_width"])

    conn.close()
    elapsed = int(time.time() - start)
    print(f"\n✔ Inventario completado | orgs={total_orgs} dashboards={total_dash} tiempo={elapsed}s run_id={run_id}")

if __name__ == "__main__":
    main()
