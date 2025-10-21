#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, argparse, csv
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth

# ---------- utils ----------
def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def norm(s: Optional[str]) -> str:
    return (s or "").strip().casefold()

def build_config(args) -> Dict[str, Any]:
    # Carga .env si existe (opcional, como en tu script)
    try:
        from dotenv import load_dotenv, find_dotenv
        load_dotenv(find_dotenv(), override=False)
    except Exception:
        pass

    cfg = load_json(args.config)

    g = cfg.get("grafana", {})
    grafana_url  = os.getenv("GRAFANA_URL", g.get("url", "")).rstrip("/")
    grafana_user = os.getenv("GRAFANA_USERNAME", g.get("username", ""))
    grafana_pass = os.getenv("GRAFANA_PASSWORD", g.get("password", ""))
    verify_ssl   = (os.getenv("VERIFY_SSL", str(g.get("verify_ssl", True))).lower() not in {"0","false","no"})

    companies      = g.get("companies")
    companies_file = os.getenv("COMPANIES_FILE", g.get("companies_file", "companies.json"))

    r = cfg.get("rules", {}) or {}
    link_targets = r.get("link_targets") or {}

    return {
        "grafana": {
            "url": grafana_url, "username": grafana_user, "password": grafana_pass,
            "verify_ssl": verify_ssl, "companies_inline": companies,
            "companies_file": companies_file
        },
        "rules": {"link_targets": link_targets},
        "env_name": cfg.get("env_name", os.getenv("ENV_NAME", "dev"))
    }

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

def resolve_uid_in_company_folder(session: requests.Session, base_url: str, company_folder_title: str, expected_title: str) -> Optional[str]:
    """
    Igual a tu enfoque: busca dashboards por título y filtra folderTitle == company_folder_title.
    Devuelve UID si existe; None si no existe en la carpeta.
    """
    r = session.get(f"{base_url}/search", params={"type": "dash-db", "query": expected_title, "limit": 5000})
    r.raise_for_status()
    for it in (r.json() or []):
        if norm(it.get("title")) == norm(expected_title) and norm(it.get("folderTitle")) == norm(company_folder_title):
            return it.get("uid")
    return None

def find_company_folder(session, base_url: str, company_name: str) -> Optional[Dict[str, Any]]:
    """
    Carpeta principal: título EXACTO = nombre de la compañía.
    """
    for it in search_folders(session, base_url, company_name):
        if norm(it.get("title")) == norm(company_name):
            return it
    return None

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Lista dashboards esperados NO encontrados por compañía en su carpeta principal.")
    ap.add_argument("-c", "--config", required=True, help="Ruta al JSON de configuración")
    # Opcional: permitir override de títulos esperados por CLI
    ap.add_argument("--expected", help="Lista de títulos esperados separados por '|'. Si se omite, usa rules.link_targets (valores).")
    args = ap.parse_args()

    cfg = build_config(args)
    g, r = cfg["grafana"], cfg["rules"]

    # Companies
    companies = g["companies_inline"] if g["companies_inline"] else load_json(g["companies_file"])
    if not isinstance(companies, list) or not companies:
        print("No se encontraron compañías en config.", file=sys.stderr)
        sys.exit(2)

    # Títulos esperados (por defecto: valores del mapping link_targets)
    if args.expected:
        expected_titles: Set[str] = {t.strip() for t in args.expected.split("|") if t.strip()}
    else:
        expected_titles = set((r.get("link_targets") or {}).values())

    if not expected_titles:
        print("No hay títulos esperados (rules.link_targets vacío y no se pasó --expected).", file=sys.stderr)
        sys.exit(3)

    session, base_url = make_session(g["url"], g["username"], g["password"], g["verify_ssl"])

    results: List[Dict[str, Any]] = []   # filas para CSV/JSON
    summary_rows: List[Tuple[str, int, int]] = []  # (company, expected_count, missing_count)

    print(f"Entorno: {cfg.get('env_name')} | Compañías: {len(companies)} | Títulos esperados: {len(expected_titles)}\n")

    for company in companies:
        company_name = company.get("name") or f"id:{company.get('id')}"
        missing: List[str] = []

        try:
            switch_organization(session, base_url, company["id"])
        except Exception as e:
            # Si no se puede cambiar de org, marcamos todo como faltante por esta compañía
            for title in expected_titles:
                results.append({
                    "company": company_name,
                    "company_id": company.get("id"),
                    "expected_title": title,
                    "found": False,
                    "reason": f"switch_org_failed: {e}"
                })
            summary_rows.append((company_name, len(expected_titles), len(expected_titles)))
            print(f"- {company_name}: ERROR al cambiar de organización → todos faltantes ({len(expected_titles)})")
            continue

        folder = find_company_folder(session, base_url, company_name)
        if not folder:
            # Si no hay carpeta principal, todos faltan
            for title in expected_titles:
                results.append({
                    "company": company_name,
                    "company_id": company.get("id"),
                    "expected_title": title,
                    "found": False,
                    "reason": "company_folder_not_found"
                })
            summary_rows.append((company_name, len(expected_titles), len(expected_titles)))
            print(f"- {company_name}: carpeta principal NO encontrada → faltan {len(expected_titles)}")
            continue

        folder_title = folder.get("title")
        for title in expected_titles:
            uid = resolve_uid_in_company_folder(session, base_url, folder_title, title)
            if uid:
                results.append({
                    "company": company_name,
                    "company_id": company.get("id"),
                    "expected_title": title,
                    "found": True,
                    "dashboard_uid": uid,
                    "reason": ""
                })
            else:
                missing.append(title)
                results.append({
                    "company": company_name,
                    "company_id": company.get("id"),
                    "expected_title": title,
                    "found": False,
                    "reason": "not_found_in_company_folder"
                })

        summary_rows.append((company_name, len(expected_titles), len(missing)))
        if missing:
            print(f"- {company_name}: faltan {len(missing)}/{len(expected_titles)} → {', '.join(missing)}")
        else:
            print(f"- {company_name}: OK, todos presentes ({len(expected_titles)})")

    # Guardar JSON
    out_json = {
        "env": cfg.get("env_name"),
        "expected_count": len(expected_titles),
        "companies": len(companies),
        "results": results,
        "summary": [
            {"company": c, "expected": exp, "missing": miss} for (c, exp, miss) in summary_rows
        ]
    }
    with open("missing_dashboards.json", "w", encoding="utf-8") as f:
        json.dump(out_json, f, indent=2, ensure_ascii=False)

    # Guardar CSV (solo los no encontrados para que sea “la lista que quieres ver”)
    with open("missing_dashboards.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["company","company_id","expected_title","reason"])
        for row in results:
            if not row.get("found"):
                w.writerow([row.get("company"), row.get("company_id"), row.get("expected_title"), row.get("reason")])

    total_missing = sum(miss for _, _, miss in summary_rows)
    print(f"\nResumen: compañías={len(companies)} | títulos_esperados={len(expected_titles)} | faltantes_total={total_missing}")
    print("Archivos generados: missing_dashboards.json, missing_dashboards.csv")

if __name__ == "__main__":
    main()
