#Author: Vladimir Franca de Sousa vfrancad@gmail.com
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.

#!/usr/bin/env python3
from __future__ import annotations
import os, sys, json, time
from typing import Dict, List, Any, Optional
import requests

# Auth + API base
AUTH_URL = os.getenv("PRISMASASE_AUTH_URL", "https://auth.apps.paloaltonetworks.com/oauth2/access_token")
BASE_API_URL = os.getenv("SASE_BASE_URL", "https://api.sase.paloaltonetworks.com")

def get_env_variable(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise ValueError(f"Environment variable {name} is not set")
    return v

def get_token() -> str:
    client_id = get_env_variable("PRISMASASE_CLIENT_ID")
    client_secret = get_env_variable("PRISMASASE_CLIENT_SECRET")
    tsg_id = get_env_variable("PRISMASASE_TSG_ID")
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": f"tsg_id:{tsg_id}",
    }
    r = requests.post(
        AUTH_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data, timeout=30
    )
    if r.status_code != 200:
        raise RuntimeError(f"Auth failed {r.status_code}: {r.text[:200]}")
    j = r.json()
    tok = j.get("access_token") or j.get("accessToken")
    if not tok:
        raise RuntimeError(f"Token field not found in response: keys={list(j.keys())}")
    return tok

def get_headers(token: str) -> Dict[str,str]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        # Tenant scoping header — required in most SD-WAN calls:
        "X-PAN-TSG-ID": get_env_variable("PRISMASASE_TSG_ID"),
    }
    # Optional region header if your tenant needs it; otherwise omit
    region = os.getenv("PRISMASASE_REGION")
    if region:
        headers["x-panw-region"] = region
    return headers

# ----- keep profile call (non-fatal if it fails)
def get_profile(session: requests.Session, headers: Dict[str,str]) -> Optional[Dict[str,Any]]:
    urls = [
        f"{BASE_API_URL}/sdwan/v2.5/api/tenants/self",
        f"{BASE_API_URL}/sdwan/v2.1/api/profile",
    ]
    for url in urls:
        try:
            r = session.get(url, headers=headers, timeout=30)
            if r.status_code == 200:
                print(f"[info] profile OK: {url}")
                return r.json()
            else:
                print(f"[warn] profile {url} -> {r.status_code}: {r.text[:120]}")
        except Exception as e:
            print(f"[warn] profile {url} exception: {e}")
    return None

MACHINE_FIELDS = [
    "machine_state",
    "renew_state",
    "em_element_id",
    "connected",
    "manufacture_id",   # some tenants return manufacturer_id; we handle both below
    "ship_state",
    "esp_tenant_id",
    "suspend_state",
]

def list_machines(session: requests.Session, headers: Dict[str,str]) -> List[Dict[str,Any]]:
    url = f"{BASE_API_URL}/sdwan/v2.5/api/machines"
    items: List[Dict[str,Any]] = []
    params = {"limit": 200}

    while True:
        r = session.get(url, headers=headers, params=params, timeout=60)
        if r.status_code != 200:
            raise RuntimeError(f"/machines {r.status_code}: {r.text[:200]}")
        data = r.json()

        if isinstance(data, list):
            page = data
            next_token = None
            total = None
        else:
            page = data.get("items") or data.get("data") or data.get("machines") or []
            next_token = data.get("next") or (data.get("page", {}) or {}).get("next")
            total = data.get("total") or data.get("totalCount")

        items.extend(page)

        if next_token:
            params = {"limit": 200, "cursor": next_token}
            continue
        if total is not None and len(items) < int(total):
            params = {"limit": 200, "offset": len(items)}
            continue
        break

    return items

def extract_machine_status(m: Dict[str,Any]) -> Dict[str,Any]:
    out = {k: m.get(k) for k in MACHINE_FIELDS}
    if out.get("manufacture_id") is None and "manufacturer_id" in m:
        out["manufacture_id"] = m.get("manufacturer_id")
    return out

def main() -> int:
    try:
        token = get_token()
    except Exception as e:
        print(f"[error] auth failed: {e}", file=sys.stderr)
        return 1

    headers = get_headers(token)

    with requests.Session() as s:
        _ = get_profile(s, headers)

        try:
            machines = list_machines(s, headers)
        except Exception as e:
            print(f"[error] fetching machines: {e}", file=sys.stderr)
            return 1

        if not machines:
            print("[info] no machines returned.")
            return 0

        rows = [extract_machine_status(m) for m in machines]

        cols = MACHINE_FIELDS
        print("\n=== Machines status ===")
        print(" | ".join(cols))
        print("-" * (len(" | ".join(cols)) + 2))
        for r in rows:
            print(" | ".join(str(r.get(c, "")) for c in cols))

        out = {"generated_at": int(time.time()), "count": len(rows), "machines": rows}
        with open("machines_status.json", "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(f"\n[ok] wrote machines_status.json with {len(rows)} entries.")
        return 0

if __name__ == "__main__":
    raise SystemExit(main())
