# main.py
import os
import json
from datetime import datetime
from io import BytesIO
from flask import Flask, send_file, render_template_string, request
import google.auth
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from google.cloud import storage
import pandas as pd

app = Flask(__name__)

# HTML dashboard template
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>GCP Security Audit</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f7f8fb; color: #111;}
    h1 { color: #1a73e8; }
    .card { background: white; padding: 12px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 12px; }
    button { padding: 10px 16px; background: #1a73e8; color: white; border: none; border-radius: 6px; cursor: pointer; }
    button:hover { background: #1669c1; }
  </style>
</head>
<body>
<h1>🔒 GCP Security Audit</h1>

<form method="GET" action="/download">
  <button type="submit">Run Audit & Download Excel</button>
</form>

{% if message %}
<div class="card">
  <p>{{ message }}</p>
</div>
{% endif %}

</body>
</html>
"""

# --------------------------
# Helper
# --------------------------
def mk_result(category, check, resources=None, notes=None):
    return {
        "category": category,
        "check": check,
        "resources": resources or [],
        "notes": notes or ""
    }

# GCP defaults
credentials, project = google.auth.default()
PROJECT_ID = os.environ.get("GCP_PROJECT", project)

def get_service(name, version):
    return discovery.build(name, version, credentials=credentials, cache_discovery=False)

def is_service_enabled(api_name):
    try:
        serviceusage = get_service('serviceusage', 'v1')
        resp = serviceusage.services().get(
            name=f'projects/{PROJECT_ID}/services/{api_name}.googleapis.com'
        ).execute()
        return resp.get('state') == 'ENABLED'
    except Exception:
        return False

# -----------------------
# Checks
# -----------------------
def check_sql_public_ips():
    if not is_service_enabled("sqladmin"):
        return mk_result("Cloud SQL", "SQL Instances with public IPs", notes="Cloud SQL API not enabled")
    try:
        sql = get_service('sqladmin', 'v1beta4')
        resp = sql.instances().list(project=PROJECT_ID).execute()
        items = resp.get('items', [])
        public = []
        for inst in items:
            ips = []
            for ip in inst.get('ipAddresses', []):
                ips.append({
                    "ipAddress": ip.get('ipAddress'),
                    "type": ip.get('type')
                })
            public.append({
                "instance": inst.get('name'),
                "region": inst.get('region'),
                "ipAddresses": ips
            })
        return mk_result("Cloud SQL", "SQL Instances", public)
    except Exception as e:
        return mk_result("Cloud SQL", "SQL Instances", notes=str(e))

def check_gke_public_nodes():
    if not is_service_enabled("container"):
        return mk_result("GKE", "GKE clusters", notes="GKE API not enabled")
    try:
        container = get_service('container', 'v1')
        clusters = []
        try:
            resp = container.projects().zones().clusters().list(projectId=PROJECT_ID, zone='-').execute()
            clusters = resp.get('clusters', []) or []
        except HttpError:
            try:
                resp = container.projects().locations().clusters().list(parent=f"projects/{PROJECT_ID}/locations/-").execute()
                clusters = resp.get('clusters', []) or []
            except Exception:
                clusters = []

        results = []
        for c in clusters:
            endpoint = c.get('endpoint')
            private_config = c.get('privateClusterConfig')
            results.append({
                "cluster": c.get('name'),
                "endpoint": endpoint,
                "privateClusterConfig": bool(private_config)
            })
        return mk_result("GKE", "GKE clusters", results)
    except Exception as e:
        return mk_result("GKE", "GKE clusters", notes=str(e))

def check_buckets_public():
    if not is_service_enabled("storage"):
        return mk_result("Cloud Storage", "Buckets", notes="Storage API not enabled")
    try:
        storage_client = storage.Client(project=PROJECT_ID, credentials=credentials)
        buckets = list(storage_client.list_buckets())
        results = []
        for b in buckets:
            try:
                policy = b.get_iam_policy(requested_policy_version=3)
                bindings = policy.bindings
                for bind in bindings:
                    members = list(bind.get('members', []))
                    if any(m in ('allUsers', 'allAuthenticatedUsers') for m in members):
                        results.append({"bucket": b.name, "role": bind.get('role'), "members": members})
                        break
            except Exception:
                continue
        return mk_result("Cloud Storage", "Buckets", results)
    except Exception as e:
        return mk_result("Cloud Storage", "Buckets", notes=str(e))

def check_service_accounts_with_owner():
    if not is_service_enabled("cloudresourcemanager"):
        return mk_result("IAM", "Service Accounts with roles/owner", notes="CRM API not enabled")
    try:
        crm = get_service('cloudresourcemanager', 'v1')
        policy = crm.projects().getIamPolicy(resource=PROJECT_ID, body={}).execute()
        owners = []
        for b in policy.get('bindings', []):
            if b.get('role') == 'roles/owner':
                owners.extend(list(b.get('members', [])))
        results = [{"member": o} for o in owners]
        return mk_result("IAM", "Service Accounts with roles/owner", results)
    except Exception as e:
        return mk_result("IAM", "Service Accounts with roles/owner", notes=str(e))

def check_vms():
    from google.cloud import compute_v1
    try:
        client = compute_v1.InstancesClient()
        zones = [z.name for z in compute_v1.ZonesClient().list(project=PROJECT_ID)]
        results = []
        for zone in zones:
            for vm in client.list(project=PROJECT_ID, zone=zone):
                results.append({
                    "name": vm.name,
                    "zone": zone,
                    "status": vm.status,
                    "machine_type": vm.machine_type.split('/')[-1]
                })
        return mk_result("Compute Engine VM", "VM Instances", results)
    except Exception as e:
        return mk_result("Compute Engine VM", "VM Instances", notes=str(e))

# -----------------------
# Run all checks
# -----------------------
def run_all_checks():
    return [
        check_sql_public_ips(),
        check_gke_public_nodes(),
        check_buckets_public(),
        check_service_accounts_with_owner(),
        check_vms()
    ]

# -----------------------
# Flask routes
# -----------------------
@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/download')
def download_excel():
    results = run_all_checks()

    # Flatten results for Excel
    rows = []
    for item in results:
        for r in item.get("resources", []):
            row = {"Category": item["category"], "Check": item["check"]}
            row.update(r)
            row["Notes"] = item.get("notes", "")
            rows.append(row)

    df = pd.DataFrame(rows)
    output = BytesIO()
    df.to_excel(output, index=False)
    output.seek(0)

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    filename = f"audit-{ts}.xlsx"

    return send_file(output, download_name=filename, as_attachment=True)

# -----------------------
# Run locally
# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
