# main.py
import os
import json
import threading
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request
import google.auth
from googleapiclient import discovery
from google.cloud import storage

try:
    from google.cloud import compute_v1
except Exception:
    compute_v1 = None  # if module not installed, skip VMs

app = Flask(__name__)

# HTML template
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
    pre { white-space: pre-wrap; word-wrap: break-word; }
  </style>
</head>
<body>
<h1>🔒 GCP Security Audit Report</h1>
<div id="progress">Progress: 0/5 done</div>
<div id="results"></div>

<script>
function fetchProgress(){
    fetch(window.location.href + "?_progress=1")
      .then(r => r.json())
      .then(data => {
          document.getElementById('progress').innerText = 
            `Progress: ${data.completed}/${data.total} done`;
          if(data.results_html) {
            document.getElementById('results').innerHTML = data.results_html;
          }
          if(data.completed < data.total){
            setTimeout(fetchProgress, 2000);
          }
      })
      .catch(e => console.log(e));
}
fetchProgress();
</script>
</body>
</html>
"""

# --------------------------
# Globals
# --------------------------
credentials, project = google.auth.default()
PROJECT_ID = os.environ.get("GCP_PROJECT", project)
RESULT_BUCKET = os.environ.get("RESULT_BUCKET")

audit_progress = {
    "completed": 0,
    "total": 5,
    "results": []
}
progress_lock = threading.Lock()
audit_started = False

def mk_result(category, check, resources=None, notes=None):
    return {"category": category, "check": check, "resources": resources or [], "notes": notes or ""}

def get_service(name, version):
    try:
        return discovery.build(name, version, credentials=credentials, cache_discovery=False)
    except Exception:
        return None

def is_service_enabled(api_name):
    try:
        svc = get_service('serviceusage', 'v1')
        resp = svc.services().get(name=f'projects/{PROJECT_ID}/services/{api_name}.googleapis.com').execute()
        return resp.get('state') == 'ENABLED'
    except Exception:
        return False

# --------------------------
# Checks
# --------------------------
def check_sql_public_ips():
    if not is_service_enabled("sqladmin"): return mk_result("Cloud SQL", "SQL Instances", notes="SQL API not enabled")
    try:
        sql = get_service('sqladmin', 'v1beta4')
        items = sql.instances().list(project=PROJECT_ID).execute().get('items', [])
        res = []
        for i in items:
            ips = [{"ipAddress": ip.get('ipAddress'), "type": ip.get('type')} for ip in i.get('ipAddresses', [])]
            res.append({"instance": i.get('name'), "region": i.get('region'), "ipAddresses": ips})
        return mk_result("Cloud SQL", "SQL Instances", res)
    except Exception as e:
        return mk_result("Cloud SQL", "SQL Instances", notes=str(e))

def check_gke_public_nodes():
    if not is_service_enabled("container"): return mk_result("GKE", "GKE clusters", notes="GKE API not enabled")
    try:
        container = get_service('container', 'v1')
        clusters = []
        try:
            clusters = container.projects().locations().clusters().list(parent=f"projects/{PROJECT_ID}/locations/-").execute().get('clusters', [])
        except Exception:
            clusters = []
        results = [{"cluster": c.get('name'), "endpoint": c.get('endpoint'), "privateClusterConfig": bool(c.get('privateClusterConfig'))} for c in clusters]
        return mk_result("GKE", "GKE clusters", results)
    except Exception as e:
        return mk_result("GKE", "GKE clusters", notes=str(e))

def check_buckets_public():
    if not is_service_enabled("storage"): return mk_result("Storage", "Buckets", notes="Storage API not enabled")
    try:
        client = storage.Client(project=PROJECT_ID, credentials=credentials)
        buckets = list(client.list_buckets())
        res = []
        for b in buckets:
            try:
                policy = b.get_iam_policy(requested_policy_version=3)
                for bind in policy.bindings:
                    members = list(bind.get('members', []))
                    if any(m in ('allUsers', 'allAuthenticatedUsers') for m in members):
                        res.append({"bucket": b.name, "role": bind.get('role'), "members": members})
                        break
            except Exception:
                continue
        return mk_result("Storage", "Buckets", res)
    except Exception as e:
        return mk_result("Storage", "Buckets", notes=str(e))

def check_service_accounts_with_owner():
    if not is_service_enabled("cloudresourcemanager"): return mk_result("IAM", "Owners", notes="CRM API not enabled")
    try:
        crm = get_service('cloudresourcemanager', 'v1')
        policy = crm.projects().getIamPolicy(resource=PROJECT_ID, body={}).execute()
        owners = []
        for b in policy.get('bindings', []):
            if b.get('role') == 'roles/owner':
                owners.extend(list(b.get('members', [])))
        return mk_result("IAM", "Service Accounts with owner", [{"member": o} for o in owners])
    except Exception as e:
        return mk_result("IAM", "Service Accounts with owner", notes=str(e))

def check_vms():
    if compute_v1 is None or not is_service_enabled("compute"): return mk_result("Compute Engine", "VMs", notes="Compute API not enabled")
    try:
        client = compute_v1.InstancesClient(credentials=credentials)
        zones = ["us-central1-a", "us-central1-b"]  # safer: default zones
        vms = []
        for z in zones:
            try:
                for vm in client.list(project=PROJECT_ID, zone=z):
                    vms.append({"name": vm.name, "zone": z, "status": vm.status})
            except Exception:
                continue
        return mk_result("Compute Engine", "VMs", vms)
    except Exception as e:
        return mk_result("Compute Engine", "VMs", notes=str(e))

# --------------------------
# Async audit runner
# --------------------------
def run_audit():
    checks = [check_sql_public_ips, check_gke_public_nodes, check_buckets_public, check_service_accounts_with_owner, check_vms]
    for chk in checks:
        try:
            res = chk()
        except Exception as e:
            res = mk_result("Error", str(chk.__name__), notes=str(e))
        with progress_lock:
            audit_progress["results"].append(res)
            audit_progress["completed"] += 1

# --------------------------
# Route
# --------------------------
@app.route('/')
def dashboard():
    global audit_started
    if "_progress" in dict(request.args):
        with progress_lock:
            results_html = "".join([f"<div class='card'><h3>{i['category']}</h3><pre>{json.dumps(i, indent=2)}</pre></div>" for i in audit_progress["results"]])
            return jsonify({"completed": audit_progress["completed"], "total": audit_progress["total"], "results_html": results_html})
    if not audit_started:
        threading.Thread(target=run_audit, daemon=True).start()
        audit_started = True
    return render_template_string(TEMPLATE)

# --------------------------
# Cloud Function entry
# --------------------------
def main(request):
    return dashboard()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
