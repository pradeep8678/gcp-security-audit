# main.py
import os
import json
import threading
from datetime import datetime
from flask import Flask, render_template_string, jsonify
import google.auth
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from google.cloud import storage, compute_v1

app = Flask(__name__)

# --------------------------
# HTML template
# --------------------------
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
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { padding: 8px 10px; border-bottom: 1px solid #eee; text-align:left; vertical-align:top; }
    th { background: #1a73e8; color: #fff; }
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
            setTimeout(fetchProgress, 1500);
          }
      })
      .catch(e => console.log(e));
}

// start fetching progress when page loads
fetchProgress();
</script>
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

credentials, project = google.auth.default()
PROJECT_ID = os.environ.get("GCP_PROJECT", project)
RESULT_BUCKET = os.environ.get("RESULT_BUCKET")

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

# --------------------------
# Global state for progress
# --------------------------
audit_progress = {
    "completed": 0,
    "total": 5,  # number of checks
    "results": []
}

progress_lock = threading.Lock()

# --------------------------
# Checks
# --------------------------
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
                ips.append({"ipAddress": ip.get('ipAddress'), "type": ip.get('type')})
            public.append({"instance": inst.get('name'), "region": inst.get('region'), "ipAddresses": ips})
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
            results.append({
                "cluster": c.get('name'),
                "endpoint": c.get('endpoint'),
                "privateClusterConfig": bool(c.get('privateClusterConfig'))
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
                for bind in policy.bindings:
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
    if not is_service_enabled("compute"):
        return mk_result("Compute Engine", "VM Instances", notes="Compute API not enabled")
    try:
        client = compute_v1.InstancesClient(credentials=credentials)
        zones = [z.name for z in compute_v1.ZonesClient().list(project=PROJECT_ID)]
        vms = []
        for z in zones:
            try:
                for vm in client.list(project=PROJECT_ID, zone=z):
                    vms.append({"name": vm.name, "zone": z, "status": vm.status})
            except Exception:
                continue
        return mk_result("Compute Engine", "VM Instances", vms)
    except Exception as e:
        return mk_result("Compute Engine", "VM Instances", notes=str(e))

# --------------------------
# Async runner
# --------------------------
def run_audit():
    checks = [check_sql_public_ips, check_gke_public_nodes, check_buckets_public, check_service_accounts_with_owner, check_vms]
    results = []
    for chk in checks:
        res = chk()
        results.append(res)
        with progress_lock:
            audit_progress["results"].append(res)
            audit_progress["completed"] += 1

# --------------------------
# Flask route
# --------------------------
@app.route('/')
def dashboard():
    # If _progress query, return JSON
    if "_progress" in dict(request.args):
        with progress_lock:
            # Generate HTML for completed checks
            results_html = ""
            for item in audit_progress["results"]:
                results_html += f"<div class='card'><h3>{item['category']}</h3><pre>{json.dumps(item, indent=2)}</pre></div>"
            return jsonify({
                "completed": audit_progress["completed"],
                "total": audit_progress["total"],
                "results_html": results_html
            })
    # Start audit thread if not started
    if audit_progress["completed"] == 0:
        threading.Thread(target=run_audit, daemon=True).start()
    # Render page
    return render_template_string(TEMPLATE)

# --------------------------
# Cloud Function entry
# --------------------------
def main(request):
    return dashboard()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
