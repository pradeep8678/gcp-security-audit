import os
import json
import threading
from datetime import datetime
from flask import Flask, jsonify, render_template_string
import google.auth
from googleapiclient import discovery
from google.cloud import storage

app = Flask(__name__)

# -----------------------
# Global Progress Storage
# -----------------------
progress = {
    "total": 5,   # number of checks
    "done": 0,
    "results": [],
    "running": False
}

# HTML Template
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
button { padding: 8px 12px; margin-bottom: 12px; cursor:pointer; background:#1a73e8; color:white; border:none; border-radius:4px;}
</style>
</head>
<body>
<h1>🔒 GCP Security Audit Report</h1>
<button onclick="fetchProgress()">Show Progress</button>
<div id="progress">Audit Progress: {{ progress.done }}/{{ progress.total }} done</div>
<div id="results">
{% for item in progress.results %}
<div class="card">
  <h3>{{ item.category }}</h3>
  <div>{{ item.check }}</div>
  {% if item.resources %}
  <pre>{{ item.resources|tojson(indent=2) }}</pre>
  {% else %}
  <div><em>No resources found.</em></div>
  {% endif %}
</div>
{% endfor %}
</div>
<script>
function fetchProgress(){
    fetch("/progress")
    .then(r => r.json())
    .then(data => {
        document.getElementById("progress").innerText = "Audit Progress: "+data.done+"/"+data.total+" done";
        let container = document.getElementById("results");
        container.innerHTML = "";
        data.results.forEach(item=>{
            let card = document.createElement("div");
            card.className = "card";
            let html = "<h3>"+item.category+"</h3><div>"+item.check+"</div>";
            if(item.resources.length>0){
                html += "<pre>"+JSON.stringify(item.resources,null,2)+"</pre>";
            } else { html += "<div><em>No resources found.</em></div>"; }
            card.innerHTML = html;
            container.appendChild(card);
        });
    })
    .catch(err => console.log(err));
}

// auto refresh every 3 seconds
setInterval(fetchProgress, 3000);
</script>
</body>
</html>
"""

# -----------------------
# Helper
# -----------------------
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

# -----------------------
# Checks
# -----------------------
def check_sql_public_ips():
    if not is_service_enabled("sqladmin"):
        return mk_result("Cloud SQL", "SQL Instances", notes="Cloud SQL API not enabled")
    try:
        sql = get_service('sqladmin', 'v1beta4')
        resp = sql.instances().list(project=PROJECT_ID).execute()
        items = resp.get('items', [])
        resources = []
        for inst in items:
            ips = [{"ipAddress": ip.get('ipAddress'), "type": ip.get('type')} for ip in inst.get('ipAddresses',[])]
            resources.append({"instance": inst.get('name'), "region": inst.get('region'), "ipAddresses": ips})
        return mk_result("Cloud SQL", "SQL Instances", resources)
    except Exception as e:
        return mk_result("Cloud SQL", "SQL Instances", notes=str(e))

def check_gke_public_nodes():
    if not is_service_enabled("container"):
        return mk_result("GKE", "GKE clusters", notes="GKE API not enabled")
    try:
        container = get_service('container', 'v1')
        clusters = container.projects().locations().clusters().list(parent=f"projects/{PROJECT_ID}/locations/-").execute().get('clusters',[])
        results = [{"cluster": c.get('name'), "endpoint": c.get('endpoint')} for c in clusters]
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
                    members = bind.get('members',[])
                    if any(m in ['allUsers','allAuthenticatedUsers'] for m in members):
                        results.append({"bucket": b.name, "role": bind.get('role'), "members": members})
                        break
            except:
                continue
        return mk_result("Cloud Storage", "Buckets", results)
    except Exception as e:
        return mk_result("Cloud Storage", "Buckets", notes=str(e))

def check_service_accounts_with_owner():
    if not is_service_enabled("cloudresourcemanager"):
        return mk_result("IAM", "Service Accounts with roles/owner", notes="CRM API not enabled")
    try:
        crm = get_service('cloudresourcemanager','v1')
        policy = crm.projects().getIamPolicy(resource=PROJECT_ID, body={}).execute()
        owners = []
        for b in policy.get('bindings',[]):
            if b.get('role')=='roles/owner':
                owners.extend(list(b.get('members',[])))
        return mk_result("IAM", "Service Accounts with roles/owner", [{"member":o} for o in owners])
    except Exception as e:
        return mk_result("IAM", "Service Accounts with roles/owner", notes=str(e))

def check_vms():
    if not is_service_enabled("compute"):
        return mk_result("Compute Engine", "VM Instances", notes="Compute API not enabled")
    try:
        from google.cloud import compute_v1
        instances_client = compute_v1.InstancesClient(credentials=credentials)
        zones = [z.name for z in compute_v1.ZonesClient().list(project=PROJECT_ID)]
        vms=[]
        for zone in zones:
            for inst in instances_client.list(project=PROJECT_ID, zone=zone):
                vms.append({"name":inst.name,"zone":zone,"status":inst.status})
        return mk_result("Compute Engine", "VM Instances", vms)
    except Exception as e:
        return mk_result("Compute Engine", "VM Instances", notes=str(e))

# -----------------------
# Async Audit Runner
# -----------------------
def run_audit():
    progress["running"] = True
    progress["done"] = 0
    progress["results"] = []

    checks = [check_sql_public_ips, check_gke_public_nodes, check_buckets_public, check_service_accounts_with_owner, check_vms]
    progress["total"] = len(checks)

    for check in checks:
        try:
            result = check()
            progress["results"].append(result)
        except Exception as e:
            progress["results"].append(mk_result("Error", check.__name__, notes=str(e)))
        progress["done"] += 1

    progress["running"] = False

# -----------------------
# Flask Routes
# -----------------------
@app.route('/')
def dashboard():
    if not progress["running"] and progress["done"]==0:
        # start audit in background
        threading.Thread(target=run_audit).start()
    return render_template_string(TEMPLATE, progress=progress)

@app.route('/progress')
def get_progress():
    return jsonify(progress)

# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
