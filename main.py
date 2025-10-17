# main.py
import os
import json
import threading
from datetime import datetime
from flask import Flask, render_template_string
import google.auth
from googleapiclient import discovery
from google.cloud import storage, compute_v1

app = Flask(__name__)

# -----------------------
# Global progress tracker
# -----------------------
progress = {"total": 5, "done": 0, "results": []}
lock = threading.Lock()

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
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { padding: 8px 10px; border-bottom: 1px solid #eee; text-align:left; vertical-align:top; }
    th { background: #1a73e8; color: #fff; }
    #progress { font-size: 18px; margin-bottom: 10px; }
  </style>
</head>
<body>
<h1>🔒 GCP Security Audit Report</h1>
<div id="progress">Audit Progress: <span id="prog">{{ done }}/{{ total }}</span></div>
<button onclick="startAudit()">Start Audit</button>

<div id="results">
{% for item in results %}
<div class="card">
  <h3>{{ item.category }}</h3>
  <div>{{ item.check }}</div>
  {% if item.resources %}
  <table>
    <thead>
      <tr>
        {% if item.category == 'Cloud SQL' %}
          <th>Instance Name</th><th>Region</th><th>IP Address</th><th>Type</th>
        {% elif item.category == 'GKE' %}
          <th>Cluster Name</th><th>Endpoint</th><th>Private Cluster</th>
        {% elif item.category == 'Cloud Storage' %}
          <th>Bucket Name</th><th>Role</th><th>Members</th>
        {% elif item.category == 'IAM' %}
          <th>Member</th>
        {% elif item.category == 'VM' %}
          <th>VM Name</th><th>Zone</th><th>Machine Type</th><th>Public IP</th>
        {% else %}
          <th>Resource</th>
        {% endif %}
        <th>Notes</th>
      </tr>
    </thead>
    <tbody>
      {% for r in item.resources %}
      <tr>
        {% if item.category == 'Cloud SQL' %}
          {% for ip in r.ipAddresses %}
            <td>{{ r.instance }}</td><td>{{ r.region }}</td><td>{{ ip.ipAddress }}</td><td>{{ ip.type }}</td><td>{{ item.notes or '' }}</td>
          {% endfor %}
        {% elif item.category == 'GKE' %}
          <td>{{ r.cluster }}</td><td>{{ r.endpoint }}</td><td>{{ 'Yes' if r.privateClusterConfig else 'No' }}</td><td>{{ item.notes or '' }}</td>
        {% elif item.category == 'Cloud Storage' %}
          <td>{{ r.bucket }}</td><td>{{ r.role }}</td><td>{{ r.members|join(', ') }}</td><td>{{ item.notes or '' }}</td>
        {% elif item.category == 'IAM' %}
          <td>{{ r.member }}</td><td>{{ item.notes or '' }}</td>
        {% elif item.category == 'VM' %}
          <td>{{ r.name }}</td><td>{{ r.zone }}</td><td>{{ r.machine_type }}</td><td>{{ r.public_ip }}</td><td>{{ item.notes or '' }}</td>
        {% else %}
          <td>{{ r|tojson }}</td><td>{{ item.notes or '' }}</td>
        {% endif %}
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
    <div><em>No resources found.</em></div>
  {% endif %}
</div>
{% endfor %}
</div>

<script>
function startAudit(){
    fetch(window.location.href + "?start=1").then(r => r.text()).then(()=>{console.log("Audit started")});
}
function refreshProgress(){
    fetch(window.location.href + "progress").then(r => r.json()).then(data=>{
        document.getElementById("prog").innerText = data.done + "/" + data.total;
        document.getElementById("results").innerHTML = data.html;
        if(data.done < data.total){
            setTimeout(refreshProgress, 2000);
        }
    }).catch(()=>{setTimeout(refreshProgress, 2000);});
}
setTimeout(refreshProgress, 1000);
</script>
</body>
</html>
"""

# -----------------------
# Helper & GCP setup
# -----------------------
credentials, project = google.auth.default()
PROJECT_ID = os.environ.get("GCP_PROJECT", project)
RESULT_BUCKET = os.environ.get("RESULT_BUCKET")

def mk_result(category, check, resources=None, notes=None):
    return {"category": category,"check": check,"resources": resources or [],"notes": notes or ""}

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
        except:
            try:
                resp = container.projects().locations().clusters().list(parent=f"projects/{PROJECT_ID}/locations/-").execute()
                clusters = resp.get('clusters', []) or []
            except:
                clusters = []
        results = []
        for c in clusters:
            endpoint = c.get('endpoint')
            private_config = c.get('privateClusterConfig')
            results.append({"cluster": c.get('name'), "endpoint": endpoint, "privateClusterConfig": bool(private_config)})
        return mk_result("GKE", "GKE clusters", results)
    except Exception as e:
        return mk_result("GKE", "GKE clusters", notes=str(e))

def check_buckets_public():
    if not is_service_enabled("storage"):
        return mk_result("Cloud Storage", "Buckets", notes="Storage API not enabled")
    try:
        client = storage.Client(project=PROJECT_ID, credentials=credentials)
        buckets = list(client.list_buckets())
        results = []
        for b in buckets:
            try:
                policy = b.get_iam_policy(requested_policy_version=3)
                for bind in policy.bindings:
                    members = list(bind.get('members', []))
                    if any(m in ('allUsers', 'allAuthenticatedUsers') for m in members):
                        results.append({"bucket": b.name, "role": bind.get('role'), "members": members})
                        break
            except: continue
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

# 🆕 VM Scan
def check_vms():
    try:
        client = compute_v1.InstancesClient(credentials=credentials)
        zones_client = compute_v1.ZonesClient(credentials=credentials)
        zones = [z.name for z in zones_client.list(project=PROJECT_ID)]
        results = []
        for z in zones:
            try:
                for inst in client.list(project=PROJECT_ID, zone=z):
                    pub_ip = inst.network_interfaces[0].access_configs[0].nat_ip if inst.network_interfaces and inst.network_interfaces[0].access_configs else None
                    results.append({
                        "name": inst.name,
                        "zone": z,
                        "machine_type": inst.machine_type.split('/')[-1],
                        "public_ip": pub_ip
                    })
            except: continue
        return mk_result("VM", "Compute Engine VMs", results)
    except Exception as e:
        return mk_result("VM", "Compute Engine VMs", notes=str(e))

# -----------------------
# Run checks in background
# -----------------------
def run_audit():
    global progress
    checks = [
        check_sql_public_ips,
        check_gke_public_nodes,
        check_buckets_public,
        check_service_accounts_with_owner,
        check_vms
    ]
    with lock:
        progress = {"total": len(checks), "done": 0, "results": []}
    for check in checks:
        res = check()
        with lock:
            progress["results"].append(res)
            progress["done"] += 1
    # Optionally save to GCS
    if RESULT_BUCKET:
        client = storage.Client(project=PROJECT_ID, credentials=credentials)
        bucket = client.bucket(RESULT_BUCKET)
        if not bucket.exists():
            bucket = client.create_bucket(RESULT_BUCKET)
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        blob = bucket.blob(f"audit-{ts}.json")
        blob.upload_from_string(json.dumps(progress, indent=2), content_type='application/json')

# -----------------------
# Flask routes
# -----------------------
@app.route('/')
def dashboard():
    start = 'start' in (os.environ.get("START") or "")
    if not getattr(app, "audit_thread", None) or not app.audit_thread.is_alive():
        app.audit_thread = threading.Thread(target=run_audit, daemon=True)
        app.audit_thread.start()
    with lock:
        done = progress["done"]
        total = progress["total"]
        results = progress["results"]
    return render_template_string(TEMPLATE, done=done, total=total, results=results)

@app.route('/progress')
def get_progress():
    with lock:
        from flask import Markup
        results_html = render_template_string("""
        {% for item in results %}
        <div class="card">
            <h3>{{ item.category }}</h3>
            <div>{{ item.check }}</div>
        </div>
        {% endfor %}
        """, results=progress["results"])
        return json.dumps({"done": progress["done"], "total": progress["total"], "html": results_html})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
