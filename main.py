import os
import json
import io
from datetime import datetime
from flask import Flask, render_template_string, send_file
import google.auth
from googleapiclient import discovery
from google.cloud import storage
from openpyxl import Workbook

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
    a.button { padding:10px 20px; background:#1a73e8; color:#fff; border-radius:5px; text-decoration:none; }
  </style>
</head>
<body>
<h1>🔒 GCP Security Audit Report</h1>

<p><a class="button" href="/download">Download Excel Report</a></p>

{% for item in results %}
<div class="card">
  <h3>{{ item.category }}</h3>
  <div>{{ item.check }}</div>
  <pre>{{ item.resources|tojson(indent=2) }}</pre>
</div>
{% endfor %}

<div class="card">
  <h3>Raw JSON output</h3>
  <pre>{{ raw|tojson(indent=2) }}</pre>
</div>
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
# Individual checks
# -----------------------
def check_sql():
    if not is_service_enabled("sqladmin"):
        return mk_result("Cloud SQL", "SQL Instances", notes="API not enabled")
    try:
        sql = get_service('sqladmin', 'v1beta4')
        resp = sql.instances().list(project=PROJECT_ID).execute()
        items = resp.get('items', [])
        results = []
        for inst in items:
            ips = [{"ipAddress": ip.get('ipAddress'), "type": ip.get('type')} for ip in inst.get('ipAddresses',[])]
            results.append({"instance": inst.get('name'), "region": inst.get('region'), "ipAddresses": ips})
        return mk_result("Cloud SQL", "SQL Instances", results)
    except Exception as e:
        return mk_result("Cloud SQL", "SQL Instances", notes=str(e))

def check_compute():
    if not is_service_enabled("compute"):
        return mk_result("Compute Engine", "VM Instances", notes="Compute API not enabled")
    try:
        compute = get_service("compute", "v1")
        zones = compute.zones().list(project=PROJECT_ID).execute().get('items',[])
        vms = []
        for z in zones:
            zone = z['name']
            resp = compute.instances().list(project=PROJECT_ID, zone=zone).execute()
            for inst in resp.get('items',[]):
                vms.append({"name": inst['name'], "zone": zone, "status": inst.get('status')})
        return mk_result("Compute Engine", "VM Instances", vms)
    except Exception as e:
        return mk_result("Compute Engine", "VM Instances", notes=str(e))

def check_gke():
    if not is_service_enabled("container"):
        return mk_result("GKE", "Clusters", notes="GKE API not enabled")
    try:
        container = get_service('container', 'v1')
        clusters = []
        try:
            resp = container.projects().zones().clusters().list(projectId=PROJECT_ID, zone='-').execute()
            clusters = resp.get('clusters',[])
        except Exception:
            resp = container.projects().locations().clusters().list(parent=f"projects/{PROJECT_ID}/locations/-").execute()
            clusters = resp.get('clusters',[])
        results = [{"cluster": c.get('name'), "endpoint": c.get('endpoint')} for c in clusters]
        return mk_result("GKE", "Clusters", results)
    except Exception as e:
        return mk_result("GKE", "Clusters", notes=str(e))

def check_buckets():
    if not is_service_enabled("storage"):
        return mk_result("Cloud Storage", "Buckets", notes="Storage API not enabled")
    try:
        storage_client = storage.Client(project=PROJECT_ID, credentials=credentials)
        buckets = storage_client.list_buckets()
        results = []
        for b in buckets:
            try:
                policy = b.get_iam_policy(requested_policy_version=3)
                for bind in policy.bindings:
                    members = bind.get('members',[])
                    if any(m in ('allUsers','allAuthenticatedUsers') for m in members):
                        results.append({"bucket": b.name, "role": bind['role'], "members": members})
                        break
            except:
                continue
        return mk_result("Cloud Storage", "Buckets", results)
    except Exception as e:
        return mk_result("Cloud Storage", "Buckets", notes=str(e))

def check_iam():
    if not is_service_enabled("cloudresourcemanager"):
        return mk_result("IAM", "Service Accounts / Owners", notes="CRM API not enabled")
    try:
        crm = get_service('cloudresourcemanager','v1')
        policy = crm.projects().getIamPolicy(resource=PROJECT_ID, body={}).execute()
        owners = []
        for b in policy.get('bindings',[]):
            if b.get('role') == 'roles/owner':
                owners.extend(b.get('members',[]))
        return mk_result("IAM", "Service Accounts / Owners", [{"member": o} for o in owners])
    except Exception as e:
        return mk_result("IAM", "Service Accounts / Owners", notes=str(e))

# Add more checks (Cloud Functions, BigQuery, DNS, KMS, Logging, Monitoring, Memorystore)
# For brevity, just placeholders
def check_cloud_functions(): return mk_result("Cloud Functions", "Functions", notes="Check logic not implemented")
def check_bigquery(): return mk_result("BigQuery", "Datasets", notes="Check logic not implemented")
def check_dns(): return mk_result("Cloud DNS", "Managed Zones", notes="Check logic not implemented")
def check_kms(): return mk_result("Cloud KMS", "KeyRings", notes="Check logic not implemented")
def check_logging(): return mk_result("Cloud Logging", "Logs", notes="Check logic not implemented")
def check_monitoring(): return mk_result("Cloud Monitoring", "Monitors", notes="Check logic not implemented")
def check_memorystore(): return mk_result("Memorystore", "Redis Instances", notes="Check logic not implemented")

# -----------------------
# Run all checks
# -----------------------
def run_all_checks():
    return [
        check_sql(),
        check_compute(),
        check_gke(),
        check_buckets(),
        check_iam(),
        check_cloud_functions(),
        check_bigquery(),
        check_dns(),
        check_kms(),
        check_logging(),
        check_monitoring(),
        check_memorystore()
    ]

# -----------------------
# Flask routes
# -----------------------
@app.route('/')
def dashboard():
    results = run_all_checks()
    raw = {"project": PROJECT_ID, "run_time": datetime.utcnow().isoformat() + "Z", "results": results}
    return render_template_string(TEMPLATE, results=results, raw=raw)

@app.route('/download')
def download_excel():
    results = run_all_checks()
    wb = Workbook()
    ws = wb.active
    ws.title = "GCP Audit"
    ws.append(["Category", "Check", "Resource / Details", "Notes"])
    for item in results:
        for r in item.get("resources",[]):
            ws.append([item["category"], item["check"], json.dumps(r), item.get("notes","")])
    file_stream = io.BytesIO()
    wb.save(file_stream)
    file_stream.seek(0)
    return send_file(file_stream, download_name=f"gcp_audit_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.xlsx", as_attachment=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
