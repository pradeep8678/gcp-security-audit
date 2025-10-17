import os
import json
from datetime import datetime
from flask import Flask, render_template_string, send_file
import google.auth
from googleapiclient import discovery
from google.cloud import storage, bigquery, kms_v1
import io
from openpyxl import Workbook

app = Flask(__name__)

# HTML template with Excel button
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
  </style>
</head>
<body>
<h1>🔒 GCP Security Audit Report</h1>

<p><a href="/download" style="padding:10px 20px;background:#1a73e8;color:#fff;border-radius:5px;text-decoration:none;">Download Excel Report</a></p>

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
    return {"category": category, "check": check, "resources": resources or [], "notes": notes or ""}

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
# Checks for all services
# -----------------------
def check_sql_public_ips():
    if not is_service_enabled("sqladmin"):
        return mk_result("Cloud SQL", "SQL Instances", notes="SQL Admin API not enabled")
    try:
        sql = get_service('sqladmin','v1beta4')
        resp = sql.instances().list(project=PROJECT_ID).execute()
        results=[]
        for inst in resp.get('items',[]):
            ips=[]
            for ip in inst.get('ipAddresses',[]):
                ips.append({"ip":ip.get("ipAddress"),"type":ip.get("type")})
            results.append({"instance":inst.get("name"),"region":inst.get("region"),"ipAddresses":ips})
        return mk_result("Cloud SQL","SQL Instances",results)
    except Exception as e:
        return mk_result("Cloud SQL","SQL Instances",notes=str(e))

def check_gce():
    if not is_service_enabled("compute"):
        return mk_result("Compute Engine (GCE)","Compute API not enabled")
    try:
        compute = get_service("compute","v1")
        results=[]
        zones=compute.zones().list(project=PROJECT_ID).execute().get("items",[])
        for z in zones:
            zname=z.get("name")
            insts=compute.instances().list(project=PROJECT_ID, zone=zname).execute().get("items",[])
            for i in insts:
                results.append({"name":i.get("name"),"zone":zname,"status":i.get("status")})
        return mk_result("Compute Engine (GCE)","Instances",results)
    except Exception as e:
        return mk_result("Compute Engine (GCE)","Instances",notes=str(e))

def check_gke():
    if not is_service_enabled("container"):
        return mk_result("GKE","Container API not enabled")
    try:
        container = get_service("container","v1")
        clusters=[]
        try:
            clusters = container.projects().zones().clusters().list(projectId=PROJECT_ID, zone='-').execute().get("clusters",[])
        except:
            clusters = container.projects().locations().clusters().list(parent=f"projects/{PROJECT_ID}/locations/-").execute().get("clusters",[])
        results=[]
        for c in clusters:
            results.append({"cluster":c.get("name"),"endpoint":c.get("endpoint"),"privateClusterConfig":bool(c.get("privateClusterConfig"))})
        return mk_result("GKE","Clusters",results)
    except Exception as e:
        return mk_result("GKE","Clusters",notes=str(e))

def check_buckets():
    if not is_service_enabled("storage"):
        return mk_result("Cloud Storage","Storage API not enabled")
    try:
        storage_client = storage.Client(project=PROJECT_ID, credentials=credentials)
        buckets = list(storage_client.list_buckets())
        results=[]
        for b in buckets:
            try:
                policy = b.get_iam_policy(requested_policy_version=3)
                for bind in policy.bindings:
                    members = list(bind.get("members",[]))
                    if any(m in ("allUsers","allAuthenticatedUsers") for m in members):
                        results.append({"bucket":b.name,"role":bind.get("role"),"members":members})
                        break
            except:
                continue
        return mk_result("Cloud Storage","Public Buckets",results)
    except Exception as e:
        return mk_result("Cloud Storage","Public Buckets",notes=str(e))

def check_iam():
    if not is_service_enabled("cloudresourcemanager"):
        return mk_result("IAM","CRM API not enabled")
    try:
        crm = get_service("cloudresourcemanager","v1")
        policy = crm.projects().getIamPolicy(resource=PROJECT_ID,body={}).execute()
        owners=[]
        for b in policy.get("bindings",[]):
            if b.get("role")=="roles/owner":
                owners.extend(list(b.get("members",[])))
        results=[{"member":o} for o in owners]
        return mk_result("IAM","Service Accounts with Owner",results)
    except Exception as e:
        return mk_result("IAM","Service Accounts with Owner",notes=str(e))

def check_cloud_functions():
    if not is_service_enabled("cloudfunctions"):
        return mk_result("Cloud Functions","API not enabled")
    try:
        cf = get_service("cloudfunctions","v1")
        functions = cf.projects().locations().functions().list(parent=f"projects/{PROJECT_ID}/locations/-").execute().get("functions",[])
        results=[]
        for f in functions:
            results.append({"name":f.get("name"),"status":f.get("status")})
        return mk_result("Cloud Functions","Functions",results)
    except Exception as e:
        return mk_result("Cloud Functions","Functions",notes=str(e))

def check_bigquery():
    if not is_service_enabled("bigquery"):
        return mk_result("BigQuery","API not enabled")
    try:
        client = bigquery.Client(project=PROJECT_ID, credentials=credentials)
        datasets = list(client.list_datasets())
        results=[]
        for d in datasets:
            results.append({"dataset":d.dataset_id})
        return mk_result("BigQuery","Datasets",results)
    except Exception as e:
        return mk_result("BigQuery","Datasets",notes=str(e))

def check_dns():
    if not is_service_enabled("dns"):
        return mk_result("Cloud DNS","API not enabled")
    try:
        dns = get_service("dns","v1")
        zones = dns.managedZones().list(project=PROJECT_ID).execute().get("managedZones",[])
        results=[]
        for z in zones:
            results.append({"zone":z.get("name")})
        return mk_result("Cloud DNS","Managed Zones",results)
    except Exception as e:
        return mk_result("Cloud DNS","Managed Zones",notes=str(e))

def check_kms():
    if not is_service_enabled("cloudkms"):
        return mk_result("Cloud KMS","API not enabled")
    try:
        client = kms_v1.KeyManagementServiceClient(credentials=credentials)
        parent = f"projects/{PROJECT_ID}/locations/-"
        key_rings = client.list_key_rings(request={"parent": parent})
        results=[]
        for kr in key_rings:
            results.append({"key_ring":kr.name})
        return mk_result("Cloud KMS","Key Rings",results)
    except Exception as e:
        return mk_result("Cloud KMS","Key Rings",notes=str(e))

def check_logging():
    if not is_service_enabled("logging"):
        return mk_result("Cloud Logging","API not enabled")
    try:
        logging = get_service("logging","v2")
        sinks = logging.projects().sinks().list(parent=f"projects/{PROJECT_ID}").execute().get("sinks",[])
        results=[]
        for s in sinks:
            results.append({"sink":s.get("name")})
        return mk_result("Cloud Logging","Sinks",results)
    except Exception as e:
        return mk_result("Cloud Logging","Sinks",notes=str(e))

def check_monitoring():
    if not is_service_enabled("monitoring"):
        return mk_result("Cloud Monitoring","API not enabled")
    try:
        monitoring = get_service("monitoring","v3")
        mcs = monitoring.projects().metricDescriptors().list(name=f"projects/{PROJECT_ID}").execute().get("metricDescriptors",[])
        results=[]
        for mc in mcs:
            results.append({"metric":mc.get("name")})
        return mk_result("Cloud Monitoring","Metric Descriptors",results)
    except Exception as e:
        return mk_result("Cloud Monitoring","Metric Descriptors",notes=str(e))

def check_memorystore():
    if not is_service_enabled("redis"):
        return mk_result("Memorystore (Redis)","API not enabled")
    try:
        redis = get_service("redis","v1")
        instances = redis.projects().locations().instances().list(parent=f"projects/{PROJECT_ID}/locations/-").execute().get("instances",[])
        results=[]
        for i in instances:
            results.append({"name":i.get("name"),"tier":i.get("tier")})
        return mk_result("Memorystore (Redis)","Instances",results)
    except Exception as e:
        return mk_result("Memorystore (Redis)","Instances",notes=str(e))

# -----------------------
# Run all checks
# -----------------------
def run_all_checks():
    return [
        check_sql_public_ips(),
        check_gce(),
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
    ws.append(["Category","Check","Resource / Details","Notes"])
    for item in results:
        for r in item["resources"]:
            ws.append([item["category"],item["check"],json.dumps(r),item.get("notes","")])
    # Save to in-memory file
    file_stream = io.BytesIO()
    wb.save(file_stream)
    file_stream.seek(0)
    return send_file(file_stream, download_name=f"gcp_audit_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.xlsx", as_attachment=True)

if __name__ == "__main__":
    port=int(os.environ.get("PORT",8080))
    app.run(host="0.0.0.0", port=port)
