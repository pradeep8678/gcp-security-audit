import os
import json
import threading
from datetime import datetime
from flask import Flask, jsonify, render_template_string, send_file
import google.auth
from googleapiclient import discovery
from google.cloud import storage
import io
from openpyxl import Workbook

app = Flask(__name__)

# Shared progress
progress_data = {"done": 0, "total": 0, "results": [], "status": "idle"}
progress_lock = threading.Lock()

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
button { padding:10px 20px;background:#1a73e8;color:#fff;border:none;border-radius:5px;cursor:pointer;}
.card { background: white; padding: 12px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 12px; }
</style>
<script>
function startAudit() {
    fetch('/start')
    .then(()=>{document.getElementById('status').innerText='Audit started...'; updateProgress();});
}

function updateProgress(){
    fetch('/progress')
    .then(res=>res.json())
    .then(data=>{
        document.getElementById('status').innerText='Audit progress: '+data.done+'/'+data.total+' done';
        let container=document.getElementById('results');
        container.innerHTML='';
        data.results.forEach(item=>{
            let card=document.createElement('div');
            card.className='card';
            card.innerHTML='<h3>'+item.category+'</h3><pre>'+JSON.stringify(item.resources,null,2)+'</pre>';
            container.appendChild(card);
        });
        if(data.done<data.total){
            setTimeout(updateProgress,2000);
        } else {
            document.getElementById('status').innerHTML+=' <br>✅ Audit complete! <a href="/download">Download Excel</a>';
        }
    });
}
</script>
</head>
<body>
<h1>🔒 GCP Security Audit</h1>
<button onclick="startAudit()">Start Audit</button>
<p id="status">Status: Idle</p>
<div id="results"></div>
</body>
</html>
"""

# GCP defaults
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
# Audit Functions (Add new services here)
# -----------------------
def mk_result(category, check, resources=None, notes=None):
    return {"category": category, "check": check, "resources": resources or [], "notes": notes or ""}

def check_sql():
    from googleapiclient.errors import HttpError
    category="Cloud SQL"
    if not is_service_enabled("sqladmin"):
        return mk_result(category,"Cloud SQL API not enabled")
    try:
        sql = get_service('sqladmin','v1beta4')
        resp = sql.instances().list(project=PROJECT_ID).execute()
        items=resp.get('items',[])
        results=[]
        for inst in items:
            ips=[]
            for ip in inst.get('ipAddresses',[]):
                ips.append({"ip":ip.get("ipAddress"),"type":ip.get("type")})
            results.append({"instance":inst.get("name"),"region":inst.get("region"),"ipAddresses":ips})
        return mk_result(category,"Cloud SQL Instances",results)
    except Exception as e:
        return mk_result(category,"Cloud SQL Instances",notes=str(e))

def check_gce():
    category="Compute Engine (GCE)"
    if not is_service_enabled("compute"):
        return mk_result(category,"Compute API not enabled")
    try:
        compute = get_service("compute","v1")
        zones=compute.zones().list(project=PROJECT_ID).execute().get("items",[])
        results=[]
        for z in zones:
            zname=z.get("name")
            insts=compute.instances().list(project=PROJECT_ID, zone=zname).execute().get("items",[])
            for i in insts:
                results.append({"name":i.get("name"),"zone":zname,"status":i.get("status")})
        return mk_result(category,"GCE Instances",results)
    except Exception as e:
        return mk_result(category,"GCE Instances",notes=str(e))

def check_gke():
    category="GKE"
    if not is_service_enabled("container"):
        return mk_result(category,"GKE API not enabled")
    try:
        container=get_service("container","v1")
        clusters=[]
        try:
            resp=container.projects().zones().clusters().list(projectId=PROJECT_ID, zone='-').execute()
            clusters=resp.get('clusters',[]) or []
        except:
            resp=container.projects().locations().clusters().list(parent=f"projects/{PROJECT_ID}/locations/-").execute()
            clusters=resp.get('clusters',[]) or []
        results=[]
        for c in clusters:
            results.append({"cluster":c.get("name"),"endpoint":c.get("endpoint"),"privateClusterConfig":bool(c.get("privateClusterConfig"))})
        return mk_result(category,"GKE Clusters",results)
    except Exception as e:
        return mk_result(category,"GKE Clusters",notes=str(e))

def check_buckets():
    category="Cloud Storage"
    if not is_service_enabled("storage"):
        return mk_result(category,"Storage API not enabled")
    try:
        storage_client=storage.Client(project=PROJECT_ID, credentials=credentials)
        buckets=list(storage_client.list_buckets())
        results=[]
        for b in buckets:
            try:
                policy=b.get_iam_policy(requested_policy_version=3)
                bindings=policy.bindings
                for bind in bindings:
                    members=list(bind.get("members",[]))
                    if any(m in ("allUsers","allAuthenticatedUsers") for m in members):
                        results.append({"bucket":b.name,"role":bind.get("role"),"members":members})
                        break
            except:
                continue
        return mk_result(category,"Public Buckets",results)
    except Exception as e:
        return mk_result(category,"Public Buckets",notes=str(e))

def check_iam():
    category="IAM"
    if not is_service_enabled("cloudresourcemanager"):
        return mk_result(category,"CRM API not enabled")
    try:
        crm=get_service("cloudresourcemanager","v1")
        policy=crm.projects().getIamPolicy(resource=PROJECT_ID,body={}).execute()
        owners=[]
        for b in policy.get("bindings",[]):
            if b.get("role")=="roles/owner":
                owners.extend(list(b.get("members",[])))
        results=[{"member":o} for o in owners]
        return mk_result(category,"Service Accounts with owner",results)
    except Exception as e:
        return mk_result(category,"Service Accounts with owner",notes=str(e))

# Add more check_* functions for Cloud Functions, BigQuery, Cloud DNS, Cloud KMS, Logging, Monitoring, Memorystore (Redis)

def all_checks():
    return [
        check_sql,
        check_gce,
        check_gke,
        check_buckets,
        check_iam,
        # TODO: Add other checks here
    ]

# -----------------------
# Background audit
# -----------------------
def run_audit():
    with progress_lock:
        progress_data["done"]=0
        progress_data["results"]=[]
        progress_data["status"]="running"
        progress_data["total"]=len(all_checks())
    for func in all_checks():
        result=func()
        with progress_lock:
            progress_data["results"].append(result)
            progress_data["done"]+=1
    with progress_lock:
        progress_data["status"]="completed"

# -----------------------
# Flask routes
# -----------------------
@app.route('/')
def dashboard():
    return render_template_string(TEMPLATE)

@app.route('/start')
def start_audit():
    thread=threading.Thread(target=run_audit)
    thread.start()
    return '', 200

@app.route('/progress')
def progress():
    with progress_lock:
        return jsonify(progress_data)

@app.route('/download')
def download_excel():
    with progress_lock:
        results=progress_data["results"]
    wb=Workbook()
    ws=wb.active
    ws.title="GCP Audit"
    ws.append(["Category","Check","Resource/Details","Notes"])
    for item in results:
        for r in item["resources"]:
            ws.append([item["category"],item["check"],json.dumps(r),item.get("notes","")])
    file_stream=io.BytesIO()
    wb.save(file_stream)
    file_stream.seek(0)
    return send_file(file_stream, download_name=f"gcp_audit_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.xlsx",as_attachment=True)

if __name__=="__main__":
    port=int(os.environ.get("PORT",8080))
    app.run(host="0.0.0.0", port=port)
