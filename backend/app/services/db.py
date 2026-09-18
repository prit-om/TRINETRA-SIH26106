from __future__ import annotations
import json, os, sqlite3, threading
from pathlib import Path

_DB=Path(os.getenv('TRINETRA_SQLITE_PATH','data/trinetra_runtime.db'))
_DB.parent.mkdir(parents=True,exist_ok=True); _lock=threading.Lock()

def connect():
    c=sqlite3.connect(_DB, check_same_thread=False); c.row_factory=sqlite3.Row; return c

def init_db():
    with _lock:
        c=connect(); c.executescript('''
        CREATE TABLE IF NOT EXISTS cases(case_id TEXT PRIMARY KEY, uploaded_at TEXT NOT NULL, sender_email TEXT, subject TEXT, risk_score INTEGER, classification TEXT, summary TEXT, source TEXT, evidence_sha256 TEXT, raw_email BLOB, report_json TEXT);
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, actor_role TEXT, action TEXT, at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS campaign_links(case_id TEXT, indicator TEXT, value TEXT);
        '''); c.commit(); c.close()

def save_case(report, raw, role='analyst'):
    from datetime import datetime, timezone
    init_db(); c=connect();
    c.execute('INSERT OR REPLACE INTO cases VALUES(?,?,?,?,?,?,?,?,?,?,?)',(report['case_id'],datetime.now(timezone.utc).isoformat(),report.get('sender_email',''),report.get('subject',''),report['risk_score'],report['classification'],report.get('summary',''),report.get('source','manual'),report.get('evidence',{}).get('sha256'),raw,json.dumps(report,default=str)))
    c.execute('INSERT INTO audit_log(case_id,actor_role,action,at) VALUES(?,?,?,?)',(report['case_id'],role,'case_created',datetime.now(timezone.utc).isoformat())); c.commit(); c.close()

def list_cases():
    init_db(); c=connect(); rows=[dict(x) for x in c.execute('SELECT case_id,uploaded_at,sender_email,subject,risk_score,classification,summary,source,evidence_sha256 FROM cases ORDER BY uploaded_at DESC').fetchall()]; c.close(); return rows

def find_related(case_id, sender_email, domains=None, ip=None, hashes=None):
    init_db(); c=connect(); vals=[]; cond=[]
    domain=(sender_email or "").rsplit("@",1)[-1].lower() if "@" in (sender_email or "") else ""
    if domain: cond.append("sender_email LIKE ?"); vals.append("%@"+domain)
    if ip: cond.append("report_json LIKE ?"); vals.append("%"+ip+"%")
    for d in domains or []: cond.append("report_json LIKE ?"); vals.append("%"+d+"%")
    for h in hashes or []: cond.append("report_json LIKE ?"); vals.append("%"+h+"%")
    if not cond: c.close(); return []
    rows=c.execute("SELECT case_id FROM cases WHERE case_id<>? AND ("+" OR ".join(cond)+")",[case_id,*vals]).fetchall(); c.close(); return [r[0] for r in rows]

def alerts(limit=50):
    init_db(); c=connect(); rows=[dict(x) for x in c.execute("SELECT case_id,uploaded_at,sender_email,subject,risk_score,classification,summary,source FROM cases WHERE risk_score>=70 ORDER BY uploaded_at DESC LIMIT ?",(limit,)).fetchall()]; c.close(); return rows

def get_case(case_id, include_raw=False):
    init_db(); c=connect(); row=c.execute('SELECT * FROM cases WHERE case_id=?',(case_id,)).fetchone();
    if not row: c.close(); return None
    data=json.loads(row['report_json']); data['uploaded_at']=row['uploaded_at']; data['evidence_sha256']=row['evidence_sha256'];
    if include_raw and row['raw_email'] is not None: data['raw_email']=row['raw_email'].decode('utf-8','replace')
    c.execute('INSERT INTO audit_log(case_id,actor_role,action,at) VALUES(?,?,?,datetime(\'now\'))',(case_id,'system','case_viewed')); c.commit(); c.close(); return data
