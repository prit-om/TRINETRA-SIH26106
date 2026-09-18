from __future__ import annotations
import re, socket
from datetime import datetime, timezone
try:
    import dns.resolver
except Exception:
    dns=None

def analyze_domain(domain: str) -> dict:
    d=(domain or '').lower().strip().rstrip('.')
    result={"domain":d,"dns_available":bool(dns),"a_records":[],"mx_records":[],"nameservers":[],"domain_age_days":None,"risk_flags":[]}
    if not d: return result
    if d.startswith('xn--') or '.xn--' in d: result['risk_flags'].append('punycode/homograph candidate')
    labels=d.split('.')
    if len(labels)>=2 and any(len(x)>45 for x in labels): result['risk_flags'].append('unusually long DNS label')
    try:
        result['a_records']=socket.gethostbyname_ex(d)[2]
    except Exception: pass
    if dns:
        for typ,key in [('MX','mx_records'),('NS','nameservers')]:
            try: result[key]=[str(x).rstrip('.') for x in dns.resolve(d,typ)]
            except Exception: pass
    return result

def analyze_domains(domains):
    return [analyze_domain(d) for d in sorted(set(x for x in (domains or []) if x))]
