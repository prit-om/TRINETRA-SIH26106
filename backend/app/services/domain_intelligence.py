from __future__ import annotations
import re, socket
from datetime import datetime, timezone
try:
    import dns.resolver
except Exception:
    dns=None

from concurrent.futures import ThreadPoolExecutor

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
        try:
            r = dns.resolver.Resolver()
            r.lifetime = 0.8
            r.timeout = 0.6
            for typ,key in [('MX','mx_records'),('NS','nameservers')]:
                try: result[key]=[str(x).rstrip('.') for x in r.resolve(d, typ, lifetime=0.8)]
                except Exception: pass
        except Exception: pass
    return result

def analyze_domains(domains):
    unique = sorted(set(x for x in (domains or []) if x))[:4]
    if not unique:
        return []
    with ThreadPoolExecutor(max_workers=min(4, len(unique))) as executor:
        return list(executor.map(analyze_domain, unique))

