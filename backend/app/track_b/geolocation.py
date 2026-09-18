from __future__ import annotations
import ipaddress, logging
from pathlib import Path
from .config import get_settings
log = logging.getLogger(__name__)

def _fallback(ip=""):
    return {"earliest_external_ip": ip, "country":"Unknown","region":"Unknown","city":"Unknown",
            "latitude":0.0,"longitude":0.0,"isp":"Unknown","asn":"Unknown",
            "is_vpn_or_proxy":False,"is_tor_exit_node":False,"confidence_level":0.0}

def _public(ip):
    try: return ipaddress.ip_address(ip).is_global
    except ValueError: return False

def _city(ip, path):
    try:
        import geoip2.database
        if not Path(path).exists(): return None
        with geoip2.database.Reader(path) as r:
            x=r.city(ip)
            return {"country":x.country.name or "Unknown",
                    "region":(x.subdivisions.most_specific.name if x.subdivisions else None) or "Unknown",
                    "city":x.city.name or "Unknown",
                    "latitude":float(x.location.latitude or 0),
                    "longitude":float(x.location.longitude or 0)}
    except Exception as e:
        log.warning("GeoLite city lookup failed: %s", e); return None

def _asn(ip, path):
    try:
        import geoip2.database
        if not Path(path).exists(): return None
        with geoip2.database.Reader(path) as r:
            x=r.asn(ip)
            return {"isp":x.autonomous_system_organization or "Unknown",
                    "asn":f"AS{x.autonomous_system_number}" if x.autonomous_system_number else "Unknown"}
    except Exception as e:
        log.warning("GeoLite ASN lookup failed: %s", e); return None

def geolocate_origin(received_chain: list) -> dict:
    s=get_settings(); ip=""
    hop_index = 0
    for idx, hop in enumerate(received_chain or []):
        candidate=str(hop.get("ip","")).strip()
        if _public(candidate):
            ip=candidate
            hop_index = idx
            break
    if not ip: return _fallback()
    city=_city(ip,s.geolite_city_db)
    if city is None: return _fallback(ip)
    out=_fallback(ip); out.update(city)
    a=_asn(ip,s.geolite_asn_db)
    if a: out.update(a)
    try:
        from .bgp import lookup_bgp
        bgp=lookup_bgp(ip)
        if bgp.get("asn") != "Unknown": out["bgp"]=bgp
    except Exception: pass
    tor=set()
    p=Path(s.tor_exit_nodes_file)
    if p.exists():
        tor={x.strip() for x in p.read_text(errors="ignore").splitlines() if x.strip() and not x.startswith("#")}
    out["is_tor_exit_node"]=ip in tor
    out["is_vpn_or_proxy"]=out["is_tor_exit_node"]

    # Dynamic, evidence-calibrated origin infrastructure confidence:
    if out["is_tor_exit_node"] or out["is_vpn_or_proxy"]:
        conf = 0.25
    else:
        conf = 0.15
        if out.get("country") and out["country"] != "Unknown":
            conf += 0.25
        if out.get("region") and out["region"] != "Unknown":
            conf += 0.15
        if out.get("city") and out["city"] != "Unknown":
            conf += 0.15
        if out.get("asn") and out["asn"] != "Unknown":
            conf += 0.12
        if out.get("isp") and out["isp"] != "Unknown":
            conf += 0.08
        if hop_index == 0:
            conf += 0.05

    out["confidence_level"] = round(min(0.96, max(0.10, conf)), 2)
    return out
