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
    try:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global or addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local:
            return False
        if addr.version == 6:
            if addr in ipaddress.ip_network("2002::/16") or addr in ipaddress.ip_network("2001:0::/32"):
                return False
        return True
    except ValueError:
        return False

def _city(ip, path):
    try:
        import geoip2.database
        if not Path(path).exists(): return None
        with geoip2.database.Reader(path) as r:
            x = r.city(ip)
            country = x.country.name or "Unknown"
            subdiv = (x.subdivisions.most_specific.name if x.subdivisions else None) or "Unknown"
            city = x.city.name or (subdiv if subdiv != "Unknown" else country)
            lat = float(x.location.latitude or 0)
            lng = float(x.location.longitude or 0)
            if country == "Unknown" and lat == 0.0 and lng == 0.0:
                return None
            return {"country": country,
                    "region": subdiv,
                    "city": city,
                    "latitude": lat,
                    "longitude": lng}
    except Exception as e:
        log.warning("GeoLite city lookup failed: %s", e)
        return None

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

def geolocate_origin(received_chain: list, client_ip: str = "") -> dict:
    s = get_settings()
    candidate_ips: list[tuple[str, int]] = []
    
    # 1. Authentic client-ip from Received-SPF / Authentication-Results
    c_ip = str(client_ip or "").strip()
    if c_ip and _public(c_ip):
        candidate_ips.append((c_ip, 0))

    # 2. Public IPs from Received chain
    for idx, hop in enumerate(received_chain or []):
        cand = str(hop.get("ip", "")).strip()
        if cand and _public(cand) and not any(cand == c[0] for c in candidate_ips):
            candidate_ips.append((cand, idx))

    # 3. Fallback: if no strict public IP passed, check any global IP
    if not candidate_ips:
        if c_ip:
            try:
                if ipaddress.ip_address(c_ip).is_global:
                    candidate_ips.append((c_ip, 0))
            except ValueError:
                pass
        for idx, hop in enumerate(received_chain or []):
            cand = str(hop.get("ip", "")).strip()
            try:
                if cand and ipaddress.ip_address(cand).is_global and not any(cand == c[0] for c in candidate_ips):
                    candidate_ips.append((cand, idx))
            except ValueError:
                pass

    if not candidate_ips:
        return _fallback()

    chosen_ip = candidate_ips[0][0]
    hop_index = candidate_ips[0][1]
    best_city = None

    # Iterate through candidates to find the one with valid GeoLite2 coordinates
    for cand, h_idx in candidate_ips:
        city_res = _city(cand, s.geolite_city_db)
        if city_res and (city_res.get("latitude") != 0.0 or city_res.get("country") != "Unknown"):
            chosen_ip = cand
            hop_index = h_idx
            best_city = city_res
            break

    if best_city is None:
        return _fallback(chosen_ip)

    out = _fallback(chosen_ip)
    out.update(best_city)
    a = _asn(chosen_ip, s.geolite_asn_db)
    if a:
        out.update(a)

    try:
        from .bgp import lookup_bgp
        bgp = lookup_bgp(chosen_ip)
        if bgp.get("asn") != "Unknown":
            out["bgp"] = bgp
    except Exception:
        pass

    tor = set()
    p = Path(s.tor_exit_nodes_file)
    if p.exists():
        tor = {x.strip() for x in p.read_text(errors="ignore").splitlines() if x.strip() and not x.startswith("#")}
    out["is_tor_exit_node"] = chosen_ip in tor
    out["is_vpn_or_proxy"] = out["is_tor_exit_node"]

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

