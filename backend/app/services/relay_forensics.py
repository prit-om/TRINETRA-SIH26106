from __future__ import annotations
from datetime import datetime

def analyze_relay_chain(chain: list[dict]) -> dict:
    hops=[]; anomalies=[]; previous=None
    for idx, hop in enumerate(chain or [], 1):
        item=dict(hop); item["hop"] = idx; item["chronological"] = idx
        ts=hop.get("timestamp")
        parsed=None
        if ts:
            try: parsed=datetime.fromisoformat(ts.replace("Z","+00:00"))
            except Exception: pass
        if parsed and previous and parsed < previous:
            anomalies.append({"type":"time_drift","hop":idx,"message":"Received timestamp moved backwards in chronological order"})
        if parsed: previous=parsed
        if not hop.get("ip"):
            anomalies.append({"type":"missing_ip","hop":idx,"message":"Received hop has no parseable IP"})
        hops.append(item)
    public=[h for h in hops if h.get("ip") and not _private(h["ip"])]
    return {"hop_count":len(hops),"hops":hops,"anomalies":anomalies,"earliest_reliable_public_ip": public[0]["ip"] if public else "","confidence":0.95 if public else 0.2}

def _private(ip):
    import ipaddress
    try: return not ipaddress.ip_address(ip).is_global
    except ValueError: return True
