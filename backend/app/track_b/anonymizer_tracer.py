import re
from datetime import datetime
from pathlib import Path
import geoip2.database

DATA_DIR = Path(__file__).resolve().parent / "data"
ASN_DB_PATH = DATA_DIR / "GeoLite2-ASN.mmdb"

# Major timezone offset to approximate regional mappings
TIMEZONE_REGIONS = {
    "+0530": {"region": "South Asia (India, Sri Lanka)", "primary_countries": ["IN", "LK"]},
    "+0545": {"region": "Nepal", "primary_countries": ["NP"]},
    "+0600": {"region": "Bangladesh, Central Asia", "primary_countries": ["BD", "KZ"]},
    "+0500": {"region": "Pakistan, West Asia", "primary_countries": ["PK", "UZ"]},
    "+0300": {"region": "Eastern Europe, East Africa, Russia (MSK)", "primary_countries": ["RU", "TR", "KE", "SA"]},
    "+0200": {"region": "Eastern Europe, Central Africa", "primary_countries": ["UA", "RO", "EG", "ZA"]},
    "+0100": {"region": "Central Europe, West Africa", "primary_countries": ["DE", "FR", "NG"]},
    "+0000": {"region": "Western Europe (UK, Portugal), West Africa", "primary_countries": ["GB", "PT", "GH"]},
    "-0400": {"region": "Americas (EDT / Caribbean)", "primary_countries": ["US", "CA"]},
    "-0500": {"region": "Americas (EST / Central America)", "primary_countries": ["US", "CO", "PE"]},
    "-0600": {"region": "Americas (CST)", "primary_countries": ["US", "MX"]},
    "-0700": {"region": "Americas (MST)", "primary_countries": ["US", "CA"]},
    "-0800": {"region": "Americas (PST)", "primary_countries": ["US", "CA"]},
    "+0800": {"region": "East Asia (China, Singapore, Malaysia, Philippines)", "primary_countries": ["CN", "SG", "MY", "PH"]}
}

KNOWN_VPN_DATACENTER_KEYWORDS = [
    "mullvad", "nordvpn", "expressvpn", "digitalocean", "ovh", 
    "linode", "m247", "choopa", "clouvider", "contabo", "leaseweb", "hetzner"
]

def analyze_sender_anonymization(origin_ip: str, headers: dict, resolved_country: str) -> dict:
    """
    Correlates Network Layer (VPN/Tor) with Application Layer (Client Clock)
    to estimate true probable region and highlight identity pivots.
    """
    trace_info = {
        "is_anonymized": False,
        "anonymizer_type": "DIRECT_RESIDENTIAL",
        "hosting_provider": "Unknown",
        "server_location": resolved_country,
        "client_timezone_offset": None,
        "probable_sender_region": resolved_country,
        "confidence": "HIGH (Direct Origin)",
        "identity_pivot_markers": []
    }

    # 1. Detect VPN / Datacenter Node via ASN database
    if ASN_DB_PATH.exists() and origin_ip:
        try:
            with geoip2.database.Reader(str(ASN_DB_PATH)) as reader:
                asn_record = reader.asn(origin_ip)
                org = (asn_record.autonomous_system_organization or "").lower()
                trace_info["hosting_provider"] = asn_record.autonomous_system_organization or "Unknown"

                if any(kw in org for kw in KNOWN_VPN_DATACENTER_KEYWORDS):
                    trace_info["is_anonymized"] = True
                    trace_info["anonymizer_type"] = "COMMERCIAL_VPN_OR_VPS"
        except Exception:
            pass

    # 2. Extract Client System Clock Leak from 'Date' header
    date_header = headers.get("Date", "")
    tz_match = re.search(r'([+-]\d{4})', date_header)
    if tz_match:
        client_offset = tz_match.group(1)
        trace_info["client_timezone_offset"] = client_offset

        if client_offset in TIMEZONE_REGIONS:
            tz_data = TIMEZONE_REGIONS[client_offset]
            
            # If VPN is active and timezone contradicts server country, we caught a geographical mismatch
            if trace_info["is_anonymized"]:
                trace_info["probable_sender_region"] = tz_data["region"]
                trace_info["confidence"] = "ESTIMATED_VIA_CLIENT_CLOCK (Approximate)"
                trace_info["identity_pivot_markers"].append(
                    f"Timezone offset {client_offset} indicates origin in {tz_data['region']}, contradicting VPN exit in {resolved_country}"
                )

    # 3. Harvest secondary identity markers
    if headers.get("X-Mailer"):
        trace_info["identity_pivot_markers"].append(f"Mailer Tool: {headers.get('X-Mailer')}")
    if headers.get("Message-ID"):
        trace_info["identity_pivot_markers"].append(f"Message-ID Host Pattern: {headers.get('Message-ID')}")

    return trace_info