from __future__ import annotations

import ipaddress
import logging
import re
from email.utils import parseaddr
from pathlib import Path
from .config import get_settings

log = logging.getLogger(__name__)

# =====================================================================
# TIER 4: ccTLD Sovereign Registry & National Jurisdiction Map
# =====================================================================
CCTLD_MAPPINGS: dict[str, dict] = {
    "in": {"country": "India", "region": "Delhi", "city": "New Delhi", "latitude": 28.6139, "longitude": 77.2090, "isp": "National Jurisdiction Registry (.IN)"},
    "pk": {"country": "Pakistan", "region": "Islamabad", "city": "Islamabad", "latitude": 33.6844, "longitude": 73.0479, "isp": "PKNIC ccTLD Registry (.PK)"},
    "bd": {"country": "Bangladesh", "region": "Dhaka", "city": "Dhaka", "latitude": 23.8103, "longitude": 90.4125, "isp": "BTCL ccTLD Registry (.BD)"},
    "np": {"country": "Nepal", "region": "Bagmati", "city": "Kathmandu", "latitude": 27.7172, "longitude": 85.3240, "isp": "Mercantile ccTLD Registry (.NP)"},
    "lk": {"country": "Sri Lanka", "region": "Western", "city": "Colombo", "latitude": 6.9271, "longitude": 79.8612, "isp": "LK Domain Registry (.LK)"},
    "ru": {"country": "Russia", "region": "Moscow", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173, "isp": "Coordination Center for TLD RU (.RU)"},
    "su": {"country": "Russia", "region": "Moscow", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173, "isp": "Soviet Union Legacy ccTLD (.SU)"},
    "uk": {"country": "United Kingdom", "region": "England", "city": "London", "latitude": 51.5074, "longitude": -0.1278, "isp": "Nominet UK (.UK)"},
    "us": {"country": "United States", "region": "District of Columbia", "city": "Washington", "latitude": 38.9072, "longitude": -77.0369, "isp": "Registry Services LLC (.US)"},
    "de": {"country": "Germany", "region": "Berlin", "city": "Berlin", "latitude": 52.5200, "longitude": 13.4050, "isp": "DENIC eG (.DE)"},
    "fr": {"country": "France", "region": "Île-de-France", "city": "Paris", "latitude": 48.8566, "longitude": 2.3522, "isp": "AFNIC (.FR)"},
    "cn": {"country": "China", "region": "Beijing", "city": "Beijing", "latitude": 39.9042, "longitude": 116.4074, "isp": "CNNIC (.CN)"},
    "jp": {"country": "Japan", "region": "Tokyo", "city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503, "isp": "Japan Registry Services (.JP)"},
    "au": {"country": "Australia", "region": "Australian Capital Territory", "city": "Canberra", "latitude": -35.2809, "longitude": 149.1300, "isp": "auDA Registry (.AU)"},
    "ca": {"country": "Canada", "region": "Ontario", "city": "Ottawa", "latitude": 45.4215, "longitude": -75.6972, "isp": "CIRA (.CA Registry)"},
    "sg": {"country": "Singapore", "region": "Singapore", "city": "Singapore", "latitude": 1.3521, "longitude": 103.8198, "isp": "SGNIC (.SG)"},
    "ae": {"country": "United Arab Emirates", "region": "Abu Dhabi", "city": "Abu Dhabi", "latitude": 24.4539, "longitude": 54.3773, "isp": "TRA UAE (.AE)"},
    "ng": {"country": "Nigeria", "region": "Federal Capital Territory", "city": "Abuja", "latitude": 9.0765, "longitude": 7.3986, "isp": "NiRA (.NG Registry)"},
    "br": {"country": "Brazil", "region": "Federal District", "city": "Brasília", "latitude": -15.8267, "longitude": -47.9218, "isp": "Registro.br (.BR)"},
    "za": {"country": "South Africa", "region": "Gauteng", "city": "Pretoria", "latitude": -25.7479, "longitude": 28.2293, "isp": "ZADNA (.ZA)"},
    "nl": {"country": "Netherlands", "region": "North Holland", "city": "Amsterdam", "latitude": 52.3676, "longitude": 4.9041, "isp": "SIDN (.NL)"},
    "ch": {"country": "Switzerland", "region": "Bern", "city": "Bern", "latitude": 46.9480, "longitude": 7.4474, "isp": "SWITCH (.CH)"},
    "se": {"country": "Sweden", "region": "Stockholm", "city": "Stockholm", "latitude": 59.3293, "longitude": 18.0686, "isp": "Internetstiftelsen (.SE)"},
    "it": {"country": "Italy", "region": "Lazio", "city": "Rome", "latitude": 41.9028, "longitude": 12.4964, "isp": "Registro.it (.IT)"},
    "es": {"country": "Spain", "region": "Madrid", "city": "Madrid", "latitude": 40.4168, "longitude": -3.7038, "isp": "Red.es (.ES)"},
    "ir": {"country": "Iran", "region": "Tehran", "city": "Tehran", "latitude": 35.6892, "longitude": 51.3890, "isp": "IRNIC (.IR)"},
    "my": {"country": "Malaysia", "region": "Federal Territory", "city": "Kuala Lumpur", "latitude": 3.1390, "longitude": 101.6869, "isp": "MYNIC Berhad (.MY)"},
    "id": {"country": "Indonesia", "region": "Jakarta", "city": "Jakarta", "latitude": -6.2088, "longitude": 106.8456, "isp": "PANDI (.ID)"},
    "th": {"country": "Thailand", "region": "Bangkok", "city": "Bangkok", "latitude": 13.7563, "longitude": 100.5018, "isp": "THNIC (.TH)"},
    "vn": {"country": "Vietnam", "region": "Hanoi", "city": "Hanoi", "latitude": 21.0285, "longitude": 105.8542, "isp": "VNNIC (.VN)"},
    "ph": {"country": "Philippines", "region": "Metro Manila", "city": "Manila", "latitude": 14.5995, "longitude": 120.9842, "isp": "DotPH (.PH)"},
}

# =====================================================================
# TIER 5: Regional / Country-Specific Webmail Providers
# =====================================================================
REGIONAL_WEBMAIL_PROVIDERS: dict[str, dict] = {
    "rediffmail.com": {"country": "India", "region": "Maharashtra", "city": "Mumbai", "latitude": 19.0760, "longitude": 72.8777, "isp": "Rediff.com India Limited"},
    "sify.com": {"country": "India", "region": "Tamil Nadu", "city": "Chennai", "latitude": 13.0827, "longitude": 80.2707, "isp": "Sify Technologies Limited"},
    "mail.ru": {"country": "Russia", "region": "Moscow", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173, "isp": "VK / Mail.Ru LLC"},
    "yandex.ru": {"country": "Russia", "region": "Moscow", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173, "isp": "Yandex LLC"},
    "yandex.com": {"country": "Russia", "region": "Moscow", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173, "isp": "Yandex LLC"},
    "bk.ru": {"country": "Russia", "region": "Moscow", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173, "isp": "VK / Mail.Ru LLC"},
    "inbox.ru": {"country": "Russia", "region": "Moscow", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173, "isp": "VK / Mail.Ru LLC"},
    "list.ru": {"country": "Russia", "region": "Moscow", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173, "isp": "VK / Mail.Ru LLC"},
    "qq.com": {"country": "China", "region": "Guangdong", "city": "Shenzhen", "latitude": 22.5431, "longitude": 114.0579, "isp": "Tencent Holdings Ltd"},
    "163.com": {"country": "China", "region": "Zhejiang", "city": "Hangzhou", "latitude": 30.2741, "longitude": 120.1551, "isp": "NetEase Inc"},
    "126.com": {"country": "China", "region": "Zhejiang", "city": "Hangzhou", "latitude": 30.2741, "longitude": 120.1551, "isp": "NetEase Inc"},
    "sina.com": {"country": "China", "region": "Beijing", "city": "Beijing", "latitude": 39.9042, "longitude": 116.4074, "isp": "Sina Corp"},
    "naver.com": {"country": "South Korea", "region": "Gyeonggi-do", "city": "Seongnam", "latitude": 37.4449, "longitude": 127.1388, "isp": "NAVER Corp"},
    "daum.net": {"country": "South Korea", "region": "Jeju", "city": "Jeju", "latitude": 33.4996, "longitude": 126.5312, "isp": "Kakao Corp"},
    "web.de": {"country": "Germany", "region": "Rhineland-Palatinate", "city": "Montabaur", "latitude": 50.4367, "longitude": 7.8286, "isp": "1&1 Mail & Media GmbH"},
    "gmx.de": {"country": "Germany", "region": "Rhineland-Palatinate", "city": "Montabaur", "latitude": 50.4367, "longitude": 7.8286, "isp": "1&1 Mail & Media GmbH"},
    "gmx.net": {"country": "Germany", "region": "Rhineland-Palatinate", "city": "Montabaur", "latitude": 50.4367, "longitude": 7.8286, "isp": "1&1 Mail & Media GmbH"},
    "orange.fr": {"country": "France", "region": "Île-de-France", "city": "Paris", "latitude": 48.8566, "longitude": 2.3522, "isp": "Orange SA"},
    "laposte.net": {"country": "France", "region": "Île-de-France", "city": "Paris", "latitude": 48.8566, "longitude": 2.3522, "isp": "La Poste Group"},
}

# =====================================================================
# TIER 3: Client Machine Timezone Offset Leaks (RFC 5322 Date: ±HHMM)
# =====================================================================
TIMEZONE_REGIONS_GEO: dict[str, dict] = {
    "+0530": {"country": "India", "region": "South Asia", "city": "New Delhi (IST)", "latitude": 28.6139, "longitude": 77.2090, "isp": "Indian Standard Time (+0530)", "confidence": 0.65},
    "+0545": {"country": "Nepal", "region": "Bagmati", "city": "Kathmandu", "latitude": 27.7172, "longitude": 85.3240, "isp": "Nepal Standard Time (+0545)", "confidence": 0.65},
    "+0600": {"country": "Bangladesh", "region": "Dhaka", "city": "Dhaka", "latitude": 23.8103, "longitude": 90.4125, "isp": "Bangladesh Standard Time (+0600)", "confidence": 0.60},
    "+0500": {"country": "Pakistan", "region": "Islamabad", "city": "Islamabad", "latitude": 33.6844, "longitude": 73.0479, "isp": "Pakistan / West Asia (+0500)", "confidence": 0.60},
    "+0300": {"country": "Russia", "region": "Moscow", "city": "Moscow (MSK)", "latitude": 55.7558, "longitude": 37.6173, "isp": "Moscow Time / East Africa (+0300)", "confidence": 0.60},
    "+0200": {"country": "Egypt", "region": "Cairo", "city": "Cairo (EET)", "latitude": 30.0444, "longitude": 31.2357, "isp": "Eastern European Time (+0200)", "confidence": 0.55},
    "+0100": {"country": "Germany", "region": "Berlin", "city": "Berlin (CET)", "latitude": 52.5200, "longitude": 13.4050, "isp": "Central European Time (+0100)", "confidence": 0.55},
    "+0000": {"country": "United Kingdom", "region": "London", "city": "London (GMT/UTC)", "latitude": 51.5074, "longitude": -0.1278, "isp": "Greenwich Mean Time (+0000)", "confidence": 0.55},
    "-0400": {"country": "United States", "region": "New York", "city": "New York (EDT)", "latitude": 40.7128, "longitude": -74.0060, "isp": "Eastern Daylight Time (-0400)", "confidence": 0.55},
    "-0500": {"country": "United States", "region": "New York", "city": "New York (EST)", "latitude": 40.7128, "longitude": -74.0060, "isp": "Eastern Standard Time (-0500)", "confidence": 0.55},
    "-0600": {"country": "United States", "region": "Illinois", "city": "Chicago (CST)", "latitude": 41.8781, "longitude": -87.6298, "isp": "Central Standard Time (-0600)", "confidence": 0.55},
    "-0700": {"country": "United States", "region": "Colorado", "city": "Denver (MST)", "latitude": 39.7392, "longitude": -104.9903, "isp": "Mountain Standard Time (-0700)", "confidence": 0.55},
    "-0800": {"country": "United States", "region": "California", "city": "San Francisco (PST)", "latitude": 37.7749, "longitude": -122.4194, "isp": "Pacific Standard Time (-0800)", "confidence": 0.55},
    "+0800": {"country": "Singapore", "region": "Singapore", "city": "Singapore (SGT/CST)", "latitude": 1.3521, "longitude": 103.8198, "isp": "Singapore / China Standard Time (+0800)", "confidence": 0.60},
    "+0900": {"country": "Japan", "region": "Tokyo", "city": "Tokyo (JST)", "latitude": 35.6762, "longitude": 139.6503, "isp": "Japan Standard Time (+0900)", "confidence": 0.60},
    "+1000": {"country": "Australia", "region": "New South Wales", "city": "Sydney (AEST)", "latitude": -33.8688, "longitude": 151.2093, "isp": "Australian Eastern Standard Time (+1000)", "confidence": 0.60},
}

# =====================================================================
# TIER 6: Indic / Regional Script Context Corroboration
# =====================================================================
INDIC_SCRIPTS_RE = re.compile(
    r'[\u0900-\u097F\u0980-\u09FF\u0A00-\u0A7F\u0A80-\u0AFF\u0B00-\u0B7F\u0B80-\u0BFF\u0C00-\u0C7F\u0C80-\u0CFF\u0D00-\u0D7F]'
)
INDIC_KEYWORDS_RE = re.compile(
    r'(?i)\b(rbi|sbi|aadhaar|pan\s*card|neft|rtgs|imps|lakh|crore|cbi|mumbai\s*police|delhi\s*police|inr|₹)\b'
)


# =====================================================================
# TIER 7: Global Mail Hub Infrastructure Baseline
# =====================================================================
GLOBAL_MAIL_PROVIDERS: dict[str, dict] = {
    "gmail.com": {"country": "United States", "region": "California", "city": "Mountain View (Google Hub)", "latitude": 37.4220, "longitude": -122.0841, "isp": "Google LLC", "asn": "AS15169", "confidence": 0.50},
    "googlemail.com": {"country": "United States", "region": "California", "city": "Mountain View (Google Hub)", "latitude": 37.4220, "longitude": -122.0841, "isp": "Google LLC", "asn": "AS15169", "confidence": 0.50},
    "outlook.com": {"country": "United States", "region": "Washington", "city": "Redmond (Microsoft 365)", "latitude": 47.6740, "longitude": -122.1215, "isp": "Microsoft Corporation", "asn": "AS8075", "confidence": 0.50},
    "hotmail.com": {"country": "United States", "region": "Washington", "city": "Redmond (Microsoft 365)", "latitude": 47.6740, "longitude": -122.1215, "isp": "Microsoft Corporation", "asn": "AS8075", "confidence": 0.50},
    "yahoo.com": {"country": "United States", "region": "California", "city": "Sunnyvale (Yahoo)", "latitude": 37.4241, "longitude": -122.0068, "isp": "Yahoo! Inc.", "asn": "AS10310", "confidence": 0.50},
    "icloud.com": {"country": "United States", "region": "California", "city": "Cupertino (Apple iCloud)", "latitude": 37.3230, "longitude": -122.0322, "isp": "Apple Inc.", "asn": "AS714", "confidence": 0.50},
}


def _fallback(ip: str = "") -> dict:
    return {
        "earliest_external_ip": ip,
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0,
        "isp": "Unknown",
        "asn": "Unknown",
        "is_vpn_or_proxy": False,
        "is_tor_exit_node": False,
        "confidence_level": 0.0,
        "resolution_method": "unknown_no_indicators",
        "resolution_source": "No public indicators found",
    }


def _public(ip: str) -> bool:
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


def _city(ip: str, path: str) -> dict | None:
    try:
        import geoip2.database
        if not Path(path).exists():
            return None
        with geoip2.database.Reader(path) as r:
            x = r.city(ip)
            country = x.country.name or "Unknown"
            subdiv = (x.subdivisions.most_specific.name if x.subdivisions else None) or "Unknown"
            city = x.city.name or (subdiv if subdiv != "Unknown" else country)
            lat = float(x.location.latitude or 0)
            lng = float(x.location.longitude or 0)
            if country == "Unknown" and lat == 0.0 and lng == 0.0:
                return None
            return {
                "country": country,
                "region": subdiv,
                "city": city,
                "latitude": lat,
                "longitude": lng,
            }
    except Exception as e:
        log.debug("GeoLite city lookup failed: %s", e)
        return None


def _asn(ip: str, path: str) -> dict | None:
    try:
        import geoip2.database
        if not Path(path).exists():
            return None
        with geoip2.database.Reader(path) as r:
            x = r.asn(ip)
            return {
                "isp": x.autonomous_system_organization or "Unknown",
                "asn": f"AS{x.autonomous_system_number}" if x.autonomous_system_number else "Unknown",
            }
    except Exception as e:
        log.debug("GeoLite ASN lookup failed: %s", e)
        return None


def _extract_domain(addr_or_domain: str) -> str:
    """Extract clean lowercased domain from an email address or domain string."""
    addr = str(addr_or_domain or "").strip()
    if not addr:
        return ""
    if "@" in addr:
        _, email_addr = parseaddr(addr)
        if "@" in email_addr:
            return email_addr.rsplit("@", 1)[1].lower().strip().rstrip(".")
    return addr.lower().strip().rstrip(".")


# =====================================================================
# TIER 2 RESOLVER: Sender Domain Mail Infrastructure (MX / A DNS)
# =====================================================================
def _resolve_domain_infrastructure(domain: str, city_db: str, asn_db: str) -> dict | None:
    """
    Resolve Mail Exchanger (MX) or DNS A record for the sender domain.
    Lookup resolved IP in MaxMind GeoLite2 City & ASN databases.
    """
    clean_domain = _extract_domain(domain)
    # Skip huge multinational webmail domains that use global Anycast networks without localized sender mapping
    if not clean_domain or clean_domain in {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "icloud.com"}:
        return None

    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 1.0
        resolver.timeout = 0.8

        target_ips: list[str] = []

        # 1. Attempt MX lookup
        try:
            answers = resolver.resolve(clean_domain, "MX")
            for rdata in answers:
                mx_host = str(rdata.exchange).rstrip(".")
                try:
                    a_answers = resolver.resolve(mx_host, "A")
                    for a in a_answers:
                        cand_ip = str(a).strip()
                        if _public(cand_ip):
                            target_ips.append(cand_ip)
                            break
                except Exception:
                    pass
                if target_ips:
                    break
        except Exception:
            pass

        # 2. Fallback to direct domain A-record
        if not target_ips:
            try:
                a_answers = resolver.resolve(clean_domain, "A")
                for a in a_answers:
                    cand_ip = str(a).strip()
                    if _public(cand_ip):
                        target_ips.append(cand_ip)
                        break
            except Exception:
                pass

        for ip_cand in target_ips:
            city_res = _city(ip_cand, city_db)
            if city_res and (city_res.get("latitude") != 0.0 or city_res.get("country") != "Unknown"):
                asn_res = _asn(ip_cand, asn_db) or {}
                return {
                    "earliest_external_ip": f"Domain MX: {ip_cand}",
                    **city_res,
                    "isp": asn_res.get("isp", f"{clean_domain} Mail Infrastructure"),
                    "asn": asn_res.get("asn", "Unknown"),
                    "confidence_level": 0.75,
                    "resolution_method": "domain_infrastructure",
                    "resolution_source": f"Sender Domain MX/A Infrastructure ({clean_domain})",
                    "is_vpn_or_proxy": False,
                    "is_tor_exit_node": False,
                }
    except Exception as exc:
        log.debug("Domain infrastructure lookup failed for %s: %s", clean_domain, exc)

    return None


# =====================================================================
# TIER 3 RESOLVER: Client Timezone Clock Offset Leak
# =====================================================================
def _resolve_client_timezone(date_val: str) -> dict | None:
    """Extract ±HHMM from Date: header or Received timestamps."""
    raw_str = str(date_val or "")
    m = re.search(r'([+-]\d{4})', raw_str)
    if not m:
        return None
    offset = m.group(1)
    if offset in TIMEZONE_REGIONS_GEO:
        data = TIMEZONE_REGIONS_GEO[offset]
        return {
            "earliest_external_ip": f"Client Clock Leak ({offset})",
            "country": data["country"],
            "region": data["region"],
            "city": data["city"],
            "latitude": data["latitude"],
            "longitude": data["longitude"],
            "isp": data["isp"],
            "asn": f"UTC{offset[:3]}:{offset[3:]}",
            "confidence_level": data["confidence"],
            "resolution_method": "client_clock_timezone",
            "resolution_source": f"Client Timezone Offset ({offset} IST/Regional)",
            "is_vpn_or_proxy": False,
            "is_tor_exit_node": False,
        }
    return None


# =====================================================================
# TIER 4 RESOLVER: Country-Code Top-Level Domain (ccTLD)
# =====================================================================
def _resolve_cctld(domain_or_email: str) -> dict | None:
    clean_domain = _extract_domain(domain_or_email)
    if not clean_domain or "." not in clean_domain:
        return None

    parts = clean_domain.split(".")
    # Test multi-part ccTLDs (.co.in, .gov.in, .ac.uk, .com.pk)
    tld = parts[-1].lower()
    if tld in CCTLD_MAPPINGS:
        data = CCTLD_MAPPINGS[tld]
        return {
            "earliest_external_ip": f"ccTLD: .{tld.upper()}",
            "country": data["country"],
            "region": data["region"],
            "city": data["city"],
            "latitude": data["latitude"],
            "longitude": data["longitude"],
            "isp": data["isp"],
            "asn": f"ccTLD-{tld.upper()}",
            "confidence_level": 0.58,
            "resolution_method": "cctld_jurisdiction",
            "resolution_source": f"Sovereign ccTLD Jurisdiction (.{tld})",
            "is_vpn_or_proxy": False,
            "is_tor_exit_node": False,
        }
    return None


# =====================================================================
# TIER 5 RESOLVER: Regional Webmail Provider Origin
# =====================================================================
def _resolve_webmail_provider(domain_or_email: str) -> dict | None:
    clean_domain = _extract_domain(domain_or_email)
    if clean_domain in REGIONAL_WEBMAIL_PROVIDERS:
        data = REGIONAL_WEBMAIL_PROVIDERS[clean_domain]
        return {
            "earliest_external_ip": f"Provider: {clean_domain}",
            "country": data["country"],
            "region": data["region"],
            "city": data["city"],
            "latitude": data["latitude"],
            "longitude": data["longitude"],
            "isp": data["isp"],
            "asn": "PROVIDER-HOSTED",
            "confidence_level": 0.52,
            "resolution_method": "webmail_provider_origin",
            "resolution_source": f"Regional Webmail Provider Headquarters ({clean_domain})",
            "is_vpn_or_proxy": False,
            "is_tor_exit_node": False,
        }
    return None


# =====================================================================
# TIER 6 RESOLVER: Indic / Regional Linguistic Context
# =====================================================================
def _resolve_indic_linguistic(body_text: str) -> dict | None:
    text = str(body_text or "")
    has_script = bool(INDIC_SCRIPTS_RE.search(text))
    has_keywords = bool(INDIC_KEYWORDS_RE.search(text))
    if has_script or has_keywords:
        return {
            "earliest_external_ip": "Content Corroboration",
            "country": "India",
            "region": "National Jurisdiction",
            "city": "New Delhi (Indic Context)",
            "latitude": 28.6139,
            "longitude": 77.2090,
            "isp": "Indic Multi-Script Regional Corroboration",
            "asn": "IN-CONTENT",
            "confidence_level": 0.45,
            "resolution_method": "indic_linguistic",
            "resolution_source": "Indic Regional Script & Entity Linguistic Evidence",
            "is_vpn_or_proxy": False,
            "is_tor_exit_node": False,
        }
    return None


# =====================================================================
# UNIVERSAL 7-TIER HIERARCHICAL GEOLOCATION CASCADE
# =====================================================================
def geolocate_origin(
    received_chain: list | None = None,
    client_ip: str = "",
    sender_email: str = "",
    headers: dict | None = None,
    sender_domain: str = "",
    body_text: str = "",
) -> dict:
    """
    Universal 7-Tier Sender Geolocation Engine:
      Tier 1: Direct Network Header Forensics (Hop-0 / client-ip)
      Tier 2: Sender Domain Mail Infrastructure (MX / A-record lookup)
      Tier 3: Client Machine Timezone Offset Leaks (RFC 5322 Date: ±HHMM)
      Tier 4: Country-Code Top-Level Domain (ccTLD) Jurisdiction
      Tier 5: Regional Webmail Provider Origin
      Tier 6: Indic / Regional Script Context Corroboration
      Tier 7: Global Mail Hub Infrastructure Baseline (Zero-Blank Fallback)
    """
    s = get_settings()
    received_chain = received_chain or []
    headers = headers or {}
    domain = sender_domain or _extract_domain(sender_email) or ""
    date_val = str(headers.get("Date") or headers.get("date") or "")

    # -------------------------------------------------------------
    # TIER 1: Direct Network Hop-0 / Client-IP
    # -------------------------------------------------------------
    candidate_ips: list[tuple[str, int]] = []
    c_ip = str(client_ip or "").strip()
    if c_ip and _public(c_ip):
        candidate_ips.append((c_ip, 0))

    for idx, hop in enumerate(received_chain):
        cand = str(hop.get("ip", "")).strip()
        if cand and _public(cand) and not any(cand == c[0] for c in candidate_ips):
            candidate_ips.append((cand, idx))

    if not candidate_ips:
        if c_ip:
            try:
                if ipaddress.ip_address(c_ip).is_global:
                    candidate_ips.append((c_ip, 0))
            except ValueError:
                pass
        for idx, hop in enumerate(received_chain):
            cand = str(hop.get("ip", "")).strip()
            try:
                if cand and ipaddress.ip_address(cand).is_global and not any(cand == c[0] for c in candidate_ips):
                    candidate_ips.append((cand, idx))
            except ValueError:
                pass

    best_city = None
    chosen_ip = ""
    hop_index = 0

    if candidate_ips:
        chosen_ip = candidate_ips[0][0]
        hop_index = candidate_ips[0][1]
        for cand, h_idx in candidate_ips:
            city_res = _city(cand, s.geolite_city_db)
            if city_res and (city_res.get("latitude") != 0.0 or city_res.get("country") != "Unknown"):
                chosen_ip = cand
                hop_index = h_idx
                best_city = city_res
                break

    if best_city is not None:
        out = {
            "earliest_external_ip": chosen_ip,
            **best_city,
            "resolution_method": "hop0_client_ip",
            "resolution_source": f"Direct Network Hop-0 Forensics ({chosen_ip})",
        }
        asn_res = _asn(chosen_ip, s.geolite_asn_db)
        if asn_res:
            out.update(asn_res)
        else:
            out["isp"] = "Unknown"
            out["asn"] = "Unknown"

        try:
            from .bgp import lookup_bgp
            bgp = lookup_bgp(chosen_ip)
            if bgp.get("asn") != "Unknown":
                out["bgp"] = bgp
        except Exception:
            pass

        tor_file = Path(s.tor_exit_nodes_file)
        tor_nodes = set()
        if tor_file.exists():
            tor_nodes = {x.strip() for x in tor_file.read_text(errors="ignore").splitlines() if x.strip() and not x.startswith("#")}
        out["is_tor_exit_node"] = chosen_ip in tor_nodes
        out["is_vpn_or_proxy"] = out["is_tor_exit_node"]

        # Calibrate confidence level
        conf = 0.20
        if out.get("country") and out["country"] != "Unknown": conf += 0.25
        if out.get("region") and out["region"] != "Unknown": conf += 0.15
        if out.get("city") and out["city"] != "Unknown": conf += 0.15
        if out.get("asn") and out["asn"] != "Unknown": conf += 0.10
        if out.get("isp") and out["isp"] != "Unknown": conf += 0.05
        if hop_index == 0: conf += 0.05
        out["confidence_level"] = round(min(0.96, max(0.20, conf)), 2)
        return out

    # -------------------------------------------------------------
    # TIER 2: Sender Domain Mail Infrastructure (MX / A DNS)
    # -------------------------------------------------------------
    domain_result = _resolve_domain_infrastructure(domain, s.geolite_city_db, s.geolite_asn_db)
    if domain_result:
        return domain_result

    # -------------------------------------------------------------
    # TIER 3: Client Timezone Clock Offset Leak (RFC 5322 Date:)
    # -------------------------------------------------------------
    tz_result = _resolve_client_timezone(date_val)
    if tz_result:
        return tz_result

    # -------------------------------------------------------------
    # TIER 4: Country-Code Top-Level Domain (ccTLD) Jurisdiction
    # -------------------------------------------------------------
    cctld_result = _resolve_cctld(domain)
    if cctld_result:
        return cctld_result

    # -------------------------------------------------------------
    # TIER 5: Regional Webmail Provider Origin
    # -------------------------------------------------------------
    webmail_result = _resolve_webmail_provider(domain)
    if webmail_result:
        return webmail_result

    # -------------------------------------------------------------
    # TIER 6: Indic / Regional Linguistic Context Corroboration
    # -------------------------------------------------------------
    indic_result = _resolve_indic_linguistic(body_text)
    if indic_result:
        return indic_result

    # -------------------------------------------------------------
    # TIER 7: Global Mail Hub Baseline (Zero Blank Fallback)
    # -------------------------------------------------------------
    if domain in GLOBAL_MAIL_PROVIDERS:
        data = GLOBAL_MAIL_PROVIDERS[domain]
        return {
            "earliest_external_ip": f"Global Hub: {domain}",
            "country": data["country"],
            "region": data["region"],
            "city": data["city"],
            "latitude": data["latitude"],
            "longitude": data["longitude"],
            "isp": data["isp"],
            "asn": data["asn"],
            "confidence_level": data["confidence"],
            "resolution_method": "global_mail_provider_hub",
            "resolution_source": f"Global Webmail Infrastructure ({domain})",
            "is_vpn_or_proxy": False,
            "is_tor_exit_node": False,
        }

    return _fallback(chosen_ip)
