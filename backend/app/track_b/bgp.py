from __future__ import annotations
import ipaddress
try:
    import dns.resolver
except Exception: dns=None

def lookup_bgp(ip:str)->dict:
    out={'asn':'Unknown','prefix':'Unknown','registry':'Unknown','bgp_source':'Team Cymru DNS'}
    if not dns or not ip: return out
    try:
        addr=ipaddress.ip_address(ip)
        if addr.version!=4: return out
        rev='.'.join(reversed(ip.split('.')))+'.origin.asn.cymru.com'
        r = dns.resolver.Resolver()
        r.lifetime = 0.8
        r.timeout = 0.6
        txt=' '.join(str(ans) for ans in r.resolve(rev,'TXT', lifetime=0.8))
        # TXT format: "ASN | prefix | country | registry | allocated"
        parts=[x.strip() for x in txt.replace('"','').split('|')]
        if len(parts)>=4:
            out.update({'asn':('AS'+parts[0]) if parts[0] and not parts[0].startswith('AS') else parts[0],'prefix':parts[1],'registry':parts[3]})
    except Exception: pass
    return out
