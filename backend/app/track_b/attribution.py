from __future__ import annotations

def score_attribution(header, geolocation, url_findings, related_case_count=0, graph=None):
    h=header or {}; g=geolocation or {}; urls=url_findings or []
    score=0; reasons=[]
    if related_case_count: score+=min(35,10+10*min(related_case_count,3)); reasons.append(f'{related_case_count} prior related case(s)')
    if g.get('is_tor_exit_node'): score+=20; reasons.append('origin matches Tor-exit intelligence')
    if g.get('is_vpn_or_proxy'): score+=10; reasons.append('origin uses VPN/proxy infrastructure')
    if any(u.get('is_malicious') for u in urls): score+=25; reasons.append('known-malicious URL reputation')
    if any(u.get('is_lookalike_domain') for u in urls): score+=15; reasons.append('lookalike domain infrastructure')
    if h.get('sender_returnpath_mismatch') or h.get('replyto_anomaly'): score+=10; reasons.append('sender routing identity anomaly')
    score=min(100,score)
    if score>=70: cluster='targeted BEC / known criminal cluster'
    elif score>=40: cluster='opportunistic coordinated campaign'
    else: cluster='opportunistic / unclustered activity'
    return {'confidence':score,'cluster_type':cluster,'reasons':reasons or ['insufficient cross-case evidence'],'method':'evidence-weighted attribution support (not proof of actor identity)'}
