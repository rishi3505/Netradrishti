from typing import List
from app.schemas.attack_graph import RiskFactor
from app.schemas.signal import SecuritySignal
from app.schemas.incident import Incident

def calculate_severity_factor(incident: Incident, signals: List[SecuritySignal]) -> RiskFactor:
    # Deterministic mapping: INFO=0, LOW=25, MEDIUM=50, HIGH=75, CRITICAL=100
    severity_map = {"info": 0, "low": 25, "medium": 50, "high": 75, "critical": 100}
    val_str = incident.severity.value.lower() if hasattr(incident.severity, "value") else str(incident.severity).lower()
    base_val = severity_map.get(val_str, 50)
    
    # Weight is 0.3 for base severity
    weight = 0.3
    contrib = base_val * weight
    
    return RiskFactor(
        factor="DetectionSeverity",
        value=base_val,
        weight=weight,
        contribution=contrib,
        reason=f"Incident base severity is {val_str.upper()}"
    )

def calculate_source_diversity_factor(signals: List[SecuritySignal]) -> RiskFactor:
    # Count unique detection methods or sources (mocking source as signal_type for diversity)
    sources = set(s.signal_type for s in signals)
    count = len(sources)
    
    if count == 0:
        val = 0
    elif count == 1:
        val = 30
    elif count == 2:
        val = 60
    else:
        val = 100
        
    weight = 0.2
    contrib = val * weight
    
    return RiskFactor(
        factor="SourceDiversity",
        value=val,
        weight=weight,
        contribution=contrib,
        reason=f"Evidence collected from {count} distinct signal type(s)."
    )

def calculate_technique_diversity_factor(signals: List[SecuritySignal]) -> RiskFactor:
    techniques = set()
    for s in signals:
        if hasattr(s, 'mitre_mapping') and s.mitre_mapping:
            for m in s.mitre_mapping:
                if m.technique_id:
                    techniques.add(m.technique_id)
                    
    count = len(techniques)
    
    if count == 0:
        val = 0
    elif count == 1:
        val = 40
    elif count == 2:
        val = 70
    else:
        val = 100
        
    weight = 0.25
    contrib = val * weight
    
    return RiskFactor(
        factor="TechniqueDiversity",
        value=val,
        weight=weight,
        contribution=contrib,
        reason=f"Identified {count} distinct MITRE ATT&CK technique(s)."
    )

def calculate_threat_intel_factor(signals: List[SecuritySignal]) -> RiskFactor:
    # Just a stub. In reality, check attached threat intel verdicts.
    # Assuming any critical TI gives high risk.
    has_ti = any(hasattr(s, 'tags') and 'malicious_ip' in (s.tags or []) for s in signals)
    
    val = 100 if has_ti else 0
    weight = 0.25
    contrib = val * weight
    
    return RiskFactor(
        factor="ThreatIntelligence",
        value=val,
        weight=weight,
        contribution=contrib,
        reason="Malicious threat intelligence indicators are present." if has_ti else "No critical threat intelligence indicators."
    )
