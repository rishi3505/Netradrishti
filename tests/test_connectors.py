import pytest
from app.connectors.windows.connector import WindowsConnector
from app.connectors.firewall.connector import FirewallConnector
from app.connectors.suricata.connector import SuricataConnector
from app.connectors.surakshanetra.connector import SurakshaNetraConnector
from app.connectors.exceptions import ValidationError
from app.schemas.common import Severity

def test_windows_connector():
    connector = WindowsConnector()
    raw_event = {
        "EventID": 4624,
        "TimeCreated": "2026-09-02T10:00:00Z",
        "Computer": "DC01",
        "TargetUserName": "admin",
        "IpAddress": "192.168.1.100"
    }
    
    event = connector.transform(raw_event)
    assert event.source.source_type == "windows"
    assert event.classification.event_type == "authentication_success"
    assert event.user.username == "admin"
    assert event.source_host.hostname == "DC01"
    
    # invalid event
    with pytest.raises(ValidationError):
        connector.transform({"EventID": 4624})

def test_firewall_connector():
    connector = FirewallConnector()
    raw_event = {
        "timestamp": "2026-09-02T10:00:00Z",
        "src_ip": "192.168.1.10",
        "src_port": 54321,
        "dst_ip": "10.0.0.10",
        "dst_port": 443,
        "protocol": "TCP",
        "action": "allowed",
        "bytes": 1024
    }
    
    event = connector.transform(raw_event)
    assert event.source.source_type == "firewall"
    assert event.classification.event_action == "allowed"
    assert event.classification.outcome == "success"
    assert str(event.network.source_ip) == "192.168.1.10"

def test_suricata_connector():
    connector = SuricataConnector()
    raw_event = {
        "timestamp": "2026-09-02T10:00:00Z",
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "dest_ip": "192.168.1.50",
        "proto": "TCP",
        "alert": {
            "signature": "ET MALWARE Suspicious Connection",
            "category": "A Network Trojan was detected",
            "severity": 1
        }
    }
    
    event = connector.transform(raw_event)
    assert event.source.source_type == "suricata"
    assert event.classification.event_type == "suricata_alert"
    assert event.security_context.severity == Severity.HIGH
    assert "A Network Trojan was detected" in event.security_context.tags

def test_surakshanetra_connector():
    connector = SurakshaNetraConnector()
    raw_event = {
        "event_id": "sn-12345",
        "timestamp": "2026-09-02T10:00:00Z",
        "signal_type": "lateral_movement",
        "severity": "critical",
        "confidence": 95,
        "source_ip": "10.0.0.5",
        "title": "Suspicious RDP Login",
        "evidence": {"process": "mstsc.exe"},
        "affected_entities": ["host-A", "user-B"]
    }
    
    event = connector.transform(raw_event)
    assert event.source.source_type == "surakshanetra"
    assert event.security_context.severity == Severity.CRITICAL
    assert event.security_context.confidence == 95
    assert event.custom_fields["affected_entities"] == ["host-A", "user-B"]
    assert event.custom_fields["evidence"] == {"process": "mstsc.exe"}
