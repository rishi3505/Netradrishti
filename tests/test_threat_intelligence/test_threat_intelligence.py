import pytest
from uuid import uuid4
from app.schemas.threat_intel import IndicatorType, ThreatVerdict, ThreatIntelligenceRequest
from app.services.threat_intelligence.normalizer import identify_and_normalize
from app.services.threat_intelligence.engine import engine

def test_normalization_ipv4():
    ind_type, normalized = identify_and_normalize("  8.8.8.8  ")
    assert ind_type == IndicatorType.IPV4
    assert normalized == "8.8.8.8"

def test_normalization_ipv6():
    ind_type, normalized = identify_and_normalize("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert ind_type == IndicatorType.IPV6
    assert normalized == "2001:db8:85a3::8a2e:370:7334"
    
def test_normalization_domain():
    ind_type, normalized = identify_and_normalize("Example.COM")
    assert ind_type == IndicatorType.DOMAIN
    assert normalized == "example.com"
    
def test_normalization_url():
    ind_type, normalized = identify_and_normalize("https://example.com/malicious-path?q=1")
    assert ind_type == IndicatorType.URL
    assert normalized == "https://example.com/malicious-path?q=1"
    
def test_normalization_md5():
    ind_type, normalized = identify_and_normalize("44d88612fea8a8f36de82e1278abb02f")
    assert ind_type == IndicatorType.MD5
    assert normalized == "44d88612fea8a8f36de82e1278abb02f"
    
def test_normalization_invalid():
    ind_type, normalized = identify_and_normalize("not an ioc")
    assert ind_type is None
    assert normalized == "not an ioc"

import asyncio

def test_engine_mock_malicious():
    request = ThreatIntelligenceRequest(indicator="malicious.com")
    result = asyncio.run(engine.process_indicator(request))
    assert result.verdict == ThreatVerdict.MALICIOUS
    assert result.confidence == 95
    assert result.provider == "mock"
    assert "malware" in result.categories

def test_engine_mock_suspicious():
    request = ThreatIntelligenceRequest(indicator="suspicious-test-domain.com")
    result = asyncio.run(engine.process_indicator(request))
    assert result.verdict == ThreatVerdict.SUSPICIOUS
    assert result.confidence == 60
    
def test_engine_mock_benign():
    request = ThreatIntelligenceRequest(indicator="benign-test-domain.com")
    result = asyncio.run(engine.process_indicator(request))
    assert result.verdict == ThreatVerdict.BENIGN
    assert result.confidence == 99

def test_engine_mock_unknown():
    request = ThreatIntelligenceRequest(indicator="unknown-test-ip")
    result = asyncio.run(engine.process_indicator(request))
    assert result.verdict == ThreatVerdict.UNKNOWN
