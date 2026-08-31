import pytest
from app.schemas.event import UnifiedSecurityEvent, EventIdentity, EventSource, EventClassification, RawEvent
from pydantic import ValidationError

def test_unified_security_event_valid():
    event = UnifiedSecurityEvent(
        source=EventSource(source_name="windows_pc_1", source_type="windows"),
        classification=EventClassification(event_category="authentication", event_type="login"),
        raw=RawEvent(raw_event={"key": "value"}, raw_event_format="json")
    )
    assert event.identity.event_id is not None
    assert event.lifecycle == "RECEIVED"

def test_unified_security_event_invalid_missing_required():
    with pytest.raises(ValidationError):
        UnifiedSecurityEvent(
            classification=EventClassification(event_category="authentication", event_type="login"),
            raw=RawEvent(raw_event={"key": "value"}, raw_event_format="json")
        )
