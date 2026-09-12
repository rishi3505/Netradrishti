import asyncio
from datetime import datetime
import uuid

# Mock classes to simulate DB and Pipeline
from app.schemas.normalized_event import NormalizedEvent, NormalizationMetadata
from app.schemas.event import UnifiedSecurityEvent, EventIdentity, EventSource, EventClassification, RawEvent
from app.schemas.common import NetworkInfo, UserInfo
from app.detection.pipeline import DetectionPipeline
from app.services.detection_service import DetectionService

class MockDB:
    async def execute(self, query):
        class MockResult:
            def scalars(self):
                class MockScalars:
                    def all(self):
                        return []
                return MockScalars()
        return MockResult()
        
    async def commit(self):
        pass

async def run_demo():
    print("Starting Module 4 E2E Demonstration")
    db = MockDB()
    pipeline = DetectionPipeline(db)
    
    print("\n[+] Generating 25 failed logins from 192.168.1.50 for user 'administrator'...")
    
    for i in range(25):
        event = UnifiedSecurityEvent(
            identity=EventIdentity(event_id=uuid.uuid4(), timestamp=datetime.utcnow()),
            source=EventSource(source_name="Windows Server", source_type="os"),
            classification=EventClassification(event_category="authentication", event_type="login", outcome="failure"),
            network=NetworkInfo(source_ip="192.168.1.50"),
            user=UserInfo(username="administrator"),
            raw=RawEvent(raw_event={}, raw_event_format="json")
        )
        
        normalized = NormalizedEvent(
            event=event,
            normalization=NormalizationMetadata(),
            entities=[]
        )
        
        # In a real scenario, the context would query the DB to get the previous 24 failures.
        # Here we manually append to the context's cache for the demo since DB is mocked.
        context = pipeline.engine.registry.get_rule_instance("AUTH-001")
        
        signals = await pipeline.process_event(normalized)
        if signals:
            for sig in signals:
                if sig.detection_rule_id == "AUTH-001":
                    print(f"\n[!] Signal Generated: {sig.title}")
                    print(f"Severity: {sig.severity.value if hasattr(sig.severity, 'value') else sig.severity}")
                    print(f"Confidence: {sig.confidence}")
                    print(f"Risk Score: {sig.risk_score}")
                    print(f"Evidence: {sig.evidence}")
                    return

if __name__ == "__main__":
    asyncio.run(run_demo())
