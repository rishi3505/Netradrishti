import asyncio
from datetime import datetime
import uuid

from app.schemas.signal import SecuritySignal
from app.schemas.common import Severity, MitreContext
from app.correlation.engine import CorrelationEngine
from app.correlation.context import CorrelationContext

class MockDB:
    async def execute(self, query):
        class MockResult:
            def scalars(self):
                class MockScalars:
                    def all(self):
                        return []
                return MockScalars()
        return MockResult()

async def run_demo():
    print("Starting Module 5 E2E Demonstration")
    db = MockDB()
    engine = CorrelationEngine()
    
    # 1. Simulate a Brute Force Signal that happened a few minutes ago
    print("\n[+] Injecting previous AUTH-001 Brute Force Signal...")
    brute_force_sig = SecuritySignal(
        signal_id=uuid.uuid4(),
        signal_type="Brute Force Attack",
        detection_method="rule_based",
        detection_rule_id="AUTH-001",
        title="Possible Brute Force Attack against administrator from 192.168.1.50",
        severity=Severity.HIGH,
        affected_entities=["192.168.1.50", "administrator"],
        created_at=datetime.utcnow()
    )
    
    # 2. Simulate a new Suspicious Login Signal that just happened
    print("[+] Receiving new AUTH-003 Suspicious Successful Login Signal...")
    success_sig = SecuritySignal(
        signal_id=uuid.uuid4(),
        signal_type="Suspicious Login",
        detection_method="sequence_based",
        detection_rule_id="AUTH-003",
        title="Suspicious Successful Login for administrator from 192.168.1.50",
        severity=Severity.CRITICAL,
        affected_entities=["192.168.1.50", "administrator"],
        created_at=datetime.utcnow()
    )
    
    # Mocking the context cache since we have no DB
    context = CorrelationContext(db)
    context._cache_signals[f"signals_all_30"] = [brute_force_sig]
    
    print("\n[+] Running Correlation Engine...")
    incidents = await engine.analyze(success_sig, context)
    
    if incidents:
        for inc in incidents:
            print(f"\n[!] Incident Generated: {inc.title}")
            print(f"Severity: {inc.severity}")
            print(f"Confidence: {inc.confidence}")
            print(f"Affected Entities: {inc.affected_entities}")
            print(f"Mitre Techniques: {[m.technique_id for m in inc.mitre_techniques]}")
            print(f"Correlation Reason: {inc.evidence.get('reasons')}")
            print("Timeline:")
            for t in inc.timeline:
                print(f"  - {t['timestamp']}: {t['event']}")

if __name__ == "__main__":
    asyncio.run(run_demo())
