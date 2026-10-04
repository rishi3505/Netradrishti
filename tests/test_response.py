import pytest
from uuid import uuid4
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.database_models import Base, DBIncident
from app.schemas.incident import Incident, Severity, IncidentStatus
from app.schemas.response import ActionStatus, ActionRisk
from app.services.response.engine import ResponseEngine
from app.services.response.playbooks.credential_attack import CredentialAttackPlaybook
from app.schemas.common import MitreContext

# Setup mock DB for tests
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    yield db
    db.close()
    Base.metadata.drop_all(bind=engine)

def test_credential_attack_playbook():
    incident = Incident(
        incident_id=uuid4(),
        title="Brute Force Attack Detected",
        severity=Severity.HIGH,
        status=IncidentStatus.NEW,
        mitre_techniques=[MitreContext(tactic="Credential Access", technique="Brute Force")]
    )
    pb = CredentialAttackPlaybook()
    assert pb.matches(incident, {}) is True
    
    actions = pb.generate_actions(incident, {})
    assert len(actions) == 4
    
    # Check that high risk containment action requires approval
    disable_acc = next(a for a in actions if a.action_type == "disable_account")
    assert disable_acc.approval_required is True

def test_response_engine_generates_plan(db):
    incident_id = uuid4()
    incident_data = {
        "incident_id": str(incident_id),
        "title": "Brute Force Attack Detected",
        "status": "new",
        "severity": "high"
    }
    db_incident = DBIncident(
        incident_id=incident_id,
        title="Brute Force Attack",
        status="new",
        severity="high",
        incident_data=incident_data
    )
    db.add(db_incident)
    db.commit()
    
    engine = ResponseEngine(db)
    plan = engine.generate_plan(incident_id)
    
    assert plan is not None
    assert plan.incident_id == incident_id
    assert len(plan.actions) > 0
    
    # Verify save to DB
    saved_plan = engine.get_plan(incident_id)
    assert saved_plan is not None
    assert saved_plan.plan_id == plan.plan_id
    
    # Verify actions
    saved_actions = engine.get_actions(incident_id)
    assert len(saved_actions) == len(plan.actions)

def test_approval_workflow(db):
    incident_id = uuid4()
    db_incident = DBIncident(
        incident_id=incident_id,
        title="Brute Force Attack",
        status="new",
        severity="high",
        incident_data={"incident_id": str(incident_id), "title": "Brute Force", "status": "new", "severity": "high"}
    )
    db.add(db_incident)
    db.commit()

    engine = ResponseEngine(db)
    plan = engine.generate_plan(incident_id)
    
    # Find an action that requires approval
    action = next(a for a in plan.actions if a.approval_required)
    
    # Reject it
    engine.reject_action(action.action_id, approver="admin123")
    updated_action = engine.get_action(action.action_id)
    assert updated_action.status == ActionStatus.REJECTED
    
    # Approve it
    engine.approve_action(action.action_id, approver="admin123")
    updated_action2 = engine.get_action(action.action_id)
    assert updated_action2.status == ActionStatus.APPROVED
    
    # Simulate execution
    result = engine.simulate_action(action.action_id)
    assert result["status"] == ActionStatus.SIMULATED
    
    final_action = engine.get_action(action.action_id)
    assert final_action.status == ActionStatus.SIMULATED
