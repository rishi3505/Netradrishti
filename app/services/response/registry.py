from typing import List, Dict, Type
from .playbooks.base import ResponsePlaybook
from .playbooks.credential_attack import CredentialAttackPlaybook
from .playbooks.suspicious_execution import SuspiciousExecutionPlaybook
from .playbooks.malware import MalwarePlaybook
from .playbooks.network_attack import NetworkAttackPlaybook
from .playbooks.multi_source_compromise import MultiSourceCompromisePlaybook
from .connectors.base import ResponseExecutionConnector
from .connectors.mock_connector import MockResponseConnector

class ResponseRegistry:
    def __init__(self):
        self._playbooks: List[ResponsePlaybook] = []
        self._connectors: Dict[str, ResponseExecutionConnector] = {}
        self._register_defaults()

    def _register_defaults(self):
        self.register_playbook(CredentialAttackPlaybook())
        self.register_playbook(SuspiciousExecutionPlaybook())
        self.register_playbook(MalwarePlaybook())
        self.register_playbook(NetworkAttackPlaybook())
        self.register_playbook(MultiSourceCompromisePlaybook())
        self.register_connector("mock", MockResponseConnector())

    def register_playbook(self, playbook: ResponsePlaybook):
        self._playbooks.append(playbook)

    def get_matching_playbooks(self, incident, context) -> List[ResponsePlaybook]:
        return [pb for pb in self._playbooks if pb.matches(incident, context)]

    def register_connector(self, name: str, connector: ResponseExecutionConnector):
        self._connectors[name] = connector

    def get_connector(self, name: str) -> ResponseExecutionConnector:
        return self._connectors.get(name)

response_registry = ResponseRegistry()
