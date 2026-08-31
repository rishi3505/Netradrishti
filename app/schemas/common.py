from pydantic import BaseModel, Field, IPvAnyAddress, AnyUrl
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
from uuid import UUID

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class NetworkInfo(BaseModel):
    source_ip: Optional[IPvAnyAddress] = None
    source_port: Optional[int] = None
    destination_ip: Optional[IPvAnyAddress] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    transport_protocol: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    packets_sent: Optional[int] = None
    packets_received: Optional[int] = None

class HostInfo(BaseModel):
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    ip: Optional[IPvAnyAddress] = None
    mac_address: Optional[str] = None
    operating_system: Optional[str] = None
    device_id: Optional[str] = None
    asset_id: Optional[str] = None

class UserInfo(BaseModel):
    username: Optional[str] = None
    domain: Optional[str] = None
    email: Optional[str] = None
    user_id: Optional[str] = None
    account_type: Optional[str] = None
    privilege_level: Optional[str] = None

class ProcessInfo(BaseModel):
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    executable_path: Optional[str] = None
    command_line: Optional[str] = None
    process_hash: Optional[str] = None

class FileInfo(BaseModel):
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_extension: Optional[str] = None
    file_size: Optional[int] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None

class WebInfo(BaseModel):
    domain: Optional[str] = None
    url: Optional[AnyUrl] = None
    http_method: Optional[str] = None
    user_agent: Optional[str] = None
    dns_query: Optional[str] = None

class CloudInfo(BaseModel):
    cloud_provider: Optional[str] = None
    account_id: Optional[str] = None
    subscription_id: Optional[str] = None
    resource_id: Optional[str] = None
    region: Optional[str] = None

class MitreContext(BaseModel):
    tactic: Optional[str] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    subtechnique_id: Optional[str] = None

class SecurityContext(BaseModel):
    severity: Optional[Severity] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    tags: List[str] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)
    mitre: List[MitreContext] = Field(default_factory=list)
