"""Models de dades compartits per tota l'aplicació SentinelX Audit Suite."""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    CRITICAL = "Crítica"
    HIGH = "Alta"
    MEDIUM = "Mitjana"
    LOW = "Baixa"
    INFO = "Informativa"


@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: Severity
    cvss_score: Optional[float]
    reference_url: str
    exploit_available: bool = False
    exploit_source: str = ""
    recommendation: str = ""


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    service_name: str
    product: str = ""
    version: str = ""
    state: str = "open"
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    mac: str = ""
    os_guess: str = ""
    status: str = "up"
    services: List[ServiceInfo] = field(default_factory=list)


@dataclass
class TracerouteHop:
    hop_number: int
    ip: str
    hostname: str
    rtt_ms: Optional[float]


@dataclass
class AuditSession:
    target: str = ""
    hosts: List[HostResult] = field(default_factory=list)
    traceroute_hops: List[TracerouteHop] = field(default_factory=list)
    local_system_info: dict = field(default_factory=dict)
    hardening_findings: List[Vulnerability] = field(default_factory=list)
