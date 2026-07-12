"""
network.py - Core Network Simulation Module
============================================
Defines the network topology, devices, ports, firewall,
and the server that the player must protect.

Cybersecurity Concepts Demonstrated:
- Network nodes and IP addressing
- Port states (open/closed/filtered)
- Firewall rules and packet filtering
- Device vulnerability states
- Intrusion Detection System (IDS) alerts
"""

import random
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class NodeStatus(Enum):
    """Represents the security status of a network device."""
    SECURE      = "secure"
    SCANNING    = "scanning"      # Attacker is probing this node
    VULNERABLE  = "vulnerable"    # Open port detected by attacker
    UNDER_ATTACK = "under_attack" # Active exploitation attempt
    COMPROMISED = "compromised"   # Node has been taken over
    PATCHED     = "patched"       # Defender has patched this node


class PortStatus(Enum):
    """Represents the state of a network port."""
    OPEN     = "open"      # Reachable and exploitable
    CLOSED   = "closed"    # Not accepting connections
    FILTERED = "filtered"  # Blocked by firewall


class AlertSeverity(Enum):
    """Severity levels for IDS alerts."""
    INFO     = "INFO"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class Port:
    """
    Represents a single network port on a device.

    Attributes:
        number   : Port number (e.g. 22, 80, 443)
        service  : Service name (e.g. 'SSH', 'HTTP')
        status   : Current port state
        exploited: True if the attacker has leveraged this port
    """
    number: int
    service: str
    status: PortStatus = PortStatus.OPEN
    exploited: bool = False

    def close(self):
        """Defender action: close this port."""
        self.status = PortStatus.CLOSED
        self.exploited = False

    def filter_by_firewall(self):
        """Mark port as filtered (blocked by active firewall)."""
        if self.status == PortStatus.OPEN:
            self.status = PortStatus.FILTERED

    def open(self):
        """Re-open a port (used for simulation resets)."""
        self.status = PortStatus.OPEN
        self.exploited = False


@dataclass
class NetworkAlert:
    """
    An IDS alert generated when suspicious activity is detected.

    Attributes:
        timestamp : Unix timestamp when alert was created
        severity  : Severity level
        source_ip : IP address of the attacker
        target_ip : IP address of the target
        message   : Human-readable description
        acknowledged: Whether the player has seen this alert
    """
    timestamp: float
    severity: AlertSeverity
    source_ip: str
    target_ip: str
    message: str
    acknowledged: bool = False

    def formatted_time(self) -> str:
        """Return a human-readable timestamp."""
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))

    def log_line(self) -> str:
        """Return a formatted log line for display."""
        return f"[{self.formatted_time()}] [{self.severity.value}] {self.message}"


@dataclass
class NetworkNode:
    """
    Represents a single device (computer) on the network.

    Attributes:
        node_id    : Unique identifier string
        ip_address : Simulated IPv4 address
        hostname   : Human-readable hostname
        status     : Current security status
        ports      : List of ports on this device
        position   : (x, y) screen coordinates for rendering
        is_server  : True if this node is the protected server
        health     : 0-100 integrity value (100 = fully secure)
    """
    node_id: str
    ip_address: str
    hostname: str
    status: NodeStatus = NodeStatus.SECURE
    ports: List[Port] = field(default_factory=list)
    position: tuple = (0, 0)
    is_server: bool = False
    health: int = 100

    # Internal: tracks how many attack ticks have hit this node
    _attack_ticks: int = field(default=0, repr=False)
    score_tracked: bool = field(default=False, repr=False)

    @property
    def open_ports(self) -> List[Port]:
        """Return list of currently open (exploitable) ports."""
        return [p for p in self.ports if p.status == PortStatus.OPEN]

    @property
    def is_compromised(self) -> bool:
        return self.status == NodeStatus.COMPROMISED

    @property
    def is_vulnerable(self) -> bool:
        """True if node has open ports and isn't already compromised."""
        return len(self.open_ports) > 0 and not self.is_compromised

    def take_damage(self, amount: int = 10):
        """
        Reduce node health by amount.
        If health reaches 0, node becomes compromised.
        """
        self.health = max(0, self.health - amount)
        if self.health <= 0:
            self.status = NodeStatus.COMPROMISED
            self.health = 0

    def patch(self):
        """
        Defender action: patch this node.
        Restores health, closes random open port, and sets status to PATCHED.
        """
        if self.status != NodeStatus.COMPROMISED:
            self.health = min(100, self.health + 40)
        # Close one random open port as part of patching
        open_p = self.open_ports
        if open_p:
            random.choice(open_p).close()
        if self.status not in (NodeStatus.COMPROMISED,):
            self.status = NodeStatus.PATCHED

    def reset_status(self):
        """Reset to secure state (used after successful patch)."""
        if self.status != NodeStatus.COMPROMISED:
            self.status = NodeStatus.SECURE


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------

class Firewall:
    """
    Simulates a network firewall.

    The firewall can be toggled active/inactive by the defender.
    When active, it filters open ports on all nodes and reduces
    attacker success probability.

    Attributes:
        active         : Whether the firewall is currently enabled
        rules          : List of blocked IP strings
        blocked_attempts: Count of blocked connection attempts
        cooldown_end   : Timestamp when firewall can be toggled again
    """

    COOLDOWN_SECONDS = 15  # Firewall toggle cooldown

    def __init__(self):
        self.active: bool = False
        self.rules: List[str] = []
        self.blocked_attempts: int = 0
        self.cooldown_end: float = 0.0

    @property
    def is_on_cooldown(self) -> bool:
        return time.time() < self.cooldown_end

    @property
    def cooldown_remaining(self) -> float:
        return max(0.0, self.cooldown_end - time.time())

    def toggle(self) -> bool:
        """
        Toggle the firewall on or off.
        Returns True if toggle succeeded, False if on cooldown.
        """
        if self.is_on_cooldown:
            return False
        self.active = not self.active
        self.cooldown_end = time.time() + self.COOLDOWN_SECONDS
        return True

    def add_rule(self, ip: str):
        """Add a block rule for a specific IP address."""
        if ip not in self.rules:
            self.rules.append(ip)

    def check_traffic(self, source_ip: str) -> bool:
        """
        Returns True if traffic from source_ip should be blocked.
        Firewall must be active and the IP must be in rules (or wildcard).
        """
        if not self.active:
            return False
        if source_ip in self.rules or "ALL" in self.rules:
            self.blocked_attempts += 1
            return True
        return False


# ---------------------------------------------------------------------------
# Intrusion Detection System
# ---------------------------------------------------------------------------

class IDS:
    """
    Simulates a basic Intrusion Detection System.

    Monitors network activity and generates alerts when
    suspicious patterns are detected. Implements basic
    anomaly detection via activity counters.

    Attributes:
        alerts          : All generated alerts
        scan_counter    : Counts port scan events (threshold-based detection)
        alert_threshold : Number of events before triggering high-severity alert
    """

    SCAN_THRESHOLD = 3  # Scans before IDS raises a critical alert

    def __init__(self):
        self.alerts: List[NetworkAlert] = []
        self.scan_counter: Dict[str, int] = {}   # source_ip -> scan count
        self.enabled: bool = True

    def record_scan(self, source_ip: str, target_ip: str, port: int) -> NetworkAlert:
        """
        Record a port scan event and generate an appropriate alert.
        Escalates severity if the same source has scanned repeatedly.
        """
        self.scan_counter[source_ip] = self.scan_counter.get(source_ip, 0) + 1
        count = self.scan_counter[source_ip]

        if count >= self.SCAN_THRESHOLD:
            severity = AlertSeverity.CRITICAL
            msg = (f"REPEATED port scan from {source_ip} → {target_ip}:{port} "
                   f"({count} scans detected) — Possible intrusion in progress!")
        else:
            severity = AlertSeverity.WARNING
            msg = f"Port scan detected: {source_ip} probing {target_ip}:{port} ({count} attempt(s))"

        alert = NetworkAlert(
            timestamp=time.time(),
            severity=severity,
            source_ip=source_ip,
            target_ip=target_ip,
            message=msg
        )
        self.alerts.append(alert)
        return alert

    def record_attack(self, source_ip: str, target_ip: str, port: int,
                      blocked: bool = False) -> NetworkAlert:
        """Record an active attack/exploitation attempt."""
        if blocked:
            msg = (f"Firewall BLOCKED attack from {source_ip} → "
                   f"{target_ip}:{port}")
            severity = AlertSeverity.INFO
        else:
            msg = (f"INTRUSION ATTEMPT: {source_ip} exploiting "
                   f"{target_ip}:{port} — Immediate action required!")
            severity = AlertSeverity.CRITICAL

        alert = NetworkAlert(
            timestamp=time.time(),
            severity=severity,
            source_ip=source_ip,
            target_ip=target_ip,
            message=msg
        )
        self.alerts.append(alert)
        return alert

    def record_compromise(self, source_ip: str, target_ip: str) -> NetworkAlert:
        """Record a successful compromise event."""
        alert = NetworkAlert(
            timestamp=time.time(),
            severity=AlertSeverity.CRITICAL,
            source_ip=source_ip,
            target_ip=target_ip,
            message=(f"*** NODE COMPROMISED *** {target_ip} has been taken "
                     f"over by {source_ip}!")
        )
        self.alerts.append(alert)
        return alert

    def record_defender_action(self, action: str, target_ip: str) -> NetworkAlert:
        """Record a defensive action taken by the player."""
        alert = NetworkAlert(
            timestamp=time.time(),
            severity=AlertSeverity.INFO,
            source_ip="DEFENDER",
            target_ip=target_ip,
            message=f"[DEFENDER] {action} on {target_ip}"
        )
        self.alerts.append(alert)
        return alert

    def recent_alerts(self, n: int = 20) -> List[NetworkAlert]:
        """Return the n most recent alerts."""
        return self.alerts[-n:]


# ---------------------------------------------------------------------------
# Network Builder
# ---------------------------------------------------------------------------

# Common ports to simulate — realistic service mapping
COMMON_PORTS = [
    (21,  "FTP"),
    (22,  "SSH"),
    (23,  "Telnet"),
    (80,  "HTTP"),
    (443, "HTTPS"),
    (3306,"MySQL"),
    (8080,"HTTP-Alt"),
    (445, "SMB"),
]


def build_network() -> Dict:
    """
    Factory function: constructs the initial network topology.

    Creates:
    - 1 Central Server  (high-value target)
    - 1 Firewall node   (visual representation)
    - 5 Workstation nodes
    - 1 Database node

    Returns a dict with keys: 'nodes', 'server', 'firewall', 'ids'
    """

    # --- Server ---
    server = NetworkNode(
        node_id="server",
        ip_address="192.168.1.1",
        hostname="MAIN-SERVER",
        is_server=True,
        position=(500, 300),
        health=100,
        ports=[
            Port(22,   "SSH",   PortStatus.OPEN),
            Port(80,   "HTTP",  PortStatus.OPEN),
            Port(443,  "HTTPS", PortStatus.OPEN),
            Port(3306, "MySQL", PortStatus.OPEN),
        ]
    )

    # --- Workstations ---
    workstation_configs = [
        ("ws1", "192.168.1.101", "WS-ALPHA",   (180, 150)),
        ("ws2", "192.168.1.102", "WS-BETA",    (350, 130)),
        ("ws3", "192.168.1.103", "WS-GAMMA",   (650, 130)),
        ("ws4", "192.168.1.104", "WS-DELTA",   (820, 150)),
        ("ws5", "192.168.1.105", "WS-EPSILON", (180, 450)),
    ]

    workstations = []
    for node_id, ip, hostname, pos in workstation_configs:
        # Each workstation gets 2-3 random open ports
        available = COMMON_PORTS.copy()
        random.shuffle(available)
        chosen = available[:random.randint(2, 3)]
        ports = [Port(num, svc, PortStatus.OPEN) for num, svc in chosen]
        workstations.append(NetworkNode(
            node_id=node_id,
            ip_address=ip,
            hostname=hostname,
            position=pos,
            ports=ports,
            health=100
        ))

    # --- Database Node ---
    db_node = NetworkNode(
        node_id="db",
        ip_address="192.168.1.200",
        hostname="DB-NODE",
        position=(820, 450),
        health=100,
        ports=[
            Port(3306, "MySQL",    PortStatus.OPEN),
            Port(5432, "Postgres", PortStatus.OPEN),
            Port(27017,"MongoDB",  PortStatus.OPEN),
        ]
    )

    all_nodes = workstations + [db_node, server]

    return {
        "nodes":   all_nodes,
        "server":  server,
        "firewall": Firewall(),
        "ids":     IDS(),
    }
