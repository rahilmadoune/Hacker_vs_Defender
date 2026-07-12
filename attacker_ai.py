import random
import time
from enum import Enum
from typing import List, Optional, Dict, Tuple

from network import (
    NetworkNode, NetworkAlert, NodeStatus, PortStatus,
    Firewall, IDS, Port, AlertSeverity
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AttackPhase(Enum):
    """Current phase in the attacker's kill chain."""
    IDLE           = "idle"
    RECONNAISSANCE = "reconnaissance"
    SCANNING       = "scanning"
    EXPLOITATION   = "exploitation"
    PERSISTENCE    = "persistence"
    SUCCEEDED      = "succeeded"   # Attacker has won


class Difficulty(Enum):
    """Game difficulty levels affecting AI behavior."""
    EASY   = "easy"
    MEDIUM = "medium"
    HARD   = "hard"


# ---------------------------------------------------------------------------
# Difficulty Profiles
# ---------------------------------------------------------------------------

DIFFICULTY_PROFILES = {
    Difficulty.EASY: {
        "scan_interval":      4.0,   # Seconds between scans
        "attack_interval":    6.0,   # Seconds between attacks
        "exploit_chance":     0.25,  # Base probability of successful exploit
        "max_targets":        1,     # Simultaneous attack targets
        "escalation_rate":    0.005, # Increase in exploit_chance per second
        "wave_interval":      45.0,  # Seconds between attack waves
        "description": "Slow, methodical attacker — good for learning"
    },
    Difficulty.MEDIUM: {
        "scan_interval":      2.5,
        "attack_interval":    3.5,
        "exploit_chance":     0.40,
        "max_targets":        2,
        "escalation_rate":    0.008,
        "wave_interval":      30.0,
        "description": "Faster scanning, multiple targets"
    },
    Difficulty.HARD: {
        "scan_interval":      1.0,
        "attack_interval":    1.8,
        "exploit_chance":     0.60,
        "max_targets":        3,
        "escalation_rate":    0.015,
        "wave_interval":      20.0,
        "description": "Aggressive, multi-vector attacks with rapid escalation"
    },
}


# ---------------------------------------------------------------------------
# Packet Simulation
# ---------------------------------------------------------------------------

class Packet:
    """
    Simulates a network packet in transit (for visualization).

    Packets travel from attacker to a target node across the screen,
    representing scan probes or exploit payloads.
    """
    def __init__(self, source_pos: Tuple[float, float],
                 target_pos: Tuple[float, float],
                 packet_type: str = "scan",
                 color: Tuple[int, int, int] = (255, 165, 0)):
        self.source_pos  = source_pos
        self.target_pos  = target_pos
        self.current_pos = list(source_pos)
        self.packet_type = packet_type   # "scan" | "attack" | "exploit"
        self.color       = color
        self.speed       = 3.0           # Pixels per frame
        self.alive       = True          # Remove when reached target
        self.progress    = 0.0           # 0.0 → 1.0

    def update(self):
        """Advance packet toward its target."""
        dx = self.target_pos[0] - self.source_pos[0]
        dy = self.target_pos[1] - self.source_pos[1]
        dist = max(1, (dx**2 + dy**2) ** 0.5)

        self.progress = min(1.0, self.progress + self.speed / dist)
        self.current_pos[0] = self.source_pos[0] + dx * self.progress
        self.current_pos[1] = self.source_pos[1] + dy * self.progress

        if self.progress >= 1.0:
            self.alive = False


# ---------------------------------------------------------------------------
# Attacker AI
# ---------------------------------------------------------------------------

class AttackerAI:
    """
    AI-driven hacker that executes a multi-phase attack campaign.

    The attacker operates as a finite state machine, cycling through
    reconnaissance, scanning, and exploitation phases. Difficulty
    settings control speed and effectiveness.

    Attributes:
        ip_address      : Simulated external attacker IP
        phase           : Current kill-chain phase
        difficulty      : Selected difficulty profile
        known_nodes     : Nodes the attacker has discovered
        scanned_nodes   : Nodes with enumerated ports
        targeted_node   : Currently attacked node
        packets         : Active visualisation packets
        score_events    : Events to report back for scoring
    """

    ATTACKER_IP = "10.0.0.99"           # External attacker address
    ATTACKER_POS = (980, 300)           # Off-screen source position

    def __init__(self, difficulty: Difficulty = Difficulty.MEDIUM):
        self.ip_address     = self.ATTACKER_IP
        self.phase          = AttackPhase.IDLE
        self.difficulty     = difficulty
        self.profile        = DIFFICULTY_PROFILES[difficulty]

        # State tracking
        self.known_nodes:    List[NetworkNode] = []
        self.scanned_nodes:  List[NetworkNode] = []
        self.targeted_nodes: List[NetworkNode] = []
        self.packets:        List[Packet]      = []
        self.score_events:   List[str]         = []

        # Timers
        self._last_scan_time:    float = 0.0
        self._last_attack_time:  float = 0.0
        self._last_wave_time:    float = time.time()
        self._start_time:        float = time.time()

        # Escalation
        self._current_exploit_chance: float = self.profile["exploit_chance"]

        # Wave counter
        self.wave_number: int = 1
        self.in_wave:     bool = False

        # Stats
        self.total_scans:    int = 0
        self.total_attacks:  int = 0
        self.total_exploits: int = 0
        self.nodes_compromised: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        """Begin the attack campaign."""
        self.phase = AttackPhase.RECONNAISSANCE
        self._last_scan_time   = time.time()
        self._last_attack_time = time.time()

    def update(self, nodes: List[NetworkNode], firewall: Firewall,
               ids: IDS, speed_multiplier: float = 1.0) -> List[NetworkAlert]:
        """
        Main update tick — called every game frame.

        Executes the appropriate attack phase logic and returns
        a list of new IDS alerts generated this tick.
        """
        if self.phase in (AttackPhase.IDLE, AttackPhase.SUCCEEDED):
            return []

        # Escalate exploit probability over time
        elapsed = time.time() - self._start_time
        self._current_exploit_chance = min(
            0.90,
            self.profile["exploit_chance"] + elapsed * self.profile["escalation_rate"]
        )

        # Update packet animations
        self.packets = [p for p in self.packets if p.alive]
        for p in self.packets:
            p.update()

        alerts: List[NetworkAlert] = []

        # --- Check wave timing ---
        if time.time() - self._last_wave_time > self.profile["wave_interval"]:
            self.wave_number += 1
            self._last_wave_time = time.time()
            self.in_wave = True
            alerts.append(NetworkAlert(
                timestamp=time.time(),
                severity=AlertSeverity.CRITICAL,
                source_ip=self.ATTACKER_IP,
                target_ip="BROADCAST",
                message=(f"⚠  ATTACK WAVE {self.wave_number} INCOMING! "
                         f"Attacker escalating pressure...")
            ))
        else:
            self.in_wave = False

        # --- Phase dispatch ---
        now = time.time()
        scan_ready   = (now - self._last_scan_time)   >= (self.profile["scan_interval"] * speed_multiplier)
        attack_ready = (now - self._last_attack_time) >= (self.profile["attack_interval"] * speed_multiplier)

        if self.phase == AttackPhase.RECONNAISSANCE and scan_ready:
            alerts += self._do_reconnaissance(nodes, ids)
            self._last_scan_time = now

        elif self.phase == AttackPhase.SCANNING and scan_ready:
            alerts += self._do_scanning(nodes, firewall, ids)
            self._last_scan_time = now

        elif self.phase == AttackPhase.EXPLOITATION and attack_ready:
            alerts += self._do_exploitation(nodes, firewall, ids)
            self._last_attack_time = now

        elif self.phase == AttackPhase.PERSISTENCE and attack_ready:
            alerts += self._do_persistence(nodes, firewall, ids)
            self._last_attack_time = now

        # Phase transitions
        self._evaluate_phase_transition(nodes)

        return alerts

    # ------------------------------------------------------------------
    # Phase Logic
    # ------------------------------------------------------------------

    def _do_reconnaissance(self, nodes: List[NetworkNode],
                           ids: IDS) -> List[NetworkAlert]:
        """
        Phase 1 – Reconnaissance: discover live hosts on the network.
        Attacker sends ping sweeps to identify active devices.
        """
        alerts = []
        undiscovered = [n for n in nodes if n not in self.known_nodes
                        and not n.is_compromised]
        if not undiscovered:
            self.phase = AttackPhase.SCANNING
            return alerts

        # Discover 1-2 nodes per tick
        targets = random.sample(undiscovered, min(2, len(undiscovered)))
        for node in targets:
            self.known_nodes.append(node)
            node.status = NodeStatus.SCANNING

            # Spawn visual packet
            self._spawn_packet(node.position, "scan", (255, 200, 50))

            alert = ids.record_scan(
                self.ATTACKER_IP, node.ip_address, 0
            )
            alerts.append(alert)
            self.total_scans += 1

        return alerts

    def _do_scanning(self, nodes: List[NetworkNode], firewall: Firewall,
                     ids: IDS) -> List[NetworkAlert]:
        """
        Phase 2 – Port Scanning: enumerate open ports on known nodes.
        Simulates TCP SYN scan technique.
        """
        alerts = []
        unscanned = [n for n in self.known_nodes
                     if n not in self.scanned_nodes and not n.is_compromised]
        if not unscanned:
            self.phase = AttackPhase.EXPLOITATION
            return alerts

        target = random.choice(unscanned)

        # Firewall check
        if firewall.check_traffic(self.ATTACKER_IP):
            alerts.append(ids.record_attack(
                self.ATTACKER_IP, target.ip_address, 0, blocked=True
            ))
            return alerts

        # Scan each open port
        for port in target.open_ports:
            alert = ids.record_scan(
                self.ATTACKER_IP, target.ip_address, port.number
            )
            alerts.append(alert)
            self.total_scans += 1
            self._spawn_packet(target.position, "scan", (255, 165, 0))

        self.scanned_nodes.append(target)
        if NodeStatus.SCANNING == target.status:
            target.status = NodeStatus.VULNERABLE

        return alerts

    def _do_exploitation(self, nodes: List[NetworkNode], firewall: Firewall,
                         ids: IDS) -> List[NetworkAlert]:
        """
        Phase 3 – Exploitation: attempt to exploit open ports.
        Models probability-based exploitation using CVE-like logic.
        """
        alerts = []
        max_t = self.profile["max_targets"]

        # Select vulnerable targets (exclude already compromised)
        candidates = [
            n for n in self.scanned_nodes
            if n.is_vulnerable and not n.is_compromised
               and n not in self.targeted_nodes
        ]
        if not candidates:
            # Try to find new targets via re-scanning
            self.scanned_nodes = []
            self.phase = AttackPhase.SCANNING
            return alerts

        targets = candidates[:max_t]

        for target in targets:
            if not target.open_ports:
                continue

            port = random.choice(target.open_ports)

            # Firewall check
            if firewall.check_traffic(self.ATTACKER_IP):
                alerts.append(ids.record_attack(
                    self.ATTACKER_IP, target.ip_address, port.number, blocked=True
                ))
                continue

            # Exploit attempt — probability model
            roll = random.random()
            # Telnet and FTP are extra vulnerable
            bonus = 0.15 if port.service in ("Telnet", "FTP", "MySQL") else 0.0
            success = roll < (self._current_exploit_chance + bonus)

            alert = ids.record_attack(
                self.ATTACKER_IP, target.ip_address, port.number, blocked=False
            )
            alerts.append(alert)
            self._spawn_packet(target.position, "attack", (255, 50, 50))
            self.total_attacks += 1

            if success:
                port.exploited = True
                target.status = NodeStatus.UNDER_ATTACK
                target.take_damage(20)
                self.total_exploits += 1

                if target.is_compromised:
                    comp_alert = ids.record_compromise(
                        self.ATTACKER_IP, target.ip_address
                    )
                    alerts.append(comp_alert)
                    self.targeted_nodes.append(target)
                    self.nodes_compromised += 1
                    self.score_events.append(f"compromised:{target.node_id}")

                    # If server is compromised, attacker wins
                    if target.is_server:
                        self.phase = AttackPhase.SUCCEEDED

        return alerts

    def _do_persistence(self, nodes: List[NetworkNode], firewall: Firewall,
                        ids: IDS) -> List[NetworkAlert]:
        """
        Phase 4 – Persistence: pivot through compromised nodes to reach server.
        Attackers use lateral movement to escalate privileges.
        """
        alerts = []
        server = next((n for n in nodes if n.is_server), None)
        if not server:
            return alerts

        if server.is_compromised:
            self.phase = AttackPhase.SUCCEEDED
            return alerts

        # Lateral movement: use compromised nodes as jump points
        compromised = [n for n in nodes if n.is_compromised and not n.is_server]
        if not compromised:
            self.phase = AttackPhase.EXPLOITATION
            return alerts

        if not firewall.check_traffic(self.ATTACKER_IP):
            for port in server.open_ports:
                self._spawn_packet(server.position, "exploit", (200, 0, 255))
                server.take_damage(15)
                alert = ids.record_attack(
                    self.ATTACKER_IP, server.ip_address, port.number
                )
                alerts.append(alert)
                self.total_attacks += 1

                if server.is_compromised:
                    alerts.append(ids.record_compromise(
                        self.ATTACKER_IP, server.ip_address
                    ))
                    self.phase = AttackPhase.SUCCEEDED
                    break

        return alerts

    # ------------------------------------------------------------------
    # Phase Transition Logic
    # ------------------------------------------------------------------

    def _evaluate_phase_transition(self, nodes: List[NetworkNode]):
        """Evaluate whether the attacker should advance to the next phase."""
        if self.phase == AttackPhase.EXPLOITATION:
            if self.nodes_compromised >= 2:
                self.phase = AttackPhase.PERSISTENCE

    # ------------------------------------------------------------------
    # Packet Spawning
    # ------------------------------------------------------------------

    def _spawn_packet(self, target_pos: tuple, ptype: str,
                      color: Tuple[int, int, int]):
        """Create a new animated packet traveling to target_pos."""
        pkt = Packet(
            source_pos=self.ATTACKER_POS,
            target_pos=target_pos,
            packet_type=ptype,
            color=color
        )
        self.packets.append(pkt)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    @property
    def phase_label(self) -> str:
        labels = {
            AttackPhase.IDLE:           "Idle",
            AttackPhase.RECONNAISSANCE: "Reconnaissance",
            AttackPhase.SCANNING:       "Port Scanning",
            AttackPhase.EXPLOITATION:   "Exploitation",
            AttackPhase.PERSISTENCE:    "Lateral Movement",
            AttackPhase.SUCCEEDED:      "ATTACK SUCCEEDED",
        }
        return labels.get(self.phase, "Unknown")

    @property
    def threat_level(self) -> str:
        """Human-readable threat level based on current phase."""
        if self.phase in (AttackPhase.IDLE, AttackPhase.RECONNAISSANCE):
            return "LOW"
        elif self.phase == AttackPhase.SCANNING:
            return "MEDIUM"
        elif self.phase == AttackPhase.EXPLOITATION:
            return "HIGH"
        else:
            return "CRITICAL"

    @property
    def threat_color(self) -> Tuple[int, int, int]:
        colors = {
            "LOW":      (50,  205, 50),
            "MEDIUM":   (255, 165, 0),
            "HIGH":     (255, 69,  0),
            "CRITICAL": (220, 20,  60),
        }
        return colors.get(self.threat_level, (255, 255, 255))
