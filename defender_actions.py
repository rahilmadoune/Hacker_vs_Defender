"""
defender_actions.py - Defender Action System
=============================================
Provides all defensive actions available to the player.
Each action has a cooldown, cost, and specific effect on
the network state.

Actions Available:
  - Scan Network      : Reveal attacker activity
  - Close Port        : Remove an exploitable entry point
  - Activate Firewall : Toggle firewall protection
  - Patch Node        : Restore a vulnerable/attacked node
  - Deploy Honeypot   : Slow attacker with a decoy
  - Emergency Lockdown: Temporarily block all external traffic

Cybersecurity Concepts Demonstrated:
- Incident response procedures
- Port hardening
- Firewall management
- Vulnerability patching
- Deception technology (honeypot)
"""

import time
import random
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass, field

from network import (
    NetworkNode, Firewall, IDS, NodeStatus, PortStatus,
    NetworkAlert, AlertSeverity
)


# ---------------------------------------------------------------------------
# Scoring System
# ---------------------------------------------------------------------------

@dataclass
class ScoreEvent:
    """A single scored game event."""
    timestamp: float
    points: int
    description: str


class ScoreTracker:
    """
    Tracks the player's score throughout the game.

    Points are awarded for defensive actions and deducted
    when nodes are compromised or the server takes damage.
    """

    # Point values for various events
    POINTS = {
        "port_closed":          +50,
        "node_patched":         +75,
        "attack_blocked":       +30,
        "firewall_activated":   +40,
        "scan_completed":       +20,
        "honeypot_deployed":    +60,
        "lockdown_activated":   +80,
        "node_compromised":    -150,
        "server_damaged":       -50,
        "server_compromised":  -500,
        "wave_survived":       +100,
        "game_won":            +300,
    }

    def __init__(self):
        self.total_score: int = 0
        self.events: List[ScoreEvent] = []
        self.high_score: int = 0

    def add(self, event_type: str, custom_desc: str = "") -> int:
        """
        Add points for an event type. Returns points awarded.
        """
        pts = self.POINTS.get(event_type, 0)
        desc = custom_desc or event_type.replace("_", " ").title()
        self.events.append(ScoreEvent(
            timestamp=time.time(),
            points=pts,
            description=desc
        ))
        self.total_score += pts
        self.high_score = max(self.high_score, self.total_score)
        return pts

    def get_grade(self) -> str:
        """Return a letter grade based on current score."""
        if self.total_score >= 1000: return "A+"
        if self.total_score >= 750:  return "A"
        if self.total_score >= 500:  return "B"
        if self.total_score >= 250:  return "C"
        if self.total_score >= 0:    return "D"
        return "F"

    def recent_events(self, n: int = 5) -> List[ScoreEvent]:
        return self.events[-n:]


# ---------------------------------------------------------------------------
# Action Definition
# ---------------------------------------------------------------------------

@dataclass
class DefenderAction:
    """
    Defines a single defensive action available to the player.

    Attributes:
        name        : Display name
        key         : Keyboard shortcut character
        cooldown    : Seconds before this action can be used again
        description : Tooltip / help text
        color       : Button colour (R, G, B)
    """
    name: str
    key: str
    cooldown: float
    description: str
    color: Tuple[int, int, int]
    _last_used: float = field(default=0.0, repr=False)
    rect: Optional[object] = field(default=None, repr=False)

    @property
    def is_ready(self) -> bool:
        return time.time() >= self._last_used + self.cooldown

    @property
    def cooldown_remaining(self) -> float:
        return max(0.0, (self._last_used + self.cooldown) - time.time())

    @property
    def cooldown_fraction(self) -> float:
        """0.0 = just used, 1.0 = fully ready."""
        if self.is_ready:
            return 1.0
        elapsed = time.time() - self._last_used
        return elapsed / self.cooldown

    def use(self):
        """Mark this action as used (starts cooldown)."""
        self._last_used = time.time()


# ---------------------------------------------------------------------------
# Defender Controller
# ---------------------------------------------------------------------------

class DefenderController:
    """
    Manages all defensive actions and game state for the player.

    Acts as the interface layer between player input (from ui.py)
    and the network simulation (network.py / attacker_ai.py).
    """

    def __init__(self, nodes: List[NetworkNode], firewall: Firewall,
                 ids: IDS, score_tracker: ScoreTracker):
        self.nodes         = nodes
        self.firewall      = firewall
        self.ids           = ids
        self.score         = score_tracker

        # Define all available actions
        self.actions: Dict[str, DefenderAction] = {
            "scan": DefenderAction(
                name="Scan Network",
                key="S",
                cooldown=8.0,
                description="Perform an active network scan to reveal attacker activity on all nodes.",
                color=(30, 144, 255)
            ),
            "close_port": DefenderAction(
                name="Close Port",
                key="C",
                cooldown=5.0,
                description="Close the most vulnerable open port on the selected node.",
                color=(255, 165, 0)
            ),
            "firewall": DefenderAction(
                name="Toggle Firewall",
                key="F",
                cooldown=15.0,
                description="Activate/deactivate firewall. Blocks attacker traffic while active.",
                color=(0, 200, 100)
            ),
            "patch": DefenderAction(
                name="Patch Node",
                key="P",
                cooldown=12.0,
                description="Apply security patches to a vulnerable node — restores health and closes a port.",
                color=(148, 0, 211)
            ),
            "honeypot": DefenderAction(
                name="Deploy Honeypot",
                key="H",
                cooldown=25.0,
                description="Plant a decoy to distract and slow down the attacker for 10 seconds.",
                color=(255, 20, 147)
            ),
            "lockdown": DefenderAction(
                name="Emergency Lockdown",
                key="L",
                cooldown=40.0,
                description="Emergency: lock down all nodes — closes all ports temporarily.",
                color=(200, 0, 0)
            ),
        }

        # Honeypot state
        self._honeypot_active: bool = False
        self._honeypot_end:    float = 0.0

        # Selected node (player click target)
        self.selected_node: Optional[NetworkNode] = None

        # Timer for auto-alert acknowledgement
        self._scan_revealed: List[str] = []

    # ------------------------------------------------------------------
    # Core Actions
    # ------------------------------------------------------------------

    def scan_network(self) -> Optional[NetworkAlert]:
        """
        Action: Scan the network.
        Reveals nodes that are under scanning/attack and logs the activity.
        Returns an IDS alert, or None if action is on cooldown.
        """
        action = self.actions["scan"]
        if not action.is_ready:
            return None

        action.use()

        # Reveal all nodes currently being targeted by attacker
        suspicious = [
            n for n in self.nodes
            if n.status in (NodeStatus.SCANNING, NodeStatus.VULNERABLE,
                            NodeStatus.UNDER_ATTACK)
        ]

        msg = (f"Network scan complete. Found {len(suspicious)} suspicious "
               f"node(s). {len([n for n in self.nodes if n.open_ports])} "
               f"node(s) have open ports.")

        alert = self.ids.record_defender_action("Network Scan", "ALL NODES")
        alert.message = msg

        pts = self.score.add("scan_completed",
                             f"Scanned network — {len(suspicious)} threats found")
        return alert

    def close_port(self, node: Optional[NetworkNode] = None) -> Optional[NetworkAlert]:
        """
        Action: Close the most dangerous open port on a node.
        Prefers ports marked as exploited or high-risk services.
        """
        action = self.actions["close_port"]
        if not action.is_ready:
            return None

        target = node or self.selected_node
        if not target:
            # Auto-select the most vulnerable node
            target = self._most_vulnerable_node()
        if not target:
            return None

        open_ports = target.open_ports
        if not open_ports:
            return None

        action.use()

        # Prioritise exploited > risky services > random
        exploited = [p for p in open_ports if p.exploited]
        risky = [p for p in open_ports if p.service in
                 ("Telnet", "FTP", "MySQL", "MongoDB")]
        port_to_close = (
            exploited[0] if exploited else
            risky[0]     if risky     else
            random.choice(open_ports)
        )

        port_to_close.close()
        if target.status == NodeStatus.VULNERABLE and not target.open_ports:
            target.status = NodeStatus.SECURE

        self.score.add("port_closed",
                       f"Closed port {port_to_close.number} "
                       f"({port_to_close.service}) on {target.hostname}")

        alert = self.ids.record_defender_action(
            f"Closed port {port_to_close.number}/{port_to_close.service}",
            target.ip_address
        )
        return alert

    def toggle_firewall(self) -> Optional[NetworkAlert]:
        """
        Action: Toggle firewall on/off.
        When activated, adds block rules for the known attacker IP.
        """
        action = self.actions["firewall"]
        if not action.is_ready:
            return None

        # Use the firewall's own cooldown logic too
        toggled = self.firewall.toggle()
        if not toggled:
            return None

        action.use()

        if self.firewall.active:
            self.firewall.add_rule("10.0.0.99")   # Attacker's IP
            self.score.add("firewall_activated", "Firewall activated")
            msg = ("Firewall ACTIVATED — blocking external traffic. "
                   "Attacker IP 10.0.0.99 added to block list.")
        else:
            msg = "Firewall DEACTIVATED — network is exposed."

        alert = self.ids.record_defender_action(
            f"Firewall {'ON' if self.firewall.active else 'OFF'}",
            "NETWORK PERIMETER"
        )
        alert.message = msg
        return alert

    def patch_node(self, node: Optional[NetworkNode] = None) -> Optional[NetworkAlert]:
        """
        Action: Apply security patch to a node.
        Restores health, closes a port, and clears vulnerability status.
        """
        action = self.actions["patch"]
        if not action.is_ready:
            return None

        target = node or self.selected_node
        if not target:
            target = self._most_damaged_node()
        if not target or target.status == NodeStatus.COMPROMISED:
            return None

        action.use()
        old_health = target.health
        target.patch()
        target.reset_status()

        self.score.add("node_patched",
                       f"Patched {target.hostname} "
                       f"(+{target.health - old_health}HP)")

        alert = self.ids.record_defender_action(
            f"Security patch applied (health: {old_health}→{target.health})",
            target.ip_address
        )
        return alert

    def deploy_honeypot(self) -> Optional[NetworkAlert]:
        """
        Action: Deploy a honeypot decoy.
        Slows attacker scanning/attack rate for a duration.
        """
        action = self.actions["honeypot"]
        if not action.is_ready:
            return None

        action.use()
        self._honeypot_active = True
        self._honeypot_end = time.time() + 10.0  # 10s duration

        self.score.add("honeypot_deployed", "Honeypot deployed")

        alert = self.ids.record_defender_action(
            "HONEYPOT deployed — attacker activity being misdirected",
            "DECOY NODE"
        )
        alert.message = ("Honeypot ACTIVE for 10 seconds. Attacker is "
                         "wasting resources on decoy system.")
        return alert

    def emergency_lockdown(self) -> Optional[NetworkAlert]:
        """
        Action: Emergency lockdown — close ALL open ports on all nodes.
        High cost action, used as last resort.
        """
        action = self.actions["lockdown"]
        if not action.is_ready:
            return None

        action.use()
        closed_count = 0

        for node in self.nodes:
            if not node.is_compromised:
                for port in node.open_ports:
                    port.close()
                    closed_count += 1
                if node.status not in (NodeStatus.COMPROMISED,):
                    node.status = NodeStatus.SECURE

        self.score.add("lockdown_activated",
                       f"Emergency lockdown — {closed_count} ports closed")

        alert = self.ids.record_defender_action(
            f"EMERGENCY LOCKDOWN: {closed_count} ports closed across all nodes",
            "ALL NODES"
        )
        alert.message = (f"🔒 LOCKDOWN ACTIVE — {closed_count} ports sealed. "
                         f"Network hardened temporarily.")
        alert.severity = AlertSeverity.WARNING
        return alert

    # ------------------------------------------------------------------
    # Honeypot Status
    # ------------------------------------------------------------------

    @property
    def honeypot_active(self) -> bool:
        if self._honeypot_active and time.time() > self._honeypot_end:
            self._honeypot_active = False
        return self._honeypot_active

    @property
    def honeypot_slowdown(self) -> float:
        """Returns a speed multiplier (< 1.0) when honeypot is active."""
        return 2.5 if self.honeypot_active else 1.0

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _most_vulnerable_node(self) -> Optional[NetworkNode]:
        """Find the node most at risk."""
        candidates = [
            n for n in self.nodes
            if n.status in (NodeStatus.VULNERABLE, NodeStatus.UNDER_ATTACK,
                            NodeStatus.SCANNING)
        ]
        if not candidates:
            candidates = [n for n in self.nodes if n.open_ports
                          and not n.is_compromised]
        return min(candidates, key=lambda n: n.health) if candidates else None

    def _most_damaged_node(self) -> Optional[NetworkNode]:
        """Find the node with least health (excluding fully compromised)."""
        candidates = [
            n for n in self.nodes
            if n.health < 100 and not n.is_compromised
        ]
        return min(candidates, key=lambda n: n.health) if candidates else None

    # ------------------------------------------------------------------
    # Game Over Checks
    # ------------------------------------------------------------------

    def check_win_condition(self, current_wave: int, target_waves: int) -> bool:
        """
        Player wins if they survive the target number of waves and the server is not compromised.
        """
        server = next((n for n in self.nodes if n.is_server), None)
        if server is None or server.is_compromised:
            return False
        return current_wave > target_waves

    def check_loss_condition(self) -> bool:
        """Player loses if the server is fully compromised."""
        server = next((n for n in self.nodes if n.is_server), None)
        return server is not None and server.is_compromised

    def network_security_score(self) -> int:
        """
        Compute a 0-100 network security score based on node health.
        Used for the dashboard health bar.
        """
        if not self.nodes:
            return 0
        return int(sum(n.health for n in self.nodes) / len(self.nodes))
