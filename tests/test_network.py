import time
from unittest.mock import patch
import pytest

from network import (
    Port, PortStatus, NetworkNode, NodeStatus, Firewall, IDS, AlertSeverity
)

def test_port_transitions():
    p = Port(number=80, service="HTTP", status=PortStatus.OPEN)
    assert p.status == PortStatus.OPEN
    assert not p.exploited

    p.close()
    assert p.status == PortStatus.CLOSED
    assert not p.exploited

    # Reset
    p.open()
    assert p.status == PortStatus.OPEN

    # Filter
    p.filter_by_firewall()
    assert p.status == PortStatus.FILTERED

    # Filter when already closed shouldn't change to FILTERED
    p.close()
    p.filter_by_firewall()
    assert p.status == PortStatus.CLOSED


def test_node_damage_and_compromise():
    ports = [Port(22, "SSH"), Port(80, "HTTP")]
    node = NetworkNode(
        node_id="test_node",
        ip_address="192.168.1.50",
        hostname="TEST-WS",
        ports=ports
    )
    assert node.health == 100
    assert not node.is_compromised
    assert node.status == NodeStatus.SECURE

    # Take minor damage
    node.take_damage(30)
    assert node.health == 70
    assert not node.is_compromised

    # Take fatal damage
    node.take_damage(80)
    assert node.health == 0
    assert node.is_compromised
    assert node.status == NodeStatus.COMPROMISED


def test_firewall_toggle_cooldown():
    firewall = Firewall()
    assert not firewall.active
    assert not firewall.is_on_cooldown

    # First toggle succeeds
    assert firewall.toggle() is True
    assert firewall.active is True
    assert firewall.is_on_cooldown

    # Immediately toggle again - should fail due to cooldown
    assert firewall.toggle() is False
    assert firewall.active is True  # state doesn't change

    # Mock time passing beyond cooldown
    with patch("time.time", return_value=time.time() + 20):
        assert not firewall.is_on_cooldown
        assert firewall.toggle() is True
        assert firewall.active is False


def test_firewall_traffic_filtering():
    firewall = Firewall()
    attacker_ip = "10.0.0.99"
    other_ip = "10.0.0.5"

    # Inactive firewall allows all traffic
    assert firewall.check_traffic(attacker_ip) is False

    # Active firewall with no rules allows all
    firewall.active = True
    assert firewall.check_traffic(attacker_ip) is False

    # Active firewall with attacker rule blocks attacker, allows other
    firewall.add_rule(attacker_ip)
    assert firewall.check_traffic(attacker_ip) is True
    assert firewall.check_traffic(other_ip) is False
    assert firewall.blocked_attempts == 1

    # Active firewall with wildcard rule blocks all
    firewall.rules = ["ALL"]
    assert firewall.check_traffic(other_ip) is True
    assert firewall.blocked_attempts == 2


def test_ids_alert_escalation():
    ids = IDS()
    source_ip = "10.0.0.99"
    target_ip = "192.168.1.101"

    # First two scans are warnings
    alert1 = ids.record_scan(source_ip, target_ip, 80)
    assert alert1.severity == AlertSeverity.WARNING
    assert "Port scan detected" in alert1.message

    alert2 = ids.record_scan(source_ip, target_ip, 443)
    assert alert2.severity == AlertSeverity.WARNING

    # Third scan reaches SCAN_THRESHOLD -> CRITICAL escalation
    alert3 = ids.record_scan(source_ip, target_ip, 22)
    assert alert3.severity == AlertSeverity.CRITICAL
    assert "REPEATED port scan" in alert3.message
    assert ids.scan_counter[source_ip] == 3
