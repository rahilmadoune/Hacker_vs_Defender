import time
from unittest.mock import patch
import pytest

from attacker_ai import AttackerAI, AttackPhase, Difficulty, Packet
from network import build_network, NodeStatus, PortStatus

def test_attacker_init():
    attacker = AttackerAI(difficulty=Difficulty.EASY)
    assert attacker.phase == AttackPhase.IDLE
    assert attacker.wave_number == 1
    assert not attacker.in_wave


def test_attacker_phase_transitions():
    # Build a controlled network
    net = build_network()
    nodes = net["nodes"]
    firewall = net["firewall"]
    ids = net["ids"]

    attacker = AttackerAI(difficulty=Difficulty.EASY)
    attacker.start()
    assert attacker.phase == AttackPhase.RECONNAISSANCE

    # We manually trigger reconnaissance to move it forward
    # Discovering all nodes transitions to SCANNING
    for _ in range(10):  # Run update multiple times to cover all nodes
        attacker._last_scan_time = 0
        attacker._last_attack_time = 0
        attacker.update(nodes, firewall, ids)
        if attacker.phase == AttackPhase.SCANNING:
            break
    assert attacker.phase == AttackPhase.SCANNING

    # Scan nodes to transition to EXPLOITATION
    for _ in range(20):
        attacker._last_scan_time = 0
        attacker._last_attack_time = 0
        attacker.update(nodes, firewall, ids)
        if attacker.phase == AttackPhase.EXPLOITATION:
            break
    assert attacker.phase == AttackPhase.EXPLOITATION

    # Manually compromise two nodes to test lateral movement phase transition (PERSISTENCE)
    compromised_count = 0
    for node in nodes:
        if not node.is_server:
            node.status = NodeStatus.COMPROMISED
            compromised_count += 1
            if compromised_count >= 2:
                break
    
    attacker.nodes_compromised = compromised_count
    attacker._evaluate_phase_transition(nodes)
    assert attacker.phase == AttackPhase.PERSISTENCE

    # Manually compromise the server to test SUCCEEDED transition
    server = next(n for n in nodes if n.is_server)
    server.status = NodeStatus.COMPROMISED
    
    # Run lateral movement which detects server compromise
    attacker._do_persistence(nodes, firewall, ids)
    assert attacker.phase == AttackPhase.SUCCEEDED


def test_exploit_escalation_over_time():
    attacker = AttackerAI(difficulty=Difficulty.EASY)
    attacker.start()
    base_chance = attacker.profile["exploit_chance"]
    assert attacker._current_exploit_chance == base_chance

    # Set start_time to 100 seconds in the past to trigger escalation
    attacker._start_time = time.time() - 100
    
    net = build_network()
    attacker.update(net["nodes"], net["firewall"], net["ids"])
    assert attacker._current_exploit_chance > base_chance


def test_wave_timing_and_increments():
    attacker = AttackerAI(difficulty=Difficulty.EASY)
    attacker.start()
    assert attacker.wave_number == 1

    net = build_network()
    interval = attacker.profile["wave_interval"]

    # Mock time to exceed wave_interval
    with patch("time.time", return_value=time.time() + interval + 1):
        alerts = attacker.update(net["nodes"], net["firewall"], net["ids"])
        assert attacker.wave_number == 2
        assert attacker.in_wave is True
        assert any("ATTACK WAVE 2 INCOMING" in alert.message for alert in alerts)


def test_speed_multiplier_scaling():
    attacker = AttackerAI(difficulty=Difficulty.EASY)
    attacker.start()

    net = build_network()
    nodes = net["nodes"]
    firewall = net["firewall"]
    ids = net["ids"]

    # easy intervals: scan_interval = 4.0, attack_interval = 6.0
    scan_int = attacker.profile["scan_interval"]
    attack_int = attacker.profile["attack_interval"]

    start_time = time.time()
    attacker._last_scan_time = start_time
    attacker._last_attack_time = start_time

    # Scenario 1: With speed_multiplier=2.5 (honeypot active), intervals are scaled.
    # At time offset 5.0 (which is > 4.0 but < 4.0 * 2.5 = 10.0), scan should NOT trigger.
    with patch("time.time", return_value=start_time + 5.0):
        attacker.phase = AttackPhase.RECONNAISSANCE
        alerts = attacker.update(nodes, firewall, ids, speed_multiplier=2.5)
        # Should not have scanned (scan interval now effectively 10.0s)
        assert attacker._last_scan_time == start_time
        assert len(alerts) == 0

    # Scenario 2: At time offset 11.0 (which is > 10.0), scan should trigger even with speed_multiplier=2.5
    with patch("time.time", return_value=start_time + 11.0):
        attacker.phase = AttackPhase.RECONNAISSANCE
        alerts = attacker.update(nodes, firewall, ids, speed_multiplier=2.5)
        assert attacker._last_scan_time == start_time + 11.0
        assert len(alerts) > 0
