import time
from unittest.mock import patch
import pytest

from defender_actions import DefenderController, ScoreTracker, DefenderAction
from network import build_network, NodeStatus, PortStatus, NetworkNode, Port

def test_score_tracker_points_and_grade():
    tracker = ScoreTracker()
    assert tracker.total_score == 0
    assert tracker.get_grade() == "D"

    # Add scan points
    tracker.add("scan_completed")
    assert tracker.total_score == 20

    # Add multiple points to reach A grade
    tracker.add("port_closed")           # +50 (70)
    tracker.add("node_patched")          # +75 (145)
    tracker.add("lockdown_activated")    # +80 (225)
    tracker.add("game_won")              # +300 (525)
    assert tracker.total_score == 525
    assert tracker.get_grade() == "B"

    tracker.add("wave_survived")         # +100 (625)
    tracker.add("wave_survived")         # +100 (725)
    tracker.add("wave_survived")         # +100 (825)
    assert tracker.get_grade() == "A"

    tracker.add("wave_survived")         # +100 (925)
    tracker.add("wave_survived")         # +100 (1025)
    assert tracker.get_grade() == "A+"

    # Penalties
    tracker.add("node_compromised")      # -150 (875)
    assert tracker.total_score == 875
    assert tracker.get_grade() == "A"


def test_defender_cooldown_enforcement():
    net = build_network()
    tracker = ScoreTracker()
    defender = DefenderController(net["nodes"], net["firewall"], net["ids"], tracker)

    # Trigger scan action
    action = defender.actions["scan"]
    assert action.is_ready is True
    
    alert = defender.scan_network()
    assert alert is not None
    assert action.is_ready is False

    # Try triggering it again while on cooldown
    alert2 = defender.scan_network()
    assert alert2 is None  # blocked by cooldown

    # Mock time passing
    with patch("time.time", return_value=time.time() + action.cooldown + 1):
        assert action.is_ready is True


def test_win_loss_conditions():
    net = build_network()
    nodes = net["nodes"]
    tracker = ScoreTracker()
    defender = DefenderController(nodes, net["firewall"], net["ids"], tracker)

    server = next(n for n in nodes if n.is_server)

    # Initial state is not won, not lost
    assert defender.check_loss_condition() is False
    assert defender.check_win_condition(current_wave=1, target_waves=3) is False

    # Server compromise triggers loss
    server.status = NodeStatus.COMPROMISED
    assert defender.check_loss_condition() is True
    assert defender.check_win_condition(current_wave=4, target_waves=3) is False  # Cannot win if compromised

    # Reset server
    server.status = NodeStatus.SECURE
    assert defender.check_loss_condition() is False

    # Win condition met when current wave > target waves
    assert defender.check_win_condition(current_wave=4, target_waves=3) is True
    assert defender.check_win_condition(current_wave=3, target_waves=3) is False
