import os
import json
from unittest.mock import patch
import pytest

from high_scores import (
    load_high_scores, save_high_score, SCORES_FILE,
    load_tutorial_flag, save_tutorial_flag
)

@pytest.fixture(autouse=True)
def clean_scores_file():
    """Ensure SCORES_FILE does not exist or is clean before/after tests."""
    if os.path.exists(SCORES_FILE):
        os.remove(SCORES_FILE)
    yield
    if os.path.exists(SCORES_FILE):
        os.remove(SCORES_FILE)

def test_load_empty_scores():
    assert load_high_scores() == []

def test_save_scores():
    # Save a first score
    scores = save_high_score(500, "MEDIUM", "B")
    assert len(scores) == 1
    assert scores[0]["score"] == 500
    assert scores[0]["difficulty"] == "MEDIUM"
    assert scores[0]["grade"] == "B"
    assert "date" in scores[0]

    # Save a second, higher score
    scores = save_high_score(750, "HARD", "A")
    assert len(scores) == 2
    assert scores[0]["score"] == 750  # Sorted descending
    assert scores[1]["score"] == 500

    # Save more to exceed limit (MAX_SCORES=5)
    save_high_score(300, "EASY", "C")
    save_high_score(400, "MEDIUM", "C")
    save_high_score(600, "HARD", "B")
    scores = save_high_score(100, "EASY", "D")  # 6th score, should be dropped
    
    assert len(scores) == 5
    assert scores[0]["score"] == 750
    assert scores[-1]["score"] == 300
    assert 100 not in [s["score"] for s in scores]

def test_tutorial_flag_persistence():
    # 1. Defaults to False when file doesn't exist
    assert load_tutorial_flag() is False

    # 2. Saving True makes it load True
    save_tutorial_flag(True)
    assert load_tutorial_flag() is True

    # 3. Save a high score, check that tutorial flag is preserved as True
    save_high_score(800, "HARD", "A")
    assert load_tutorial_flag() is True
    assert len(load_high_scores()) == 1

    # 4. Saving False makes it load False and preserves scores
    save_tutorial_flag(False)
    assert load_tutorial_flag() is False
    assert len(load_high_scores()) == 1
