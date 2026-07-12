import json
import os
import time

SCORES_FILE = "scores.json"
MAX_SCORES = 5

def load_high_scores():
    """Load high scores from JSON file, returning a list of dicts."""
    if not os.path.exists(SCORES_FILE):
        return []
    try:
        with open(SCORES_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return data.get("high_scores", [])
    except Exception:
        pass
    return []

def save_high_score(score: int, difficulty: str, grade: str):
    """Add a new score, sort them, and save top 5 to scores.json, preserving tutorial flag."""
    scores = load_high_scores()
    
    new_entry = {
        "score": score,
        "difficulty": difficulty,
        "date": time.strftime("%Y-%m-%d %H:%M"),
        "grade": grade
    }
    
    scores.append(new_entry)
    # Sort by score descending
    scores.sort(key=lambda x: x["score"], reverse=True)
    # Keep top 5
    scores = scores[:MAX_SCORES]
    
    has_seen = load_tutorial_flag()
    
    output_data = {
        "high_scores": scores,
        "has_seen_tutorial": has_seen
    }
    
    try:
        with open(SCORES_FILE, "w") as f:
            json.dump(output_data, f, indent=4)
    except Exception:
        pass
    return scores

def load_tutorial_flag() -> bool:
    """Check if the user has seen the tutorial, default to False."""
    if not os.path.exists(SCORES_FILE):
        return False
    try:
        with open(SCORES_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data.get("has_seen_tutorial", False)
    except Exception:
        pass
    return False

def save_tutorial_flag(has_seen: bool):
    """Save the has_seen_tutorial flag, preserving high scores."""
    scores = load_high_scores()
    output_data = {
        "high_scores": scores,
        "has_seen_tutorial": has_seen
    }
    try:
        with open(SCORES_FILE, "w") as f:
            json.dump(output_data, f, indent=4)
    except Exception:
        pass
