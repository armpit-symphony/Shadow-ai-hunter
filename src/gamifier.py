from risk_analyzer import simulate_what_if

def gamify_audit(scenario):
    """Gamify with scores based on simulation."""
    outcome = simulate_what_if(scenario)
    score = 100 - len(outcome) * 10  # Arbitrary game score
    return score
