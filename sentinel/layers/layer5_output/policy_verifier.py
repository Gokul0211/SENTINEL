import yaml
import os

POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "sentinel_policy.yaml")

def load_policy():
    try:
        with open(POLICY_PATH, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {}

def verify_policy(response: str) -> list[str]:
    """
    Verify response against output policy.
    Returns a list of policy violations.
    """
    policy = load_policy()
    if not policy or "output_policy" not in policy:
        return []
        
    violations = []
    out_pol = policy["output_policy"]
    resp_lower = response.lower()
    
    # Check forbidden topics
    if "forbidden_topics" in out_pol:
        for topic in out_pol["forbidden_topics"]:
            # Simple keyword matching for demo. In production, use embeddings/classifier.
            keywords = topic.split("_")
            if any(kw in resp_lower for kw in keywords):
                violations.append(f"Forbidden topic detected: {topic}")
                
    # Check required disclaimers
    if "required_disclaimers" in out_pol:
        for req in out_pol["required_disclaimers"]:
            cond = req["condition"].lower()
            # Crude check if condition words are in response
            if any(w in resp_lower for w in cond.split() if len(w) > 4):
                if req["disclaimer"].lower() not in resp_lower:
                    violations.append(f"Missing required disclaimer for condition: {req['condition']}")
                    
    return violations
