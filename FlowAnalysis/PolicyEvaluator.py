import json

class PolicyEvaluator:
  def __init__(self, policies):
    self.policies = [self._load_policy(p) for p in policies]

  def _load_policy(self, policy):
    if type(policy) is str:
      with open(policy) as f:
        return json.load(f)
    else:
      return policy
