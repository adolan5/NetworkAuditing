import json
from FlowAnalysis import FlowAnalyzer

class NetAuditor:
  def __init__(self, pdp, capture):
    self.pdp = pdp
    if type(capture) is str:
      with open(capture) as f:
        self._raw_packets = json.load(f)
    else:
      self._raw_packets = capture

    self.audit()

  def audit(self):
    pass
