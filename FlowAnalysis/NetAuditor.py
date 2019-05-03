import json
from FlowAnalysis import FlowAnalyzer

class NetAuditor:
  def __init__(self, pdp, capture):
    self.pdp = pdp
    self.flow_analyzer = FlowAnalyzer()

    if type(capture) is str:
      with open(capture) as f:
        self._raw_packets = json.load(f)
    else:
      self._raw_packets = capture

    self.audit()

  def audit(self):
    for p in self._raw_packets:
      current_flow = self.flow_analyzer.append_packet(p)
      if current_flow is None:
        continue
      print(p)
      req = self._generate_request(current_flow)

  def _generate_request(self, flow):
    print(flow.packet_stats[-1])
    return None
