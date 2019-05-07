import json
from matplotlib import pyplot as plt
from FlowAnalysis import NetAuditor, PolicyEvaluator, StatsSerializer

capture_files = ['./data/captures/FormalOnOff.json']
policies = ['./data/policies/Handshake.json']

pdp = PolicyEvaluator(policies)
audit = NetAuditor(pdp, capture_files[0])

flows = audit.flow_analyzer.get_tcp_flows()

for f in flows:
  print(f)
  """
  f.get_packets_graph()
  plt.show()
  """
