import json
from matplotlib import pyplot as plt
from FlowAnalysis import NetAuditor, PolicyEvaluator, StatsSerializer

capture_files = ['./data/captures/FormalOnOff.json']
policies = ['./data/policies/Handshake.json']

pdp = PolicyEvaluator(policies)
valid_audit = NetAuditor(pdp, capture_files[0])

invalid_audit = NetAuditor(pdp, './data/captures/fuzzed.json')

flows = valid_audit.flow_analyzer.get_tcp_flows()
# flows = invalid_audit.flow_analyzer.get_tcp_flows()

for f in flows:
  print(f)
  f.get_packets_graph(draw_highlights=False, highlight_invalid=True)
  plt.show()
