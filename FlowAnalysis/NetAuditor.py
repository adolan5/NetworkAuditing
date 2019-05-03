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
      req = self._generate_request(current_flow)
      print(req)

  def _generate_request(self, flow):
    current_packet = flow.packet_stats[-1]
    flow_stats = flow.get_aggregate_stats()
    itx_stats = flow.interactions[-1].get_aggregate_stats()
    req = {
        'packet': {
          'src_addr': current_packet.get('src_addr'),
          'dst_addr': current_packet.get('dst_addr'),
          'payload_len': current_packet.get('pkt_len'),
          'relative_time': current_packet.get('rel_time')
          },
        'network_state': {
          'current_flow': {
            'duration': flow_stats.get('duration'),
            'num_interactions': flow_stats.get('num_interactions'),
            'total_payload_bytes': flow_stats.get('total_bytes'),
            'total_bytes_by_source': flow_stats.get('total_by_src')
            },
          'current_interaction': {
            'duration': itx_stats.get('duration'),
            'total_bytes': itx_stats.get('total_bytes'),
            'total_bytes_by_source': itx_stats.get('total_lens')
            }
          }
        }
    return req
