import json
from FlowAnalysis._flow import Flow

class FlowAnalyzer:
  """The FlowAnalyzer class.
  This class is responsible for parsing PCAP data, input in JSON format (formatted by tshark),
  and extracting key characteristics of it related to security auditing at the network level.
  Flows will be extracted, and different characteristics will be gathered and may be output in
  different formats.
  """

  def __init__(self, data=None):
    """A FlowAnalyzer may be constructed with a string that represents a relative path to a JSON
    file containing PCAP data, formatted with tshark, or a dictionary of the same format.
    """
    self.flow_map = {}

    if type(data) is str:
      with open(data) as f:
        raw_data = json.load(f)
        self._extract_all_data(raw_data)
    elif data:
      self._extract_all_data(data)

  def append_packet(self, pkt):
    if pkt.get('_source').get('layers').get('tcp'):
      return self._append_tcp_packet(pkt)

  def _append_tcp_packet(self, pkt):
    ip_attribs = pkt.get('_source').get('layers').get('ip')
    tcp_attribs = pkt.get('_source').get('layers').get('tcp')

    composite_tcp_key = {
        'src_addr': ip_attribs.get('ip.src'),
        'dst_addr': ip_attribs.get('ip.dst'),
        'src_port': tcp_attribs.get('tcp.srcport'),
        'dst_port': tcp_attribs.get('tcp.dstport')
        }

    flow_collection = self.flow_map.setdefault(frozenset(composite_tcp_key.values()), [Flow(composite_tcp_key)])

    # TODO: This is a pretty naive way of distinguishing flows. No analysis of sequence numbers
    # involved. Can it be beaten?
    is_fin = tcp_attribs.get('tcp.flags_tree').get('tcp.flags.fin') is '1'
    is_rst = tcp_attribs.get('tcp.flags_tree').get('tcp.flags.reset') is '1'
    is_ack = tcp_attribs.get('tcp.flags_tree').get('tcp.flags.ack') is '1'

    flow_to_append_to = flow_collection[-1]

    if is_fin or is_rst:
      flow_to_append_to.is_open = False
    elif not flow_to_append_to.is_open and not is_ack:
      flow_to_append_to = Flow(composite_tcp_key)
      flow_collection.append(flow_to_append_to)

    flow_to_append_to.append(pkt)
    return flow_to_append_to

  def _extract_all_data(self, data):
    for p in data:
      self.append_packet(p)

  def get_tcp_flows(self):
    all_flows = sorted([flow for collection in self.flow_map.values() for flow in collection], key=lambda x: x.get_start_end_times()[0])
    return all_flows

  # def _decide_flow_action(self, composite_key, pkt):
