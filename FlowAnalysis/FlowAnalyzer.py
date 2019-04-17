import json
from FlowAnalysis._flow import Flow

class FlowAnalyzer:
  """The FlowAnalyzer class.
  This class is responsible for parsing PCAP data, input in JSON format (formatted by tshark),
  and extracting key characteristics of it related to security auditing at the network level.
  Flows will be extracted, and different characteristics will be gathered and may be output in
  different formats.
  """

  def __init__(self, data):
    """A FlowAnalyzer may be constructed with a string that represents a relative path to a JSON
    file containing PCAP data, formatted with tshark, or a dictionary of the same format.
    """
    self.tcp_flows = []

    if type(data) is str:
      with open(data) as f:
        self._raw_data = json.load(f)
    else:
      self._raw_data = data

    self._extract_data()

  def _extract_data(self):
    self.tcp_flows = self._get_tcp_flows()

  def _get_tcp_flows(self):
    flows = {}
    all_tcp = [p for p in self._raw_data if p.get('_source').get('layers').get('tcp')]

    for p in all_tcp:
      tcp_attribs = p.get('_source').get('layers').get('tcp')
      ip_attribs = p.get('_source').get('layers').get('ip')

      addresses = (ip_attribs.get('ip.src'), ip_attribs.get('ip.dst'))
      ports = (tcp_attribs.get('tcp.srcport'), tcp_attribs.get('tcp.dstport'))
      composite_tcp_key = (frozenset(addresses), frozenset(ports))

      flow_collection = flows.setdefault(composite_tcp_key,
          [Flow(src=addresses[0], dst=addresses[1], src_port=ports[0], dst_port=ports[1])])

      self._decide_flow_action(flow_collection, p)

    all_flows = sorted([flow for collection in flows.values() for flow in collection], key=lambda x: x.get_start_end_times()[0])
    return all_flows

  def _decide_flow_action(self, flow_collection, pkt):
    tcp_attribs = pkt.get('_source').get('layers').get('tcp')
    ip_attribs = pkt.get('_source').get('layers').get('ip')

    # TODO: This is a pretty naive way of distinguishing flows. No analysis of sequence numbers
    # involved. Can it be beaten?
    is_fin = tcp_attribs.get('tcp.flags_tree').get('tcp.flags.fin') is '1'
    is_rst = tcp_attribs.get('tcp.flags_tree').get('tcp.flags.reset') is '1'
    is_ack = tcp_attribs.get('tcp.flags_tree').get('tcp.flags.ack') is '1'

    flow_to_append_to = flow_collection[-1]

    if is_fin or is_rst:
      flow_to_append_to.is_open = False
    elif not flow_to_append_to.is_open and not is_ack:
      flow_to_append_to = Flow()
      flow_collection.append(flow_to_append_to)

    flow_to_append_to.append(pkt)
