import json

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
    self.tcp_flows = {}

    if type(data) is str:
      with open(data) as f:
        self._raw_data = json.load(f)
    else:
      self._raw_data = data

    self._analyze_data()

  def _analyze_data(self):
    self.tcp_flows = self._get_tcp_flows()

  def _get_tcp_flows(self):
    flows = {}
    all_tcp = [p for p in self._raw_data if p.get('_source').get('layers').get('tcp')]

    for p in all_tcp:
      tcp_attribs = p.get('_source').get('layers').get('tcp')
      ip_attribs = p.get('_source').get('layers').get('ip')

      addresses = frozenset((ip_attribs.get('ip.src'), ip_attribs.get('ip.dst')))
      ports = frozenset((tcp_attribs.get('tcp.srcport'), tcp_attribs.get('tcp.dstport')))
      composite_tcp_key = (addresses, ports)

      flow_collection = flows.setdefault(composite_tcp_key, [Flow()])

      self._decide_flow_action(flow_collection, p)

    return flows

  def _decide_flow_action(self, flow_collection, pkt):
    flow_to_append_to = flow_collection[-1]
    if flow_to_append_to.is_open is not True:
      flow_to_append_to = Flow()
      flow_collection.append(flow_to_append_to)

    flow_to_append_to.packets.append(pkt)

class Flow:
  """Simple representation of a flow.
  Defined as a number of packets that share particular properties, per RFC 3917.
  """

  def __init__(self):
    self.is_open = True
    self.packets = []

  def __repr__(self):
    return '<Flow of {} packets; Open: {}>'.format(len(self.packets), self.is_open)
