import json
import ipaddress

# TODO: DELME
from FlowAnalysis import StatsSerializer

class PolicyEvaluator:
  def __init__(self, policies):
    self.policies = [self._load_policy(p) for p in policies]

  def evaluate(self, request):
    relevant_policy = self._combine_policies(request.get('packet'))

    # print(json.dumps(relevant_policy, indent=2, cls=StatsSerializer))
    # print(json.dumps(request, indent=2, cls=StatsSerializer))

    valid_endpoint = self._check_endpoints(relevant_policy, request.get('packet'))
    print(valid_endpoint)
    return False

  def _load_policy(self, policy):
    if type(policy) is str:
      with open(policy) as f:
        policy = json.load(f)

    policy['devices'] = [self._convert_addr(i) for i in policy.get('devices', [])]
    policy['flow']['endpoints'] = [self._convert_addr(i) for i in policy.get('flow').get('endpoints')]
    return policy

  def _convert_addr(self, ip_string):
    try:
      return ipaddress.IPv4Network(ip_string)
    except ipaddress.AddressValueError:
      return None

  def _combine_policies(self, packet_info):
    # TODO: This method should pull any and all relevant policies (probably by referencing the
    # IP addresses, and combine them.
    # For now, this will just use the first policy.
    return self.policies[0]

  def _check_endpoints(self, policy, packet):
    is_valid = False
    src = ipaddress.IPv4Address(packet.get('src_addr'))
    dst = ipaddress.IPv4Address(packet.get('dst_addr'))
    for n in policy.get('flow').get('endpoints'):
      if src in n or dst in n:
        is_valid = True
        break
    return is_valid
