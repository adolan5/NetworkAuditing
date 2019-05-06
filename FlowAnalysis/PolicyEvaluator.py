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

    validities = []
    validities.append(self._check_endpoints(relevant_policy, request.get('packet')))
    validities.append(self._check_interaction(relevant_policy, request.get('network_state').get('current_interaction')))
    print(validities)
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
    base_policy = self.policies[0]

    src = ipaddress.IPv4Address(packet_info.get('src_addr'))
    dst = ipaddress.IPv4Address(packet_info.get('dst_addr'))
    device = dst
    endpoint = src

    for n in base_policy.get('devices'):
      if src in n:
        device = src
        endpoint = dst
        break

    base_policy['device'] = device
    base_policy['endpoint'] = endpoint
    return base_policy

  def _check_endpoints(self, policy, packet):
    for n in policy.get('flow').get('endpoints'):
      if policy.get('endpoint') in n:
        return True
    return False

  def _check_interaction(self, policy, itx):
    if (itx.get('duration') * 1000) > policy.get('interaction').get('max_duration'):
      return False

    if itx.get('total_bytes') > policy.get('interaction').get('max_total_payload_bytes'):
      return False

    device_bytes = itx.get('total_bytes_by_source').get(str(policy.get('device')), 0)
    endpoint_bytes = itx.get('total_bytes_by_source').get(str(policy.get('endpoint')), 0)

    if device_bytes > policy.get('interaction').get('device').get('total_sent_bytes'):
      return False

    if endpoint_bytes > policy.get('interaction').get('endpoint').get('total_sent_bytes'):
      return False

    return True
