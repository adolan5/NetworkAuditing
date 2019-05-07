import json
import random
from scapy.all import *

class InputFuzzer:
  def __init__(self, capture, policy):
    all_packets = rdpcap(capture)
    self.packets = all_packets.filter(lambda x: scapy.layers.inet.TCP in x.layers())
    if type(policy) is str:
      with open(policy) as f:
        policy = json.load(f)

    self.policy = policy

  def fuzz(self):
    new_list = scapy.plist.PacketList()
    self._fuzz_duration(new_list)
    return new_list

  def _fuzz_duration(self, new_list):
    rand_packet = random.choice(self.packets)
    original_time = rand_packet.time
    policy_time = self.policy.get('interaction').get('max_duration') / 1000
    curr_time = original_time

    for i in range(random.randrange(500)):
      new_packet = rand_packet.copy()
      curr_time = curr_time + random.random() * 0.5
      new_packet.time = curr_time
      new_list.append(new_packet)

    if curr_time - original_time > policy_time:
      print('Time constraint invalidated')
