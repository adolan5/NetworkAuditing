import json
import random
import ipaddress
from scapy.all import *

class InputFuzzer:
  def __init__(self, capture):
    all_packets = rdpcap(capture)
    self.packets = all_packets.filter(lambda x: scapy.layers.inet.TCP in x.layers())

  def fuzz(self):
    new_list = scapy.plist.PacketList()
    self._fuzz_duration(new_list)
    self._fuzz_sizes(new_list)
    self._fuzz_endpoints(new_list)
    return new_list

  def _fuzz_duration(self, new_list):
    rand_packet = random.choice(self.packets)
    original_time = rand_packet.time
    curr_time = original_time

    for i in range(random.randrange(500)):
      new_packet = rand_packet.copy()
      curr_time = curr_time + random.random() * 0.5
      new_packet.time = curr_time
      new_list.append(new_packet)

  def _fuzz_sizes(self, new_list):
    curr_time = new_list[-1].time + 10
    for i in range(random.randrange(500)):
      rand_packet = random.choice(self.packets).copy()
      new_payload_len = random.randrange(3000)
      payload_string = 'p' * new_payload_len
      rand_packet['TCP'].remove_payload()
      rand_packet.add_payload(scapy.packet.Raw(load=payload_string))

      rand_packet['IP'].len = None
      rand_packet['IP'].chksum = None
      rand_packet['TCP'].chksum = None
      rand_packet = Ether(bytes(rand_packet))

      rand_packet.time = curr_time
      curr_time = curr_time + random.random() * random.randrange(5)

      new_list.append(rand_packet)

  def _fuzz_endpoints(self, new_list):
    new_start_time = new_list[-1].time + 10
    curr_time = new_start_time
    num_packets = math.floor(0.05 * len(self.packets))
    packet_subset = random.choices(self.packets, k=num_packets)

    for pkt in packet_subset:
      p = pkt.copy()
      rand = random.random()
      if rand > 0.5 and rand < 0.75:
        p['IP'].src = str(ipaddress.IPv4Address(random.randrange(4294967296)))
      elif rand >= 0.75:
        p['IP'].dst = str(ipaddress.IPv4Address(random.randrange(4294967296)))
      p.time = curr_time
      curr_time = curr_time + 1
      new_list.append(p)
