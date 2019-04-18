from scipy import stats
import numpy as np
from matplotlib import pyplot as plt
from matplotlib import ticker

class Flow:
  """Simple representation of a flow.
  Defined as a number of packets that share particular properties, per RFC 3917.
  """

  def __init__(self, src, dst, src_port, dst_port):
    self.src_addr = src
    self.dst_addr = dst
    self.src_port = src_port
    self.dst_port = dst_port

    self.is_open = True
    self.packets = []
    self.packet_stats = []

  def __repr__(self):
    return '<Flow ({}:{} <--> {}:{}) of {} packets; Open: {}>'.format(self.src_addr, self.src_port,
        self.dst_addr, self.dst_port, len(self.packets), self.is_open)

  def __iter__(self):
    for p in self.packet_stats:
      yield p

  def append(self, packet):
    self.packets.append(packet)
    self.packet_stats.append(self._get_stats_for_packet(packet))

  def get_start_end_times(self):
    try:
      times = [float(p.get('_source').get('layers').get('frame').get('frame.time_epoch')) for p in self.packets]
      start = min(times)
      end = max(times)
    except ValueError:
      start = None
      end = None
    return (start, end)

  def get_duration(self):
    start_time, end_time = self.get_start_end_times()
    return end_time - start_time

  def get_bitrate(self):
    duration = self.get_duration()
    aggregate_bytes = sum([float(p.get('_source').get('layers').get('frame').get('frame.len')) for p in self.packets])

    try:
      return (aggregate_bytes / duration) * 8
    except:
      return 0

  def get_aggregate_stats(self, duration_start=0, duration_end=None):
    if duration_end is None:
      duration_end = self.get_duration()

    filtered_stats = [p for p in self.packet_stats if p.get('rel_time') >= duration_start and p.get('rel_time') <= duration_end]
    pkts_no_acks = [p for p in filtered_stats if not (p.get('is_ack') and p.get('pkt_len') == 0)]

    src_lens = [p.get('pkt_len') for p in pkts_no_acks if p.get('src_addr') == self.src_addr]
    dst_lens = [p.get('pkt_len') for p in pkts_no_acks if p.get('src_addr') == self.dst_addr]

    interactions = self.get_packet_interactions()
    int_durations = [i[-1].get('rel_time') - i[0].get('rel_time') for i in interactions]

    aggregate_stats = {
        'mode_src_len': stats.mode(src_lens)[0][0] if src_lens else np.nan,
        'mode_dst_len': stats.mode(dst_lens)[0][0] if dst_lens else np.nan,
        'avg_src_len': stats.tmean(src_lens),
        'avg_dst_len': stats.tmean(dst_lens),
        'max_src_len': max(src_lens),
        'max_dst_len': max(dst_lens),
        'num_interactions': len(interactions),
        'avg_interaction_duration': stats.tmean(int_durations),
        'max_interaction_duration': max(int_durations),
        'min_interaction_duration': min(int_durations),
        'overall_bitrate': self.get_bitrate()
        }
    return aggregate_stats

  def _get_stats_for_packet(self, packet):
    pkt_stats = {}
    frame_info = packet.get('_source').get('layers').get('frame')
    ip_info = packet.get('_source').get('layers').get('ip')
    tcp_info = packet.get('_source').get('layers').get('tcp')

    pkt_stats['src_addr'] = ip_info.get('ip.src')
    pkt_stats['dst_addr'] = ip_info.get('ip.dst')
    pkt_stats['pkt_len'] = int(tcp_info.get('tcp.len'))
    pkt_stats['rel_time'] = float(frame_info.get('frame.time_epoch')) - self.get_start_end_times()[0]
    pkt_stats['is_ack'] = (tcp_info.get('tcp.flags_tree').get('tcp.flags.ack') == '1')
    return pkt_stats

  def get_packet_interactions(self, sep_time=0.5):
    interactions = []
    current_interaction = []
    for i, p in enumerate(self.packet_stats):
      current_interaction.append(p)
      delta = self.packet_stats[(i + 1) % len(self.packet_stats)].get('rel_time') - p.get('rel_time')
      if delta > sep_time or i == (len(self.packet_stats) - 1):
        interactions.append(current_interaction)
        current_interaction = []
    return interactions

  def get_packets_graph(self, duration_start=0, duration_end=None):
    if duration_end is None:
      duration_end = self.get_duration()

    src_packets = [p for p in self.packet_stats if p.get('src_addr') == self.src_addr and
        p.get('rel_time') >= duration_start and p.get('rel_time') <= duration_end]
    dst_packets = [p for p in self.packet_stats if p.get('src_addr') == self.dst_addr and
        p.get('rel_time') >= duration_start and p.get('rel_time') <= duration_end]

    src_lens = [p.get('pkt_len') for p in src_packets]
    dst_lens = [-p.get('pkt_len') for p in dst_packets]

    fig, ax = plt.subplots(figsize=(15,10))
    ax.scatter([p.get('rel_time') for p in src_packets], src_lens, label=self.src_addr)
    ax.scatter([p.get('rel_time') for p in dst_packets], dst_lens, label=self.dst_addr)
    ax.axhline(0, color='gray', linestyle=':', label='No payload length (e.g., ACK)')

    ax.set_title('Packets between {} and {} from {} to {} seconds'.format(self.src_addr, self.dst_addr, duration_start, duration_end))
    ax.set_xlabel('Relative duration (seconds)')
    ax.set_ylabel('Packet length (bytes)')
    ax.legend(loc=4, title='Sender of Packet')

    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: '{}'.format(abs(x))))
    return (fig, ax)
