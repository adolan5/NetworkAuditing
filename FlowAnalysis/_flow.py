from scipy import stats
import numpy as np
from matplotlib import pyplot as plt
from matplotlib import ticker
from matplotlib.collections import PatchCollection
from FlowAnalysis._interaction import Interaction

class Flow:
  """Simple representation of a flow.
  Defined as a number of packets that share particular properties, per RFC 3917.
  """

  def __init__(self, composite_key, interaction_sep_time=0.5):
    self.src_addr = composite_key.get('src_addr')
    self.dst_addr = composite_key.get('dst_addr')
    self.src_port = composite_key.get('src_port')
    self.dst_port = composite_key.get('dst_port')
    self._interaction_sep_time=interaction_sep_time

    self.is_open = True
    self.packets = []
    self.packet_stats = []
    self.interactions = [Interaction()]
    self.current_interaction = self.interactions[0]

  def __repr__(self):
    return '<Flow ({}:{} <--> {}:{}) of {} packets>'.format(self.src_addr, self.src_port,
        self.dst_addr, self.dst_port, len(self.packets))

  def __iter__(self):
    for p in self.packet_stats:
      yield p

  def __getitem__(self, key):
    return self.packet_stats[key]

  def append(self, packet):
    self.packets.append(packet)
    stat = self._get_stats_for_packet(packet)
    self.packet_stats.append(stat)

    previous_packet = self.current_interaction[-1] if self.current_interaction else None
    if previous_packet and (stat.get('rel_time') - previous_packet.get('rel_time')) > self._interaction_sep_time:
      self.current_interaction = Interaction()
      self.interactions.append(self.current_interaction)

    self.current_interaction.append(stat)

  def get_start_end_times(self):
    try:
      start = self.packet_stats[0].get('epoch_time')
      end = self.packet_stats[-1].get('epoch_time')
    except IndexError:
      start = None
      end = None
    return (start, end)

  def get_duration(self):
    start_time, end_time = self.get_start_end_times()
    return end_time - start_time

  def get_aggregate_stats(self, duration_start=0, duration_end=None):
    if duration_end is None:
      duration_end = self.get_duration()

    filtered_stats = self._filter_stats(duration_start, duration_end)
    filtered_interactions = self._filter_interactions(duration_start, duration_end)

    lens_by_src = {}
    for p in filtered_stats:
      lens_by_src.setdefault(p.get('src_addr'), []).append(p.get('pkt_len'))

    int_durations = [i.get_duration() for i in filtered_interactions]
    total_bytes = sum([p.get('pkt_len') for p in filtered_stats])

    aggregate_stats = {
        'duration': self.get_duration(),
        'avg_lens': {k: stats.tmean(v) for k,v in lens_by_src.items()},
        'max_lens': {k: max(v) for k,v in lens_by_src.items()},
        'total_by_src': {k: sum(v) for k,v in lens_by_src.items()},
        'num_interactions': len(filtered_interactions),
        'avg_interaction_duration': stats.tmean(int_durations) if int_durations else 0,
        'max_interaction_duration': max(int_durations) if int_durations else 0,
        'min_interaction_duration': min(int_durations) if int_durations else 0,
        'total_bytes': total_bytes
        }
    return aggregate_stats

  def _get_stats_for_packet(self, packet):
    pkt_stats = {}
    frame_info = packet.get('_source').get('layers').get('frame')
    ip_info = packet.get('_source').get('layers').get('ip')
    tcp_info = packet.get('_source').get('layers').get('tcp')
    start_time = self.get_start_end_times()[0]

    pkt_stats['src_addr'] = ip_info.get('ip.src')
    pkt_stats['dst_addr'] = ip_info.get('ip.dst')
    pkt_stats['pkt_len'] = int(tcp_info.get('tcp.len'))
    pkt_stats['rel_time'] = (float(frame_info.get('frame.time_epoch')) - start_time) if start_time else 0
    pkt_stats['epoch_time'] = float(frame_info.get('frame.time_epoch'))
    pkt_stats['is_ack'] = (tcp_info.get('tcp.flags_tree').get('tcp.flags.ack') == '1')
    return pkt_stats

  def _filter_stats(self, duration_start=0, duration_end=None):
    if duration_end is None:
      duration_end = self.get_duration()
    return [p for p in self.packet_stats if p.get('rel_time') >= duration_start and p.get('rel_time') <= duration_end]

  def _filter_interactions(self, duration_start=0, duration_end=None):
    if duration_end is None:
      duration_end = self.get_duration()
    filtered = [i.filter_by_time(duration_start, duration_end) for i in self.interactions]
    return [i for i in filtered if i]

  # Graphing utilities to represent flow visually
  def get_packets_graph(self, ax=None, duration_start=0, duration_end=None, draw_highlights=True, highlight_invalid=False):
    filtered_packets = self._filter_stats(duration_start, duration_end)
    filtered_interactions = self._filter_interactions(duration_start, duration_end)
    src_packets = [p for p in filtered_packets if p.get('src_addr') == self.src_addr]
    dst_packets = [p for p in filtered_packets if p.get('src_addr') == self.dst_addr]

    valid_src_packets = src_packets
    valid_dst_packets = dst_packets
    invalid_src_packets = []
    invalid_dst_packets = []

    if highlight_invalid:
      valid_src_packets = [p for p in src_packets if p.get('is_valid', True)]
      valid_dst_packets = [p for p in dst_packets if p.get('is_valid', True)]
      invalid_src_packets = [p for p in src_packets if not p.get('is_valid', True)]
      invalid_dst_packets = [p for p in dst_packets if not p.get('is_valid', True)]

    valid_src_lens = [p.get('pkt_len') for p in valid_src_packets]
    valid_dst_lens = [-p.get('pkt_len') for p in valid_dst_packets]
    invalid_src_lens = [p.get('pkt_len') for p in invalid_src_packets]
    invalid_dst_lens = [-p.get('pkt_len') for p in invalid_dst_packets]

    if ax is None:
      ax = plt.axes()

    ax.scatter([p.get('rel_time') for p in valid_src_packets], valid_src_lens, color='#35C120', label=self.src_addr)
    ax.scatter([p.get('rel_time') for p in valid_dst_packets], valid_dst_lens, color='blue', label=self.dst_addr)

    if highlight_invalid:
      ax.scatter([p.get('rel_time') for p in invalid_src_packets], invalid_src_lens, color='black', label='Invalid from {}'.format(self.src_addr))
      ax.scatter([p.get('rel_time') for p in invalid_dst_packets], invalid_dst_lens, color='red', label='Invalid from {}'.format(self.dst_addr))

    ax.axhline(0, color='gray', linestyle=':', label='No payload length (e.g., ACK)')
    x_limits = ax.get_xlim()
    ax.set_title('Packets between {} and {} from {:.2f} to {:.2f} seconds'.format(self.src_addr, self.dst_addr, x_limits[0], x_limits[1]))
    ax.set_xlabel('Relative duration (seconds)')
    ax.set_ylabel('Packet length (bytes)')
    ax.legend(loc=4, title='Sender of Packet')

    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: '{}'.format(abs(x))))
    if draw_highlights:
      for i in filtered_interactions:
        self._add_interaction_highlight(i, ax)
    return ax

  def _add_interaction_highlight(self, interaction, ax):
    x_limits = ax.get_xlim()
    graph_duration = x_limits[1] - x_limits[0]

    min_time = min([p.get('rel_time') for p in interaction])
    max_time = max([p.get('rel_time') for p in interaction])
    min_time = min_time - (0.005 * graph_duration)
    max_time = max_time + (0.005 * graph_duration)

    ax.axvspan(min_time, max_time).set_alpha(0.5)
