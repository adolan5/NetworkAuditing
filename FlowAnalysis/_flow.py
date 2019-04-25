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

  def __init__(self, src, dst, src_port, dst_port, interaction_sep_time=0.5):
    self.src_addr = src
    self.dst_addr = dst
    self.src_port = src_port
    self.dst_port = dst_port
    self.interaction_sep_time=interaction_sep_time

    self.is_open = True
    self.packets = []
    self.interactions = [Interaction()]
    self.current_interaction = self.interactions[0]

  def __repr__(self):
    return '<Flow ({}:{} <--> {}:{}) of {} packets; Open: {}>'.format(self.src_addr, self.src_port,
        self.dst_addr, self.dst_port, len(self.packets), self.is_open)

  def __iter__(self):
    for p in self.get_packet_stats():
      yield p

  def append(self, packet):
    self.packets.append(packet)
    stat = self._get_stats_for_packet(packet)

    previous_packet = self.current_interaction[-1] if self.current_interaction else None
    if previous_packet and (stat.get('rel_time') - previous_packet.get('rel_time')) > self.interaction_sep_time:
      self.current_interaction = Interaction()
      self.interactions.append(self.current_interaction)

    self.current_interaction.append(stat)

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

  def get_aggregate_stats(self, duration_start=0, duration_end=None):
    if duration_end is None:
      duration_end = self.get_duration()

    filtered_stats = self._filter_stats(duration_start, duration_end)
    filtered_interactions = self._filter_interactions(duration_start, duration_end)
    pkts_no_acks = [p for p in filtered_stats if not (p.get('is_ack') and p.get('pkt_len') == 0)]

    src_lens = [p.get('pkt_len') for p in pkts_no_acks if p.get('src_addr') == self.src_addr]
    dst_lens = [p.get('pkt_len') for p in pkts_no_acks if p.get('src_addr') == self.dst_addr]
    int_durations = [i.get_duration() for i in filtered_interactions]

    total_bytes = sum([p.get('pkt_len') for p in filtered_stats])

    aggregate_stats = {
        'mode_src_len': stats.mode(src_lens)[0][0] if src_lens else np.nan,
        'mode_dst_len': stats.mode(dst_lens)[0][0] if dst_lens else np.nan,
        'avg_src_len': stats.tmean(src_lens) if src_lens else np.nan,
        'avg_dst_len': stats.tmean(dst_lens) if dst_lens else np.nan,
        'max_src_len': max(src_lens) if src_lens else 0,
        'max_dst_len': max(dst_lens)if dst_lens else 0,
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

    pkt_stats['src_addr'] = ip_info.get('ip.src')
    pkt_stats['dst_addr'] = ip_info.get('ip.dst')
    pkt_stats['pkt_len'] = int(tcp_info.get('tcp.len'))
    pkt_stats['rel_time'] = float(frame_info.get('frame.time_epoch')) - self.get_start_end_times()[0]
    pkt_stats['is_ack'] = (tcp_info.get('tcp.flags_tree').get('tcp.flags.ack') == '1')
    return pkt_stats

  def get_packet_stats(self):
    return [p for itx in self.interactions for p in list(itx)]

  def get_packets_graph(self, duration_start=0, duration_end=None, draw_highlights=True):
    filtered_packets = self._filter_stats(duration_start, duration_end)
    filtered_interactions = self._filter_interactions(duration_start, duration_end)
    src_packets = [p for p in filtered_packets if p.get('src_addr') == self.src_addr]
    dst_packets = [p for p in filtered_packets if p.get('src_addr') == self.dst_addr]
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
    if draw_highlights:
      for i in filtered_interactions:
        hl_dims = self._get_interaction_highlight(i)
        ax.axvspan(hl_dims[0], hl_dims[1]).set_alpha(0.5)
    return (fig, ax)

  def _get_interaction_highlight(self, interaction):
    min_time = min([p.get('rel_time') for p in interaction])
    max_time = max([p.get('rel_time') for p in interaction])
    duration = max_time - min_time
    min_time = min_time - (0.005 * self.get_duration())
    max_time = max_time + (0.005 * self.get_duration())
    return (min_time, max_time)

  def _filter_stats(self, duration_start=0, duration_end=None):
    if duration_end is None:
      duration_end = self.get_duration()
    return [p for p in self.get_packet_stats() if p.get('rel_time') >= duration_start and p.get('rel_time') <= duration_end]

  def _filter_interactions(self, duration_start=0, duration_end=None):
    if duration_end is None:
      duration_end = self.get_duration()
    filtered = [i.filter_by_time(duration_start, duration_end) for i in self.interactions]
    return [i for i in filtered if i]
