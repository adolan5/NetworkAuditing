import statistics
from matplotlib import pyplot as plt

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

  def __repr__(self):
    return '<Flow ({}:{} <--> {}:{}) of {} packets; Open: {}>'.format(self.src_addr, self.src_port,
        self.dst_addr, self.dst_port, len(self.packets), self.is_open)

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

  def get_avg_length(self):
    lens = [int(p.get('_source').get('layers').get('frame').get('frame.len')) for p in self.packets]
    return statistics.mean(lens)

  def get_bitrate(self):
    duration = self.get_duration()
    aggregate_bytes = sum([float(p.get('_source').get('layers').get('frame').get('frame.len')) for p in self.packets])

    try:
      return (aggregate_bytes / duration) * 8
    except:
      return 0

  def export_packet_stats(self):
    stats = []
    for p in self.packets:
      pkt_stats = {}
      frame_info = p.get('_source').get('layers').get('frame')
      ip_info = p.get('_source').get('layers').get('ip')
      tcp_info = p.get('_source').get('layers').get('tcp')

      pkt_stats['src_addr'] = ip_info.get('ip.src')
      pkt_stats['dst_addr'] = ip_info.get('ip.dst')
      pkt_stats['pkt_len'] = int(tcp_info.get('tcp.len'))
      pkt_stats['rel_time'] = float(frame_info.get('frame.time_epoch')) - self.get_start_end_times()[0]
      stats.append(pkt_stats)

    return stats

  def get_packets_graph(self, duration_start=0, duration_end=None):
    if duration_end is None:
      duration_end = self.get_duration()

    stats = self.export_packet_stats()
    src_packets = [p for p in stats if p.get('src_addr') == self.src_addr and
        p.get('rel_time') >= duration_start and p.get('rel_time') <= duration_end]
    dst_packets = [p for p in stats if p.get('src_addr') == self.dst_addr and
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

    ticks = ax.get_yticks()
    ax.set_yticklabels([abs(y) for y in ticks])

    return (fig, ax)
