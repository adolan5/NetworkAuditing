import statistics

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

    return (aggregate_bytes / duration) * 8
