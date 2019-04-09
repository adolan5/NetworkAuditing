class Flow:
  """Simple representation of a flow.
  Defined as a number of packets that share particular properties, per RFC 3917.
  """

  def __init__(self):
    self.is_open = True
    self.packets = []

  def __repr__(self):
    src_addr = self.packets[0].get('_source').get('layers').get('ip').get('ip.src')
    dst_addr = self.packets[0].get('_source').get('layers').get('ip').get('ip.dst')

    return '<Flow ({} <--> {}) of {} packets; Open: {}>'.format(src_addr, dst_addr, len(self.packets), self.is_open)

  def get_avg_payload_length(self):
    lens = [int(p.get('_source').get('layers').get('data', {'data.len': 0}).get('data.len')) for p in self.packets]
    return statistics.mean(lens)

  def get_bitrate(self):
    times = [float(p.get('_source').get('layers').get('frame').get('frame.time_epoch')) for p in self.packets]
    start_time = min(times)
    end_time = max(times)

    duration = end_time - start_time
    aggregate_bytes = sum([float(p.get('_source').get('layers').get('frame').get('frame.len')) for p in self.packets])

    return (aggregate_bytes / duration) * 8
