class Interaction:
  def __init__(self, pkt_stats=None):
    self.packet_stats = pkt_stats if pkt_stats else []

  def __repr__(self):
    return '<itx of {} pkts over {:.02f} sec>'.format(self.__len__(), self.get_duration())

  def __iter__(self):
    for p in self.packet_stats:
      yield p

  def __len__(self):
    return len(self.packet_stats)

  def __getitem__(self, key):
    return self.packet_stats[key]

  def __bool__(self):
    return bool(self.packet_stats)

  def append(self, packet):
    self.packet_stats.append(packet)

  def filter_by_time(self, duration_start, duration_end):
    times = [p.get('rel_time') for p in self.packet_stats]
    if min(times) >= duration_start and max(times) <= duration_end:
      return self
    return Interaction([p for p in self.packet_stats if p.get('rel_time') >= duration_start and p.get('rel_time') <= duration_end])

  def get_duration(self):
    return self.packet_stats[-1].get('rel_time') - self.packet_stats[0].get('rel_time')
