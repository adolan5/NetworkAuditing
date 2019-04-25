class Interaction:
  def __init__(self):
    self.packet_stats = []

  def __iter__(self):
    for p in self.packet_stats:
      yield p

  def __getitem__(self, key):
    return self.packet_stats[key]

  def __bool__(self):
    return bool(self.packet_stats)

  def append(self, packet):
    self.packet_stats.append(packet)
