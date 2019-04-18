import json
import numpy as np

class StatsSerializer(json.JSONEncoder):
  def default(self, obj):
    if isinstance(obj, np.integer):
      return int(obj)
    if isinstance(obj, np.float):
      return float(obj)
