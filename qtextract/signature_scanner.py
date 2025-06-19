from typing import List, Optional

from .aob import Signature


class SignatureDefinition:
  def __init__(self, id: int, x64: bool, signature: Signature, extractor):
    self.id = id
    self.x64 = x64
    self.signature = signature
    self.extractor = extractor

  def scan(self, buffer: bytes, index: int, limit: int) -> Optional[int]:
    if not self.signature:
      return None
    sig_len = len(self.signature)
    if limit <= len(buffer) and limit - index >= sig_len:
      adjusted_limit = limit - sig_len
      for i in range(index, adjusted_limit + 1):
        for j, (byte_val, is_wildcard) in enumerate(self.signature):
          if not is_wildcard and buffer[i + j] != byte_val:
            break
        else:
          return i
    return None

  def scan_all(self, buffer: bytes, start: int, end: int) -> List[int]:
    results = []
    i = start
    while True:
      next_idx = self.scan(buffer, i, end)
      if next_idx is None:
        break
      results.append(next_idx)
      i = next_idx + 1
    return results
