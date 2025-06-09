import struct
from typing import Optional


class BinaryReader:
  def __init__(self, stream: bytes, position: int = 0):
    self.stream = stream
    self.position = position

  def seek(self, offset: int):
    self.position = offset

  def skip(self, num: int):
    self.position += num

  def read(self, size: int) -> Optional[bytes]:
    if self.position + size > len(self.stream):
      return None
    data = self.stream[self.position:self.position + size]
    self.position += size
    return data

  def read_bytes(self, count: int) -> Optional[bytes]:
    return self.read(count)

  def read_byte(self) -> Optional[int]:
    b = self.read(1)
    if b is None:
      return None
    return b[0]

  def read_u16(self, be: bool) -> Optional[int]:
    b = self.read(2)
    if b is None:
      return None
    return struct.unpack('>H' if be else '<H', b)[0]

  def read_i16(self, be: bool) -> Optional[int]:
    b = self.read(2)
    if b is None:
      return None
    return struct.unpack('>h' if be else '<h', b)[0]

  def read_u32(self, be: bool) -> Optional[int]:
    b = self.read(4)
    if b is None:
      return None
    return struct.unpack('>I' if be else '<I', b)[0]

  def read_i32(self, be: bool) -> Optional[int]:
    b = self.read(4)
    if b is None:
      return None
    return struct.unpack('>i' if be else '<i', b)[0]

  def read_u64(self, be: bool) -> Optional[int]:
    b = self.read(8)
    if b is None:
      return None
    return struct.unpack('>Q' if be else '<Q', b)[0]

  def read_i64(self, be: bool) -> Optional[int]:
    b = self.read(8)
    if b is None:
      return None
    return struct.unpack('>q' if be else '<q', b)[0]

  def read_u16_string(self, size: int, be: bool) -> Optional[str]:
    chars = []
    for _ in range(size):
      c = self.read_u16(be)
      if c is None:
        return None
      chars.append(c)
    try:
      return bytes().join([struct.pack('>H' if be else '<H', x) for x in chars
                          ]).decode('utf-16-be' if be else 'utf-16-le')
    except Exception:
      return None
