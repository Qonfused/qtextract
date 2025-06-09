import os
import zlib
from typing import Optional, List, Tuple, Union
from pathlib import Path

from binary_reader import BinaryReader


class QtNodeAuxDirectory:
  def __init__(self, children: List['QtNode']):
    self.children = children


class QtNodeAuxResource:
  def __init__(self, locale: int, is_compressed: bool, file_offset: int,
               data: bytes):
    self.locale = locale
    self.is_compressed = is_compressed
    self.file_offset = file_offset
    self.data = data


QtNodeAux = Union[QtNodeAuxDirectory, QtNodeAuxResource]


class QtNode:
  def __init__(self, _id: int, name: str, _name_hash: int, _flags: int,
               aux: QtNodeAux, last_modified: int):
    self._id = _id
    self.name = name
    self._name_hash = _name_hash
    self._flags = _flags
    self.aux = aux
    self.last_modified = last_modified

  def dump_impl(self, base_output_path: Path, c: int = 0):
    indent = '  ' * c
    print(f"{indent}{self.name}", end='')
    maybe_last_modified = self.last_modified if self.last_modified != 0 else None
    if isinstance(self.aux, QtNodeAuxDirectory):
      print()
      for child in self.aux.children:
        child.dump_impl(base_output_path, c + 1)
    elif isinstance(self.aux, QtNodeAuxResource):
      file_name_only = os.path.basename(self.name)
      sanitized_file_name = ''.join(
          '_' if ch in '/\\:*?"<>|' else ch for ch in file_name_only)
      output_file_path = base_output_path / sanitized_file_name
      print(f" @ 0x{self.aux.file_offset:08X} ({len(self.aux.data)} bytes)",
            end='')
      if self.aux.is_compressed:
        print(" [compressed]", end='')
      tmp = b''
      if self.aux.is_compressed and len(self.aux.data) > 4:
        print()
        print(f"{indent}  decompressing... ", end='')
        try:
          tmp = zlib.decompress(self.aux.data[4:])
          print(f"ok, {len(tmp)} bytes", end='')
        except Exception:
          print("decompression failed", end='')
      with open(output_file_path, 'wb') as f:
        f.write(tmp if self.aux.is_compressed else self.aux.data)
      if maybe_last_modified:
        try:
          os.utime(output_file_path,
                   (maybe_last_modified / 1000, maybe_last_modified / 1000))
        except Exception:
          pass
      print()

  def dump(self, path: Path):
    self.dump_impl(path, 0)


class QtResourceInfo:
  def __init__(self, signature_id: int, registrar: int, data: int, name: int,
               tree: int, version: int):
    self.signature_id = signature_id
    self.registrar = registrar
    self.data = data
    self.name = name
    self.tree = tree
    self.version = version

  def find_offset(self, node: int) -> int:
    m = 22 if self.version >= 2 else 14
    return node * m

  def read_name(self, buffer: bytes,
                name_offset: int) -> Optional[Tuple[str, int]]:
    stream = BinaryReader(buffer, self.name + name_offset)
    name_length = stream.read_u16(True)
    if name_length is None:
      return None
    name_hash = stream.read_u32(True)
    if name_hash is None:
      return None
    name = stream.read_u16_string(name_length, True)
    if name is None:
      return None
    return (name, name_hash)

  def read_data(self, buffer: bytes, data_offset: int) -> Optional[bytes]:
    stream = BinaryReader(buffer, self.data + data_offset)
    data_size = stream.read_u32(True)
    if data_size is None:
      return None
    data = stream.read_bytes(data_size)
    if data is None:
      return None
    return data

  def parse_node(self, buffer: bytes, node: int) -> Optional[QtNode]:
    if node == -1:
      return None
    stream = BinaryReader(buffer)
    node_offset = self.tree + self.find_offset(node)
    stream.seek(node_offset)
    name_offset = stream.read_i32(True)
    if name_offset is None:
      return None
    flags = stream.read_u16(True)
    if flags is None:
      return None
    is_directory = (flags & 2) != 0
    is_compressed = (flags & 1) != 0
    name_hash_pair = self.read_name(buffer, name_offset)
    if name_hash_pair is None:
      return None
    name, name_hash = name_hash_pair
    if is_directory:
      child_count = stream.read_i32(True)
      child_offset = stream.read_i32(True)
      if child_count is None or child_offset is None:
        return None
      children = []
      for i in range(child_offset, child_offset + child_count):
        child = self.parse_node(buffer, i)
        if child is not None:
          children.append(child)
      aux = QtNodeAuxDirectory(children)
    else:
      locale = stream.read_u32(True)
      data_offset = stream.read_i32(True)
      if locale is None or data_offset is None:
        return None
      data = self.read_data(buffer, data_offset)
      if data is None:
        return None
      aux = QtNodeAuxResource(locale, is_compressed, self.data + data_offset,
                              data)
    last_modified = stream.read_u64(True) if self.version >= 2 else 0
    return QtNode(node, name, name_hash, flags, aux, last_modified)
