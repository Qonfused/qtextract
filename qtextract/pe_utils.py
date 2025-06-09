from typing import Optional


class PESection:
  def __init__(self, name, virtual_address, size_of_raw_data,
               pointer_to_raw_data, characteristics):
    self.Name = name
    self.VirtualAddress = virtual_address
    self.SizeOfRawData = size_of_raw_data
    self.PointerToRawData = pointer_to_raw_data
    self.Characteristics = characteristics


class PEFileHeader:
  def __init__(self, machine):
    self.Machine = machine


class PEOptionalHeader:
  def __init__(self, image_base):
    self.ImageBase = image_base


class PEHeader:
  def __init__(self, data):
    self.sections = []
    self.FILE_HEADER = None
    self.OPTIONAL_HEADER = None
    self._parse(data)

  def _parse(self, data):
    # DOS header
    if data[0:2] != b'MZ':
      raise ValueError('Not a PE file')
    pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
    if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
      raise ValueError('Invalid PE signature')
    coff = pe_offset + 4
    machine = int.from_bytes(data[coff:coff + 2], 'little')
    num_sections = int.from_bytes(data[coff + 2:coff + 4], 'little')
    size_of_optional_header = int.from_bytes(data[coff + 16:coff + 18],
                                             'little')
    optional_header_offset = coff + 20
    image_base = int.from_bytes(
        data[optional_header_offset + 24:optional_header_offset + 28], 'little')
    self.FILE_HEADER = PEFileHeader(machine)
    self.OPTIONAL_HEADER = PEOptionalHeader(image_base)
    section_offset = optional_header_offset + size_of_optional_header
    for i in range(num_sections):
      off = section_offset + i * 40
      name = data[off:off + 8]
      virtual_size = int.from_bytes(data[off + 8:off + 12], 'little')
      virtual_address = int.from_bytes(data[off + 12:off + 16], 'little')
      size_of_raw_data = int.from_bytes(data[off + 16:off + 20], 'little')
      pointer_to_raw_data = int.from_bytes(data[off + 20:off + 24], 'little')
      characteristics = int.from_bytes(data[off + 36:off + 40], 'little')
      self.sections.append(
          PESection(name, virtual_address, size_of_raw_data,
                    pointer_to_raw_data, characteristics))
    self._data = data

  def get_offset_from_rva(self, rva):
    for section in self.sections:
      va = section.VirtualAddress
      sz = section.SizeOfRawData
      prd = section.PointerToRawData
      if va <= rva < va + sz:
        return prd + (rva - va)
    return None


class PEUtils:
  def __init__(self, pe):
    self.pe = pe
    self.image_base = pe.OPTIONAL_HEADER.ImageBase

  def rva2fo(self, rva: int) -> Optional[int]:
    try:
      return self.pe.get_offset_from_rva(rva)
    except Exception:
      return None

  def fo2rva(self, offset: int) -> Optional[int]:
    for section in self.pe.sections:
      prd = section.PointerToRawData
      srd = section.SizeOfRawData
      va = section.VirtualAddress
      if offset >= prd and offset < prd + srd:
        return (offset - prd) + va
    return None

  def va2fo(self, va: int) -> Optional[int]:
    if va >= self.image_base:
      return self.rva2fo(va - self.image_base)
    return None
