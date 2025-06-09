from pathlib import Path
import argparse
import re

from aob import define_signature
from binary_reader import BinaryReader
from extractor import QtResourceInfo
from pe_utils import PEUtils, PEHeader
from signature_scanner import SignatureDefinition


def x86_extract(offset, bytes_, pe):
  offsets = [0, 0, 0]
  stream = BinaryReader(bytes_)
  for i in range(3):
    stream.skip(1)
    val = stream.read_u32(False)
    if val is None:
      return None
    offsets[i] = PEUtils(pe).rva2fo(val - pe.OPTIONAL_HEADER.ImageBase)
    if offsets[i] is None:
      return None
  stream.skip(1)
  version = stream.read_byte()
  if version is None:
    return None
  return QtResourceInfo(-1, offset, offsets[0], offsets[1], offsets[2], version)


def x64_extract1(bytes_offset, bytes_, pe):
  result = [0, 0, 0]
  peutils = PEUtils(pe)
  bytes_rva = peutils.fo2rva(bytes_offset)
  if bytes_rva is None:
    return None
  stream = BinaryReader(bytes_)
  for i in range(3):
    stream.skip(3)
    v = stream.read_u32(False)
    if v is None:
      return None
    pos = stream.position
    result[i] = peutils.rva2fo(bytes_rva + pos + v)
    if result[i] is None:
      return None
  stream.skip(1)
  version = stream.read_u32(False)
  if version is None:
    return None
  return QtResourceInfo(-1, bytes_offset, result[0], result[1], result[2],
                        version)


def x64_extract2(bytes_offset, bytes_, pe):
  peutils = PEUtils(pe)
  bytes_rva = peutils.fo2rva(bytes_offset)
  if bytes_rva is None:
    return None
  stream = BinaryReader(bytes_)
  stream.skip(3)
  data = stream.read_u32(False)
  if data is None:
    return None
  data_fo = peutils.rva2fo(data + bytes_rva + stream.position)
  if data_fo is None:
    return None
  stream.skip(1)
  version = stream.read_u32(False)
  if version is None:
    return None
  stream.skip(3)
  name = stream.read_u32(False)
  if name is None:
    return None
  name_fo = peutils.rva2fo(name + bytes_rva + stream.position)
  if name_fo is None:
    return None
  stream.skip(3)
  tree = stream.read_u32(False)
  if tree is None:
    return None
  tree_fo = peutils.rva2fo(tree + bytes_rva + stream.position)
  if tree_fo is None:
    return None
  return QtResourceInfo(-1, bytes_offset, data_fo, name_fo, tree_fo, version)


TEXT_SIGNATURES = [
    SignatureDefinition(
        0, False,
        define_signature(
            b"68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ??"
        ), x86_extract),
    SignatureDefinition(
        1, False,
        define_signature(
            b"68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 15"),
        x86_extract),
    SignatureDefinition(
        2, True,
        define_signature(
            b"4C 8D 0D ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? B9 ?? 00 00 00 E8"
        ), x64_extract1),
    SignatureDefinition(
        3, True,
        define_signature(
            b"4C 8D 0D ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? B9 ?? 00 00 00 FF 15"
        ), x64_extract1),
    SignatureDefinition(
        4, True,
        define_signature(
            b"4C 8D 0D ?? ?? ?? ?? B9 ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? E8"
        ), x64_extract2),
    SignatureDefinition(
        5, True,
        define_signature(
            b"4C 8D 0D ?? ?? ?? ?? B9 ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? FF 15"
        ), x64_extract2),
]


def get_target_section(pe):
  for section in pe.sections:
    name = section.Name.decode(errors='ignore').rstrip('\0')
    if name == '':
      continue
    if name == '--section':
      return section
    if section.Characteristics & (0x00000020 | 0x20000000) != 0:
      return section
  return None


def do_scan(buffer, start, end, pe):
  seen = set()
  results = []
  for defn in TEXT_SIGNATURES:
    is_64 = pe.FILE_HEADER.Machine == 0x8664
    if defn.x64 == is_64:
      for fo in defn.scan_all(buffer, start, end):
        info = defn.extractor(fo, buffer[fo:fo + len(defn.signature)], pe)
        if info and info.version < 10:
          if info.data not in seen:
            seen.add(info.data)
            info.signature_id = defn.id
            results.append(info)
  return results


def parse_args():
  parser = argparse.ArgumentParser(
    prog='qtextract',
    description='Extract Qt resources from x86/x64 Windows binaries (.exe/.dll)',
    add_help=False,
    formatter_class=argparse.RawTextHelpFormatter
  )
  parser.add_argument('filename', nargs='?', help='Input binary file')
  parser.add_argument('--help', action='store_true', help='Print this help')
  parser.add_argument('--chunk', type=int, help='The chunk to dump. Exclude this to see a list of chunks (if any can be found) and use 0 to dump all chunks')
  parser.add_argument('--output', type=str, help='Output directory')
  parser.add_argument('--scanall', action='store_true', help='Scan the entire file (instead of the first executable section)')
  parser.add_argument('--section', type=str, help='Scan a specific section')
  parser.add_argument('--data', type=str, help='[Advanced] Manually provide offsets to a qt resource in the binary')
  parser.add_argument('--datarva', type=str, help='[Advanced] Like --data, but offsets are RVAs')
  return parser.parse_args()

def check_data_opt(pe, args):
  data_arg = args.data or args.datarva
  is_rva = args.datarva is not None
  if data_arg:
    m = re.match(r'([a-fA-F0-9]+),([a-fA-F0-9]+),([a-fA-F0-9]+),([0-9]+)', data_arg)
    if m:
      offsets = [0, 0, 0]
      if is_rva:
        for i in range(3):
          offsets[i] = PEUtils(pe).rva2fo(int(m.group(i+1), 16))
      else:
        for i in range(3):
          offsets[i] = int(m.group(i+1), 16)
      version = int(m.group(4))
      return [QtResourceInfo(-1, 0, offsets[0], offsets[1], offsets[2], version)]
  return None

def get_target_section(pe, args):
  if not args.scanall:
    if args.section:
      for section in pe.sections:
        name = section.Name.decode(errors='ignore').rstrip('\0')
        if name == args.section:
          return section
    else:
      for section in pe.sections:
        if section.Characteristics & (0x00000020 | 0x20000000) != 0:
          return section
  return None

def ask_resource_data(buffer, pe, args, results):
  if not results:
    print('No chunks to dump')
    return []
  if args.chunk is not None:
    if args.chunk == 0:
      return results
    elif 1 <= args.chunk <= len(results):
      return [results[args.chunk - 1]]
    else:
      print(f'Invalid chunk id: {args.chunk}')
      return []
  print('Select a resource chunk to dump:')
  print('0 - Dump all')
  for i, result in enumerate(results):
    print(f"{i+1} - 0x{result.registrar:08X} (via signature {result.signature_id}: version={result.version}, data=0x{result.data:08X}, name=0x{result.name:08X}, tree=0x{result.tree:08X})")
  print()
  while True:
    try:
      sel = int(input('>'))
      if sel == 0:
        return results
      elif 1 <= sel <= len(results):
        return [results[sel-1]]
    except Exception:
      pass
    print(f'Please enter a number between 0 and {len(results)}')

def main():
  args = parse_args()
  if args.help or not args.filename:
    print('''usage: qtextract filename [options]\noptions:\n  --help                   Print this help\n  --chunk chunk_id         The chunk to dump. Exclude this to see a list of chunks (if any can be found) and use 0 to dump all chunks\n  --output directory       For specifying an output directory\n  --scanall                Scan the entire file (instead of the first executable section)\n  --section section        For scanning a specific section\n  --data, --datarva info   [Advanced] Use these options to manually provide offsets to a qt resource in the binary\n                           (e.g. if no chunks were found automatically by qtextract).\n                           'info' should use the following format: %x,%x,%x,%d\n                           where the first 3 hexadecimal values are offsets to data, names, and tree\n                           and the last decimal value is the version (usually 1-3).\n\n                           If '--datarva' is used, provide RVA values (offsets from the image base) instead of file offsets.\n                           See check_data_opt() in main.rs for an example on finding these offsets using IDA.''')
    return
  path = args.filename
  buffer = open(path, 'rb').read()
  pe = PEHeader(buffer)
  output_directory = Path(args.output or 'qtextract-output')
  output_directory.mkdir(exist_ok=True)
  # Manual data option
  manual_chunks = check_data_opt(pe, args)
  if manual_chunks:
    to_dump = manual_chunks
  else:
    section = get_target_section(pe, args)
    if section:
      start = section.PointerToRawData
      end = start + section.SizeOfRawData
      print(f'Scanning section {section.Name.decode(errors="ignore").rstrip(chr(0))} (0x{start:08X}-0x{end:08X})...')
    else:
      start = 0
      end = len(buffer)
      print('Scanning file...')
    results = do_scan(buffer, start, end, pe)
    print('Done.')
    to_dump = ask_resource_data(buffer, pe, args, results)
  if to_dump:
    for i, result in enumerate(to_dump):
      print(f'Extracting chunk #{i+1} (0x{result.registrar:08X})... ', end='')
      dump_path = output_directory / str(i + 1) if len(to_dump) > 1 else output_directory
      if len(to_dump) > 1:
        dump_path.mkdir(exist_ok=True)
      node = result.parse_node(buffer, 0)
      if node:
        print('OK')
        node.dump(dump_path)
      else:
        print('ERROR (failed to parse node)')
  else:
    print('No chunks to dump')

if __name__ == "__main__":
  main()
