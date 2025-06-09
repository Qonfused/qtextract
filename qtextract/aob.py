from typing import List, Tuple

Signature = List[Tuple[int, bool]]


def parse_hex_digit(c: int) -> int:
  if 48 <= c <= 57:
    return c - 48
  if 97 <= c <= 102:
    return c - 97 + 10
  if 65 <= c <= 70:
    return c - 65 + 10
  raise ValueError('hex digit expected')


def craft_signature(s: bytes) -> Signature:
  current = 0
  is_wildcard = False
  bytes_out = []
  i = 0
  last_was_space = True
  while i < len(s):
    is_space = s[i] == 32
    if is_space != last_was_space:
      if is_space:
        bytes_out.append((current, is_wildcard))
        current = 0
        is_wildcard = False
      last_was_space = is_space
    if not is_space:
      if s[i] == ord('?'):
        is_wildcard = True
      else:
        current = (current << 4) | parse_hex_digit(s[i])
    i += 1
  if not last_was_space:
    bytes_out.append((current, is_wildcard))
  return bytes_out


def define_signature(s: bytes) -> Signature:
  return craft_signature(s)
