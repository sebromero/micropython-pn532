"""
Authenticate, write and read back a data block on a MIFARE Classic 1K card.

Block 4 is the first data block of sector 1. Never write sector trailers
(blocks 3, 7, 11, ...) unless you know exactly what you are doing: a wrong
value locks the sector forever.
"""

from machine import I2C
from pn532 import PN532, KeyType, PN532CardError

BLOCK = 4
KEY = b"\xFF\xFF\xFF\xFF\xFF\xFF"  # factory default key

nfc = PN532(I2C(0, freq=100_000))

print("Hold a MIFARE Classic card to the reader...")
target = None
while target is None:
    target = nfc.read_passive_target(timeout_ms=1000)

if not target.is_mifare_classic:
    raise SystemExit("Not a MIFARE Classic card: %r" % target)

try:
    nfc.mifare_classic_authenticate(BLOCK, KEY, KeyType.KEY_A)
except PN532CardError as error:
    # After a failed authentication the card must be selected again.
    raise SystemExit("Authentication failed: %s" % error)

nfc.mifare_classic_write_block(BLOCK, b"Hello MicroPy!\x00\x00")
data = nfc.mifare_classic_read_block(BLOCK)
print("Block %d:" % BLOCK, data)
