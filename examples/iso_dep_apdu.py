"""
Send an ISO 7816-4 APDU to an ISO/IEC 14443-4 card (bank cards, DESFire, phones).

The example selects the PPSE (payment environment) and prints the response.
"""

from binascii import hexlify

from machine import I2C
from pn532 import PN532

SELECT_PPSE = b"\x00\xA4\x04\x00\x0E2PAY.SYS.DDF01\x00"

nfc = PN532(I2C(0, freq=100_000))

print("Hold an ISO-DEP card or phone to the reader...")
target = None
while target is None:
    target = nfc.read_passive_target(timeout_ms=1000)

if not target.is_iso_dep:
    raise SystemExit("Card does not support ISO-DEP: %r" % target)

response = nfc.data_exchange(SELECT_PPSE, response_len=256)
print("Response:", hexlify(response, " ").decode())
print("SW1 SW2: %02X %02X" % (response[-2], response[-1]))
