"""
Print the UID of every ISO14443A card (MIFARE, NTAG, DESFire...) held to the reader.

Set the PN532 module to I2C mode (see README) and connect SDA, SCL, VCC and GND.
"""

from time import sleep_ms

from machine import I2C
from pn532 import PN532

i2c = I2C(1, freq=100_000)
nfc = PN532(i2c)

ic, version, revision, _ = nfc.firmware_version()
print("Found PN5%02X, firmware %d.%d" % (ic, version, revision))
print("Waiting for a card...")

last_uid = None
while True:
    target = nfc.read_passive_target(timeout_ms=500)
    if target is None:
        last_uid = None
        continue
    if target.uid != last_uid:
        print("Card found:", target)
        last_uid = target.uid
    sleep_ms(200)
