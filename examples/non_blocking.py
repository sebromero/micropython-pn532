"""
Look for cards in the background while the main loop keeps running.

With the PN532 IRQ pin connected the driver does not poll the I2C bus while
waiting. Change IRQ_PIN to the GPIO you wired it to, or set it to None.
"""

from time import sleep_ms, ticks_ms

from machine import I2C, Pin
from pn532 import PN532

IRQ_PIN = None  # e.g. 15

irq = Pin(IRQ_PIN, Pin.IN, Pin.PULL_UP) if IRQ_PIN is not None else None
nfc = PN532(I2C(0, freq=100_000), irq=irq)

nfc.start_passive_target_detection()
while True:
    target = nfc.get_passive_target()  # returns immediately
    if target is not None:
        print("Card:", target)
        sleep_ms(1000)
        nfc.start_passive_target_detection()  # look for the next card
    # ... do other work here ...
    print("Working... %d" % ticks_ms(), end="\r")
    sleep_ms(50)
