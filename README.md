# 📦 MicroPython PN532 Driver

MicroPython I2C driver for the NXP PN532 NFC/RFID controller found on boards such as the Adafruit PN532 breakout/shield, the Elechouse PN532 V3 module and many unbranded PN532 boards. It reads card UIDs, reads and writes MIFARE Classic and NTAG2xx / Ultralight tags, and sends APDUs to ISO/IEC 14443-4 cards.

Written from the NXP PN532 user manual (UM0701) with error recovery as the main goal. Several MicroPython PN532 ports exist, but their I2C transports crash on MicroPython or don't recover from errors.

## ✨ Features

- 🛡️ **Robust transport**
  - Every frame's LCS and DCS checksums are verified.
  - Unacknowledged commands are sent again.
  - Corrupted or truncated responses are requested again with a NACK frame, and normal and extended frames (up to 265 bytes) are both handled.
  - When a command times out, it is aborted (ACK frame) so the PN532 never stays stuck searching for a card.
  - The PN532 NACKing its I2C address while busy, clock stretching or waking up is tolerated.
- 💳 **Card support** – ISO14443A (MIFARE Classic, NTAG2xx/Ultralight, DESFire, …), ISO14443B, FeliCa 212/424 and Jewel detection, with UID, ATQA, SAK and ATS decoded.
- 🔐 **MIFARE Classic** – Key A/B authentication, block read/write, and value block format, read, increment, decrement and restore.
- 🏷️ **NTAG2xx / Ultralight** – Page read/write and `GET_VERSION` to tell NTAG213/215/216 apart.
- 📡 **Raw access** – `InDataExchange` (APDUs), `InCommunicateThru`, and register read/write for anything else.
- ⏱️ **Non-blocking detection** – Start a card search and check for the result later, optionally using the IRQ pin so the bus stays quiet.
- 🔋 **Power management** – Power-down with automatic wake-up on the next command, hard reset through RSTPDN.
- 📂 **Examples** – See [`examples/`](examples).

## 🔌 Wiring

| PN532 | Board                     |
|-------|---------------------------|
| VCC   | 3V3 (or 5 V, see module)  |
| GND   | GND                       |
| SDA   | I2C SDA                   |
| SCL   | I2C SCL                   |
| IRQ   | any GPIO (optional)       |
| RSTO / RSTPDN | any GPIO (optional) |

The PN532 must be switched to **I2C mode**. On the common red/blue modules set the DIP switches to `SEL0 = 1 (ON)`, `SEL1 = 0 (OFF)`; on the Adafruit breakout set `SEL0 = ON`, `SEL1 = OFF` as well. Check the silkscreen of your module if unsure, and power-cycle it after changing the switches.

Most modules have on-board I2C pull-ups. Keep the bus at 100 kHz (400 kHz max): the PN532 stretches the clock, so on ports with a clock-stretch timeout use a generous one (e.g. `SoftI2C(..., timeout=100_000)`).

## 📖 Usage

```python
from machine import I2C
from pn532 import PN532

nfc = PN532(I2C(0, freq=100_000))
print("Firmware:", nfc.firmware_version())

target = nfc.read_passive_target(timeout_ms=1000)
if target:
    print("UID:", target.uid_hex, "SAK: 0x%02X" % target.sak)
```

Reading and writing a MIFARE Classic block:

```python
from pn532 import KeyType

nfc.mifare_classic_authenticate(4, b"\xFF" * 6, KeyType.KEY_A)
nfc.mifare_classic_write_block(4, b"0123456789abcdef")
print(nfc.mifare_classic_read_block(4))
```

Optional pins are passed as configured `machine.Pin` objects:

```python
from machine import Pin

nfc = PN532(
    I2C(0, freq=100_000),
    irq=Pin(15, Pin.IN, Pin.PULL_UP),      # PN532 IRQ, active low
    reset=Pin(14, Pin.OUT, value=1),       # PN532 RSTPDN, active low
)
```

### Error handling

All errors derive from `PN532Error`:

| Exception            | Raised when                                                         |
|----------------------|---------------------------------------------------------------------|
| `PN532TimeoutError`  | A command was not acknowledged or answered in time (it is aborted). |
| `PN532ProtocolError` | A response stayed corrupted after the configured retries.           |
| `PN532CardError`     | The PN532 reported a card error; the status is in `.code`, e.g. `0x14` for a wrong MIFARE key, `0x01` if the card did not answer. |

`read_passive_target()` returns `None` instead of raising when no card shows up. After a failed MIFARE authentication the card halts and must be selected again with `read_passive_target()`.

## ✅ Supported Boards

Any MicroPython board with an I2C bus (Raspberry Pi Pico, ESP32, STM32, Arduino boards running MicroPython, …). The driver only uses `machine.I2C`/`machine.SoftI2C` and `machine.Pin`.

## ⚙️ Installation

Install directly onto a board using `mpremote` + `mip`:

```bash
mpremote mip install github:sebromero/micropython-pn532
```

## 🧑‍💻 Developer Installation

Clone the repo and run an example without copying files to the board:

```bash
git clone https://github.com/sebromero/micropython-pn532.git
cd micropython-pn532
mpremote connect mount src run ./examples/read_uid.py
```

### Tests

The test suite drives the driver against a simulated PN532 (including injected bus and checksum faults) and runs on both CPython and the MicroPython unix port:

```bash
python3 tests/test_pn532.py
micropython tests/test_pn532.py
```

## 📄 License

[Mozilla Public License 2.0](LICENSE)
