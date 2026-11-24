"""
Test-suite for the PN532 driver. Runs on CPython and on the MicroPython unix
port against the simulated PN532 in ``fake_pn532.py``:

    python3 tests/test_pn532.py
    micropython tests/test_pn532.py
"""

import sys

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

try:
    import micropython  # noqa: F401
except ImportError:  # CPython
    import types

    _stub = types.ModuleType("micropython")
    _stub.const = lambda value: value
    sys.modules["micropython"] = _stub
    import time

    time.sleep_ms = lambda ms: None
    time.ticks_ms = lambda: 0
    time.ticks_diff = lambda a, b: a - b

import pn532.pn532 as driver  # noqa: E402
from fake_pn532 import (  # noqa: E402
    EchoIsoDep,
    FakeClock,
    FakePN532,
    MifareClassic,
    Ntag215,
    build_response,
)
from pn532 import (  # noqa: E402
    PN532,
    CardType,
    KeyType,
    PN532CardError,
    PN532Error,
    PN532ProtocolError,
    PN532TimeoutError,
)


class FakePin:
    def __init__(self, value=1):
        self._value = value
        self.history = []

    def value(self, v=None):
        if v is None:
            return self._value
        self._value = v
        self.history.append(v)


def make(card=None, **kwargs):
    clock = FakeClock()
    driver.sleep_ms = clock.sleep_ms
    driver.ticks_ms = clock.ticks_ms
    driver.ticks_diff = clock.ticks_diff
    chip = FakePN532(clock, card)
    return PN532(chip, **kwargs), chip, clock


# Parser result kinds (module-private consts are folded away by MicroPython)
KIND_DATA, KIND_ACK, KIND_NACK, KIND_ERROR, KIND_TRUNCATED = 0, 1, 2, 3, 4


def raises(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type as exc:
        return exc
    raise AssertionError("%s not raised" % exc_type.__name__)


# -- frame layer ----------------------------------------------------------------


def test_frame_round_trip_normal_and_extended():
    for size in (1, 2, 100, 254, 255, 265):
        payload = bytes([0xD5] + [i & 0xFF for i in range(size - 1)])
        frame = driver._build_frame(payload)
        kind, data = driver._parse_frame(b"\x01" + frame, 1)
        assert kind == KIND_DATA and data == payload, size
    raises(ValueError, driver._build_frame, bytes(266))


def test_parse_detects_bad_checksums():
    frame = bytearray(driver._build_frame(b"\xd5\x03\x32"))
    frame[-2] ^= 1
    raises(PN532ProtocolError, driver._parse_frame, frame, 0)
    frame = bytearray(driver._build_frame(b"\xd5\x03\x32"))
    frame[4] ^= 1
    raises(PN532ProtocolError, driver._parse_frame, frame, 0)
    raises(PN532ProtocolError, driver._parse_frame, bytes(10), 0)


def test_parse_ack_nack_error_and_truncation():
    assert driver._parse_frame(b"\x00\x00\xff\x00\xff\x00", 0)[0] == KIND_ACK
    assert driver._parse_frame(b"\x00\x00\xff\xff\x00\x00", 0)[0] == KIND_NACK
    assert driver._parse_frame(b"\x00\x00\xff\x01\xff\x7f\x81\x00", 0)[0] == KIND_ERROR
    frame = driver._build_frame(bytes(40))
    kind, needed = driver._parse_frame(frame[:20], 0)
    assert kind == KIND_TRUNCATED and needed == len(frame), needed


# -- initialisation and transport ----------------------------------------------------


def test_begin_reads_firmware_and_configures_sam():
    nfc, chip, _ = make()
    assert nfc.firmware_version() == (0x32, 0x01, 0x06, 0x07)
    assert chip.commands[:2] == [0x02, 0x14]


def test_begin_raises_when_chip_missing():
    clock = FakeClock()
    driver.sleep_ms = clock.sleep_ms
    driver.ticks_ms = clock.ticks_ms

    class Dead:
        def writeto(self, *args):
            clock.now += 1
            raise OSError(19)

        def readfrom_into(self, *args):
            clock.now += 1
            raise OSError(19)

    exc = raises(PN532Error, PN532, Dead())
    assert "0x24" in str(exc)


def test_reset_pin_is_pulsed():
    pin = FakePin()
    make(reset=pin)
    assert pin.history == [0, 1]


def test_retransmits_command_when_ack_is_lost():
    nfc, chip, _ = make()
    chip.drop_acks = 1
    assert nfc.firmware_version()[0] == 0x32
    assert chip.commands[-2:] == [0x02, 0x02]


def test_retries_failed_writes_and_nacked_reads():
    nfc, chip, _ = make()
    chip.fail_writes = 2
    chip.nack_reads = 5
    assert nfc.firmware_version()[0] == 0x32


def test_corrupted_response_is_requested_again():
    nfc, chip, _ = make()
    chip.corrupt_responses = 2
    assert nfc.firmware_version()[0] == 0x32
    assert chip.nacks_received == 2


def test_persistently_corrupted_response_raises():
    nfc, chip, _ = make()
    chip.corrupt_responses = 100  # every retransmission is corrupted too
    raises(PN532ProtocolError, nfc.firmware_version)
    chip.corrupt_responses = 0
    assert nfc.firmware_version()[0] == 0x32  # driver recovers afterwards


def test_application_error_frame_raises():
    nfc, _, _ = make()
    raises(PN532ProtocolError, nfc.call, 0x7E)


def test_irq_pin_is_used_for_readiness():
    nfc, chip, _ = make()

    class IrqFromChip:
        def value(self):
            chip._promote()
            return 0 if chip.out is not None else 1

    nfc._irq = IrqFromChip()
    assert nfc.firmware_version()[0] == 0x32


# -- card detection --------------------------------------------------------------


def test_read_passive_target_iso14443a():
    nfc, _, _ = make(MifareClassic())
    target = nfc.read_passive_target()
    assert target.uid == b"\xde\xad\xbe\xef"
    assert target.uid_hex == "DEADBEEF"
    assert target.sak == 0x08 and target.atqa == 0x0004
    assert target.is_mifare_classic and not target.is_ntag2xx
    assert nfc.target is target


def test_read_passive_target_parses_ats():
    nfc, _, _ = make(EchoIsoDep(4))
    target = nfc.read_passive_target()
    assert target.is_iso_dep
    assert target.ats == b"\x78\x80\x70\x02"


def test_timeout_without_card_aborts_and_recovers():
    nfc, chip, clock = make(None)
    start = clock.now
    assert nfc.read_passive_target(timeout_ms=200) is None
    assert 200 <= clock.now - start < 260
    assert chip.acks_received == 1  # the pending command was aborted
    assert nfc.firmware_version()[0] == 0x32


def test_non_blocking_detection():
    card = MifareClassic()
    card.halted = True  # nothing in the field yet
    nfc, chip, _ = make(card)
    nfc.start_passive_target_detection()
    assert nfc.get_passive_target() is None
    assert nfc.get_passive_target(timeout_ms=20) is None
    # a card enters the field: the PN532 finishes the pending command
    card.halted = False
    chip.pending = (chip.clock.now, build_response(chip.handle(0x4A, b"")))
    target = nfc.get_passive_target(timeout_ms=50)
    assert target is not None and target.uid == card.uid


def test_new_command_aborts_abandoned_detection():
    nfc, chip, _ = make(None)
    nfc.start_passive_target_detection()
    assert nfc.firmware_version()[0] == 0x32
    assert chip.acks_received == 1


def test_get_passive_target_without_start_raises():
    nfc, _, _ = make()
    raises(PN532Error, nfc.get_passive_target)


# -- MIFARE Classic ----------------------------------------------------------------


def test_mifare_classic_read_write():
    card = MifareClassic()
    nfc, _, _ = make(card)
    nfc.read_passive_target()
    nfc.mifare_classic_authenticate(4, b"\xff" * 6, KeyType.KEY_A)
    nfc.mifare_classic_write_block(4, b"Hello, PN532!!!!")
    assert nfc.mifare_classic_read_block(4) == b"Hello, PN532!!!!"
    raises(ValueError, nfc.mifare_classic_write_block, 4, b"short")


def test_mifare_classic_wrong_key():
    nfc, _, _ = make(MifareClassic())
    nfc.read_passive_target()
    exc = raises(PN532CardError, nfc.mifare_classic_authenticate, 4, b"\x00" * 6)
    assert exc.code == 0x14
    assert "authentication" in str(exc)
    raises(ValueError, nfc.mifare_classic_authenticate, 4, b"\x00" * 6, 0x99)


def test_mifare_classic_value_blocks():
    nfc, _, _ = make(MifareClassic())
    nfc.read_passive_target()
    nfc.mifare_classic_authenticate(5, b"\xff" * 6)
    nfc.mifare_classic_format_value_block(5, 100)
    assert nfc.mifare_classic_get_value_block(5) == 100
    nfc.mifare_classic_increment(5, 25)
    nfc.mifare_classic_decrement(5, 200)
    assert nfc.mifare_classic_get_value_block(5) == -75
    nfc.mifare_classic_write_block(5, bytes(15) + b"\x01")
    raises(PN532Error, nfc.mifare_classic_get_value_block, 5)


def test_operations_without_target_raise():
    nfc, _, _ = make()
    raises(PN532Error, nfc.mifare_classic_read_block, 4)
    raises(PN532Error, nfc.mifare_classic_authenticate, 4, b"\xff" * 6)


# -- NTAG2xx -----------------------------------------------------------------------


def test_ntag2xx_read_write_and_version():
    nfc, _, _ = make(Ntag215())
    target = nfc.read_passive_target()
    assert target.is_ntag2xx and len(target.uid) == 7
    nfc.ntag2xx_write_page(4, b"\x01\x02\x03\x04")
    nfc.ntag2xx_write_page(5, b"\x05\x06\x07\x08")
    assert nfc.ntag2xx_read_page(4) == b"\x01\x02\x03\x04"
    assert nfc.ntag2xx_read_pages(4)[:8] == bytes(range(1, 9))
    assert nfc.ntag2xx_get_version()[6] == 0x11
    raises(ValueError, nfc.ntag2xx_write_page, 4, b"\x00")


# -- long responses ------------------------------------------------------------------


def test_long_response_is_fetched_again_in_full():
    nfc, chip, _ = make(EchoIsoDep(200))
    nfc.read_passive_target()
    chip.nacks_received = 0
    reply = nfc.data_exchange(b"\x00\xa4\x04\x00", response_len=16)
    assert reply == bytes(i & 0xFF for i in range(200))
    assert chip.nacks_received == 1


def test_extended_frame_response():
    nfc, _, _ = make(EchoIsoDep(262))
    nfc.read_passive_target()
    reply = nfc.data_exchange(b"\x00\xb0\x00\x00\x00", response_len=262)
    assert len(reply) == 262 and reply[-1] == 261 & 0xFF


# -- power management ---------------------------------------------------------------------


def test_power_down_and_automatic_wakeup():
    nfc, chip, _ = make(MifareClassic())
    assert nfc.power_down()
    assert chip.asleep
    target = nfc.read_passive_target()
    assert target is not None
    assert chip.commands[-2:] == [0x14, 0x4A]  # SAM configuration restored


def test_general_status_and_release():
    nfc, _, _ = make(MifareClassic())
    assert len(nfc.general_status()) == 5
    nfc.read_passive_target()
    nfc.release()
    assert nfc.target is None


def test_debug_output_does_not_break_transfers():
    nfc, _, _ = make(MifareClassic(), debug=True)
    assert nfc.read_passive_target() is not None


def run():
    names = sorted(name for name in globals() if name.startswith("test_"))
    failed = 0
    for name in names:
        try:
            globals()[name]()
            print("PASS", name)
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL", name, repr(exc))
            if hasattr(sys, "print_exception"):
                sys.print_exception(exc)
            else:
                import traceback

                traceback.print_exc()
    print("%d passed, %d failed" % (len(names) - failed, failed))
    return failed


if __name__ == "__main__":
    sys.exit(1 if run() else 0)
