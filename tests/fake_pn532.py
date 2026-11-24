"""
Behavioural I2C model of a PN532 used by the test-suite.

It follows the I2C behaviour described in UM0701 and observed on real
hardware:

* every read transaction starts with a status byte (bit 0 = ready),
* a 1-byte status read does not consume the pending frame, any longer read does
  (even a partial one), after which the host must send a NACK to get it again,
* a NACK from the host triggers retransmission of the last frame,
* an ACK from the host aborts the command being processed.

Faults (checksum corruption, address NACKs, lost ACKs, write failures) can be
injected to exercise the driver's recovery paths.
"""

import struct

ACK = b"\x00\x00\xff\x00\xff\x00"
NACK = b"\x00\x00\xff\xff\x00\x00"


class FakeClock:
    def __init__(self):
        self.now = 0

    def ticks_ms(self):
        return self.now

    def sleep_ms(self, ms):
        self.now += ms

    @staticmethod
    def ticks_diff(a, b):
        return a - b


def build_response(data):
    length = len(data)
    if length <= 254:
        header = bytes((0x00, 0x00, 0xFF, length, (-length) & 0xFF))
    else:
        lenm, lenl = length >> 8, length & 0xFF
        header = bytes((0x00, 0x00, 0xFF, 0xFF, 0xFF, lenm, lenl, (-(lenm + lenl)) & 0xFF))
    return header + data + bytes(((-sum(data)) & 0xFF, 0x00))


def parse_host_frame(frame):
    """Return the payload of a host frame, validating every checksum."""
    assert frame[0:3] == b"\x00\x00\xff", "bad start code %r" % frame
    if frame[3] == 0xFF and frame[4] == 0xFF:
        length = (frame[5] << 8) | frame[6]
        assert (frame[5] + frame[6] + frame[7]) & 0xFF == 0, "bad extended LCS"
        start = 8
    else:
        length = frame[3]
        assert (frame[3] + frame[4]) & 0xFF == 0, "bad LCS"
        start = 5
    data = bytes(frame[start : start + length])
    assert len(data) == length, "short frame"
    assert (sum(data) + frame[start + length]) & 0xFF == 0, "bad DCS"
    assert frame[start + length + 1] == 0x00, "missing postamble"
    assert data[0] == 0xD4, "bad TFI"
    return data


class MifareClassic:
    def __init__(self, uid=b"\xde\xad\xbe\xef", blocks=64, key=b"\xff" * 6):
        self.uid = uid
        self.sak = 0x08
        self.atqa = 0x0004
        self.memory = [bytearray(16) for _ in range(blocks)]
        self.key = key
        self.auth_sector = None
        self.halted = False
        self.transfer_buffer = None

    def exchange(self, data):
        if self.halted:
            return 0x01, b""
        cmd = data[0]
        if cmd in (0x60, 0x61):
            block, key, uid = data[1], data[2:8], data[8:12]
            if key != self.key or uid != self.uid[-4:]:
                self.halted = True
                self.auth_sector = None
                return 0x14, b""
            self.auth_sector = block // 4
            return 0x00, b""
        block = data[1]
        if self.auth_sector != block // 4:
            return 0x14, b""
        if cmd == 0x30:
            return 0x00, bytes(self.memory[block])
        if cmd == 0xA0:
            self.memory[block][:] = data[2:18]
            return 0x00, b""
        if cmd in (0xC0, 0xC1, 0xC2):
            value = struct.unpack("<i", bytes(self.memory[block][0:4]))[0]
            amount = struct.unpack("<I", bytes(data[2:6]))[0]
            if cmd == 0xC1:
                value += amount
            elif cmd == 0xC0:
                value -= amount
            self.transfer_buffer = value
            return 0x00, b""
        if cmd == 0xB0:
            raw = struct.pack("<i", self.transfer_buffer)
            inv = bytes(b ^ 0xFF for b in raw)
            addr = self.memory[block][12]
            self.memory[block][:] = raw + inv + raw + bytes((addr, addr ^ 0xFF, addr, addr ^ 0xFF))
            return 0x00, b""
        return 0x27, b""

    def thru(self, data):
        return 0x01, b""


class Ntag215:
    def __init__(self, uid=b"\x04\x11\x22\x33\x44\x55\x66"):
        self.uid = uid
        self.sak = 0x00
        self.atqa = 0x0044
        self.pages = [bytearray(4) for _ in range(135)]
        self.halted = False

    def exchange(self, data):
        cmd = data[0]
        if cmd == 0x30:
            page = data[1]
            out = b""
            for i in range(4):
                out += bytes(self.pages[(page + i) % len(self.pages)])
            return 0x00, out
        if cmd == 0xA2:
            self.pages[data[1]][:] = data[2:6]
            return 0x00, b""
        return 0x27, b""

    def thru(self, data):
        if data == b"\x60":
            return 0x00, b"\x00\x04\x04\x02\x01\x00\x11\x03"
        return 0x01, b""


class EchoIsoDep:
    """ISO-DEP card that answers every APDU with ``reply_len`` bytes."""

    def __init__(self, reply_len):
        self.uid = b"\x08\x01\x02\x03"
        self.sak = 0x20
        self.atqa = 0x0004
        self.reply_len = reply_len
        self.halted = False

    def exchange(self, data):
        return 0x00, bytes((i & 0xFF for i in range(self.reply_len)))

    def thru(self, data):
        return 0x01, b""


class FakePN532:
    ADDRESS = 0x24

    def __init__(self, clock, card=None):
        self.clock = clock
        self.card = card
        self.out = None  # frame available to the host
        self.last_frame = None  # for NACK retransmission
        self.pending = None  # (ready_at_ms, response frame) or (None, None) = never
        self.commands = []  # every command code received
        self.process_ms = 3
        # fault injection
        self.corrupt_responses = 0
        self.nack_reads = 0
        self.drop_acks = 0
        self.fail_writes = 0
        self.nacks_received = 0
        self.acks_received = 0
        self.asleep = False
        self.sleep_after_read = False

    # -- I2C interface (machine.I2C compatible) -------------------------------

    def writeto(self, addr, data):
        assert addr == self.ADDRESS
        self.clock.now += 1
        if self.asleep:
            self.asleep = False
            raise OSError(19)  # first transaction only wakes the chip
        if self.fail_writes:
            self.fail_writes -= 1
            raise OSError(5)
        data = bytes(data)
        if data == ACK:
            self.acks_received += 1
            self.pending = None
            self.out = None
            return len(data)
        if data == NACK:
            self.nacks_received += 1
            if self.last_frame is not None:
                self._emit(self.last_frame)
            return len(data)
        payload = parse_host_frame(data)
        self.commands.append(payload[1])
        self.pending = None
        if self.drop_acks:
            self.drop_acks -= 1
            self.out = None
            return len(data)
        self._send(ACK)
        response = self.handle(payload[1], payload[2:])
        if response is None:
            self.pending = (None, None)
        else:
            self.pending = (self.clock.now + self.process_ms, build_response(response))
        return len(data)

    def readfrom_into(self, addr, buf):
        assert addr == self.ADDRESS
        self.clock.now += 1
        if self.asleep:
            self.asleep = False
            raise OSError(19)
        if self.nack_reads:
            self.nack_reads -= 1
            raise OSError(19)
        self._promote()
        for i in range(len(buf)):
            buf[i] = 0
        if self.out is None:
            return
        buf[0] = 0x01
        frame = self.out
        n = min(len(buf) - 1, len(frame))
        buf[1 : 1 + n] = frame[:n]
        if len(buf) > 1:
            self.out = None  # any data read consumes the frame
            if self.sleep_after_read and frame != ACK:
                self.sleep_after_read = False
                self.asleep = True

    def readfrom(self, addr, n):
        buf = bytearray(n)
        self.readfrom_into(addr, buf)
        return bytes(buf)

    # -- internals ------------------------------------------------------------

    def _send(self, frame):
        self.last_frame = frame
        self.out = frame

    def _promote(self):
        if self.out is None and self.pending is not None:
            ready_at, frame = self.pending
            if ready_at is not None and self.clock.now >= ready_at:
                self.pending = None
                self._emit(frame)

    def _emit(self, frame):
        """Make a response frame available, corrupting it if requested."""
        self.last_frame = frame
        if self.corrupt_responses:
            self.corrupt_responses -= 1
            bad = bytearray(frame)
            bad[-2] ^= 0x55  # break the DCS
            self.out = bytes(bad)
        else:
            self.out = frame

    def handle(self, cmd, params):
        rsp = bytes((0xD5, cmd + 1))
        if cmd == 0x02:
            return rsp + b"\x32\x01\x06\x07"
        if cmd in (0x14, 0x32):
            return rsp
        if cmd == 0x04:
            return rsp + b"\x00\x01\x00\x00\x80"
        if cmd == 0x16:
            self.sleep_after_read = True
            return rsp + b"\x00"
        if cmd == 0x4A:
            card = self.card
            if card is None or card.halted:
                return None  # keeps searching forever (MxRtyPassiveActivation=0xFF)
            data = bytes((1, 1)) + struct.pack(">HB", card.atqa, card.sak)
            data += bytes((len(card.uid),)) + card.uid
            if card.sak & 0x20:
                data += b"\x05\x78\x80\x70\x02"
            return rsp + data
        if cmd == 0x40:
            status, data = self.card.exchange(params[1:])
            return rsp + bytes((status,)) + data
        if cmd == 0x42:
            status, data = self.card.thru(params)
            return rsp + bytes((status,)) + data
        if cmd in (0x52, 0x44):
            if self.card is not None:
                self.card.halted = False
            return rsp + b"\x00"
        return b"\x7f"  # application error frame payload
