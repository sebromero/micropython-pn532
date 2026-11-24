"""
MicroPython I2C driver for the NXP PN532 NFC/RFID controller.

The driver implements the PN532 host protocol described in the NXP user
manual UM0701-02 on top of ``machine.I2C`` / ``machine.SoftI2C``:

* normal and extended information frames with LCS/DCS validation,
* ACK handling with automatic command retransmission,
* NACK-driven retransmission of corrupted or truncated responses,
* aborting a pending command (ACK frame) when the host times out, so the
  PN532 never stays stuck in a long-running command,
* tolerance for the PN532 NACKing its I2C address while busy or asleep,
* optional IRQ, RSTPDN (reset) and P32/INT0 (wake-up) pins.

* Author(s): Sebastian Romero
"""

import struct
from binascii import hexlify
from time import sleep_ms, ticks_diff, ticks_ms

from micropython import const  # type: ignore

I2C_ADDRESS = const(0x24)

# Frame identifiers
_TFI_HOST_TO_PN532 = const(0xD4)
_TFI_PN532_TO_HOST = const(0xD5)

_ACK_FRAME = b"\x00\x00\xff\x00\xff\x00"
_NACK_FRAME = b"\x00\x00\xff\xff\x00\x00"

# Overhead of an extended frame on the wire (preamble, start code, 0xFF 0xFF,
# LENM, LENL, LCS, TFI, response code, DCS, postamble) plus the I2C status byte.
_FRAME_OVERHEAD = const(13)
_MAX_FRAME_DATA = const(265)  # TFI + PD0..PDn (UM0701 6.2.1.3)

# Parser results
_KIND_DATA = const(0)
_KIND_ACK = const(1)
_KIND_NACK = const(2)
_KIND_ERROR = const(3)
_KIND_TRUNCATED = const(4)

# PN532 commands (UM0701 chapter 7)
_CMD_DIAGNOSE = const(0x00)
_CMD_GET_FIRMWARE_VERSION = const(0x02)
_CMD_GET_GENERAL_STATUS = const(0x04)
_CMD_READ_REGISTER = const(0x06)
_CMD_WRITE_REGISTER = const(0x08)
_CMD_SAM_CONFIGURATION = const(0x14)
_CMD_POWER_DOWN = const(0x16)
_CMD_RF_CONFIGURATION = const(0x32)
_CMD_IN_DATA_EXCHANGE = const(0x40)
_CMD_IN_COMMUNICATE_THRU = const(0x42)
_CMD_IN_DESELECT = const(0x44)
_CMD_IN_LIST_PASSIVE_TARGET = const(0x4A)
_CMD_IN_RELEASE = const(0x52)

# MIFARE / NTAG commands sent through InDataExchange
_MIFARE_AUTH_A = const(0x60)
_MIFARE_AUTH_B = const(0x61)
_MIFARE_READ = const(0x30)
_MIFARE_WRITE = const(0xA0)
_MIFARE_ULTRALIGHT_WRITE = const(0xA2)
_MIFARE_DECREMENT = const(0xC0)
_MIFARE_INCREMENT = const(0xC1)
_MIFARE_RESTORE = const(0xC2)
_MIFARE_TRANSFER = const(0xB0)
_NTAG_GET_VERSION = const(0x60)

# Status codes returned by InDataExchange & co (UM0701 table 18)
_ERRORS = {
    0x01: "timeout, the target has not answered",
    0x02: "CRC error detected by the CIU",
    0x03: "parity error detected by the CIU",
    0x04: "erroneous bit count during anti-collision",
    0x05: "framing error during MIFARE operation",
    0x06: "abnormal bit-collision during anti-collision",
    0x07: "communication buffer size insufficient",
    0x09: "RF buffer overflow detected by the CIU",
    0x0A: "RF field not switched on in time",
    0x0B: "RF protocol error",
    0x0D: "temperature error, antenna drivers switched off",
    0x0E: "internal buffer overflow",
    0x10: "invalid parameter",
    0x12: "DEP command not supported",
    0x13: "DEP data format mismatch",
    0x14: "MIFARE authentication error",
    0x23: "ISO/IEC 14443-3 UID check byte is wrong",
    0x25: "invalid DEP device state",
    0x26: "operation not allowed in this configuration",
    0x27: "command not acceptable in the current context",
    0x29: "target has been released by the initiator",
    0x2A: "card ID does not match, card has been exchanged",
    0x2B: "previously activated card has disappeared",
    0x2C: "NFCID3 initiator/target mismatch in DEP 212/424 kbps",
    0x2D: "over-current event detected",
    0x2E: "NAD missing in DEP frame",
}


class PN532Error(Exception):
    """Base class for all errors raised by this driver."""


class PN532TimeoutError(PN532Error):
    """The PN532 did not acknowledge or answer a command in time."""


class PN532ProtocolError(PN532Error):
    """A frame received from the PN532 was malformed or failed its checksum."""


class PN532CardError(PN532Error):
    """The PN532 reported an error while talking to a card.

    The raw status code is available as :py:attr:`code`.
    """

    def __init__(self, code, command=None):
        self.code = code
        self.command = command
        message = _ERRORS.get(code, "unknown error")
        super().__init__("PN532 status 0x%02X: %s" % (code, message))


class CardType:  # pylint: disable=too-few-public-methods
    """Baud rate / modulation types for :py:meth:`PN532.read_passive_target`.

    * :py:attr:`CardType.ISO14443A` -- 106 kbps type A (MIFARE, NTAG, DESFire, ...)
    * :py:attr:`CardType.FELICA_212` -- 212 kbps FeliCa
    * :py:attr:`CardType.FELICA_424` -- 424 kbps FeliCa
    * :py:attr:`CardType.ISO14443B` -- 106 kbps type B
    * :py:attr:`CardType.JEWEL` -- 106 kbps Innovision Jewel / Topaz
    """

    ISO14443A = const(0x00)
    FELICA_212 = const(0x01)
    FELICA_424 = const(0x02)
    ISO14443B = const(0x03)
    JEWEL = const(0x04)


class KeyType:  # pylint: disable=too-few-public-methods
    """MIFARE Classic key selector for :py:meth:`PN532.mifare_classic_authenticate`."""

    KEY_A = const(_MIFARE_AUTH_A)
    KEY_B = const(_MIFARE_AUTH_B)


class Target:
    """A card detected by :py:meth:`PN532.read_passive_target`.

    Attributes:
        number: Logical target number assigned by the PN532 (``Tg``).
        card_type: One of the :py:class:`CardType` values.
        uid: Card identifier (NFCID1 for type A, PUPI for type B, IDm for
            FeliCa, NFCID1 for Jewel) as ``bytes``.
        atqa: ATQA / SENS_RES as an ``int`` (type A only, otherwise ``None``).
        sak: SAK / SEL_RES as an ``int`` (type A only, otherwise ``None``).
        ats: Answer-to-select (type A ISO-DEP cards only, otherwise ``None``).
        raw: The undecoded target data returned by the PN532.
    """

    def __init__(self, number, card_type, uid, atqa=None, sak=None, ats=None, raw=b""):
        self.number = number
        self.card_type = card_type
        self.uid = uid
        self.atqa = atqa
        self.sak = sak
        self.ats = ats
        self.raw = raw

    @property
    def uid_hex(self):
        """The UID as an upper-case hex string, e.g. ``"04A1B2C3D4E5F6"``."""
        return hexlify(self.uid).decode().upper()

    @property
    def is_mifare_classic(self):
        """``True`` if the SAK identifies a MIFARE Classic 1K/4K/Mini (or emulation)."""
        return self.sak is not None and (self.sak & 0x08) != 0

    @property
    def is_ntag2xx(self):
        """``True`` if the card looks like an NTAG2xx / MIFARE Ultralight (SAK 0x00)."""
        return self.card_type == CardType.ISO14443A and self.sak == 0x00

    @property
    def is_iso_dep(self):
        """``True`` if the card supports ISO/IEC 14443-4 (APDUs)."""
        return self.sak is not None and (self.sak & 0x20) != 0

    def __repr__(self):
        if self.sak is None:
            return "<Target %d type=%d uid=%s>" % (self.number, self.card_type, self.uid_hex)
        return "<Target %d uid=%s atqa=0x%04X sak=0x%02X>" % (
            self.number,
            self.uid_hex,
            self.atqa,
            self.sak,
        )


def _build_frame(data):
    """Wrap ``data`` (TFI + PD0..PDn) in a normal or extended information frame."""
    length = len(data)
    if length > _MAX_FRAME_DATA:
        raise ValueError("frame payload too long (%d > %d)" % (length, _MAX_FRAME_DATA))
    if length <= 254:
        header = bytes((0x00, 0x00, 0xFF, length, (-length) & 0xFF))
    else:
        lenm = length >> 8
        lenl = length & 0xFF
        header = bytes((0x00, 0x00, 0xFF, 0xFF, 0xFF, lenm, lenl, (-(lenm + lenl)) & 0xFF))
    return header + data + bytes(((-sum(data)) & 0xFF, 0x00))


def _parse_frame(buf, start):
    """Parse a frame starting at ``buf[start]``.

    Returns ``(kind, value)``. For ``_KIND_DATA`` the value is the frame payload
    (TFI + PD0..PDn) as ``bytes``; for ``_KIND_TRUNCATED`` it is the buffer size
    needed to hold the complete frame. Raises :py:class:`PN532ProtocolError` on
    malformed frames or checksum mismatches.
    """
    size = len(buf)
    i = start
    while i < size and buf[i] == 0x00:
        i += 1
    if i >= size:
        raise PN532ProtocolError("no start code in frame")
    if i == start or buf[i] != 0xFF:
        raise PN532ProtocolError("invalid start code 0x%02X" % buf[i])
    i += 1
    if i + 2 > size:
        return _KIND_TRUNCATED, i + 2
    first = buf[i]
    second = buf[i + 1]
    if first == 0x00 and second == 0xFF:
        return _KIND_ACK, None
    if first == 0xFF and second == 0x00:
        return _KIND_NACK, None
    if first == 0xFF and second == 0xFF:
        if i + 5 > size:
            return _KIND_TRUNCATED, i + 5
        length = (buf[i + 2] << 8) | buf[i + 3]
        if (buf[i + 2] + buf[i + 3] + buf[i + 4]) & 0xFF:
            raise PN532ProtocolError("extended frame length checksum mismatch")
        i += 5
    else:
        length = first
        if (first + second) & 0xFF:
            raise PN532ProtocolError("frame length checksum mismatch")
        i += 2
    if length == 0:
        raise PN532ProtocolError("empty information frame")
    end = i + length + 1  # payload + DCS
    if end > size:
        return _KIND_TRUNCATED, end + 1  # + postamble
    data = bytes(buf[i : i + length])
    if (sum(data) + buf[i + length]) & 0xFF:
        raise PN532ProtocolError("frame data checksum mismatch")
    if length == 1 and data[0] == 0x7F:
        return _KIND_ERROR, None
    return _KIND_DATA, data


class PN532:
    """Driver for a PN532 connected over I2C.

    Args:
        i2c: A ``machine.I2C`` or ``machine.SoftI2C`` instance. The PN532 uses
            clock stretching; keep the bus at 100-400 kHz.
        address: 7-bit I2C address of the PN532 (``0x24``).
        irq: Optional input ``machine.Pin`` (with pull-up) connected to the
            PN532 IRQ output. When given, readiness is signalled by the pin
            going low instead of polling the I2C status byte.
        reset: Optional output ``machine.Pin`` (initially high) connected to
            RSTPDN (active low).
        req: Optional output ``machine.Pin`` (initially high) connected to
            P32/INT0, pulsed low to wake the PN532 from power-down.
        debug: Print every frame sent and received.
        retries: How often a command is retransmitted when it is not
            acknowledged and how often a corrupted response is requested again.
        init: Run :py:meth:`begin` from the constructor.

    Raises:
        PN532Error: If ``init`` is true and the PN532 does not answer.
    """

    ACK_TIMEOUT_MS = 100
    """How long to wait for the ACK frame after sending a command."""

    POLL_INTERVAL_MS = 2
    """Delay between two readiness checks."""

    def __init__(
        self,
        i2c,
        address=I2C_ADDRESS,
        *,
        irq=None,
        reset=None,
        req=None,
        debug=False,
        retries=3,
        init=True
    ):
        self._i2c = i2c
        self._address = address
        self._irq = irq
        self._reset_pin = reset
        self._req = req
        self.debug = debug
        self.retries = max(1, retries)
        self._status = bytearray(1)
        self._pending = None
        self._pending_card_type = CardType.ISO14443A
        self._powered_down = False
        self._sam_params = b"\x01\x14\x01"
        self.target = None
        """The last :py:class:`Target` found by :py:meth:`read_passive_target`."""

        if init:
            self.begin()

    # ------------------------------------------------------------------
    # Life cycle
    # ------------------------------------------------------------------

    def begin(self):
        """Reset (if possible), wake up and configure the PN532 for reader mode.

        Returns:
            The firmware version tuple, see :py:meth:`firmware_version`.

        Raises:
            PN532Error: If the PN532 does not answer.
        """
        if self._reset_pin is not None:
            self.reset()
        self._wakeup()
        version = None
        error = None
        for _ in range(self.retries):
            try:
                version = self.firmware_version()
                break
            except (PN532Error, OSError) as exc:
                error = exc
                sleep_ms(50)
        if version is None:
            raise PN532Error(
                "PN532 not responding at I2C address 0x%02X (%s). Check the wiring "
                "and that the module is set to I2C mode." % (self._address, error)
            )
        self.sam_configuration()
        return version

    def reset(self):
        """Hard-reset the PN532 through the RSTPDN pin (if connected)."""
        if self._reset_pin is None:
            raise PN532Error("no reset pin configured")
        self._reset_pin.value(0)
        sleep_ms(20)
        self._reset_pin.value(1)
        sleep_ms(100)
        self._pending = None
        self._powered_down = False

    def _wakeup(self):
        """Wake the PN532 from power-down (I2C address match or P32/INT0 pulse)."""
        if self._req is not None:
            self._req.value(0)
            sleep_ms(2)
            self._req.value(1)
        else:
            # Any I2C transaction addressed to the PN532 wakes it up. It may NACK
            # this first transaction while its oscillator starts.
            try:
                self._i2c.readfrom_into(self._address, self._status)
            except OSError:
                pass
        sleep_ms(10)

    def _ensure_awake(self):
        if self._powered_down:
            self._powered_down = False
            self._wakeup()
            # Restore the SAM configuration, like after a reset.
            self.call(_CMD_SAM_CONFIGURATION, self._sam_params, 0)

    # ------------------------------------------------------------------
    # Low level I2C transport
    # ------------------------------------------------------------------

    def _log(self, prefix, data):
        if self.debug:
            print("PN532", prefix, hexlify(data, " ").decode())

    def _write(self, data):
        """Write raw bytes, retrying while the PN532 NACKs the transfer."""
        error = None
        for _ in range(self.retries):
            try:
                acked = self._i2c.writeto(self._address, data)
                if acked is None or acked == len(data):
                    self._log(">>", data)
                    return
                error = "only %d of %d bytes acknowledged" % (acked, len(data))
            except OSError as exc:
                error = exc
            sleep_ms(2)
        raise PN532Error("I2C write failed: %s" % error)

    def _is_ready(self):
        if self._irq is not None:
            return self._irq.value() == 0
        try:
            self._i2c.readfrom_into(self._address, self._status)
        except OSError:
            # The PN532 NACKs its address while busy or asleep.
            return False
        return (self._status[0] & 0x01) != 0

    def _wait_ready(self, timeout_ms):
        start = ticks_ms()
        while True:
            if self._is_ready():
                return True
            if timeout_ms is not None and ticks_diff(ticks_ms(), start) >= timeout_ms:
                return False
            sleep_ms(self.POLL_INTERVAL_MS)

    def _read(self, size):
        """Read ``size`` bytes (status byte included). ``None`` if not ready."""
        buf = bytearray(size)
        try:
            self._i2c.readfrom_into(self._address, buf)
        except OSError:
            return None
        if not buf[0] & 0x01:
            return None
        self._log("<<", buf)
        return buf

    def _read_ack(self):
        """Wait for the ACK frame of the last command. Returns ``True`` on ACK."""
        start = ticks_ms()
        while True:
            remaining = self.ACK_TIMEOUT_MS - ticks_diff(ticks_ms(), start)
            if remaining <= 0 or not self._wait_ready(remaining):
                return False
            buf = self._read(len(_ACK_FRAME) + 1)
            if buf is None:
                continue
            try:
                kind, _ = _parse_frame(buf, 1)
            except PN532ProtocolError:
                return False
            return kind == _KIND_ACK

    def abort(self):
        """Abort the command the PN532 is currently processing.

        Sends an ACK frame (UM0701 6.2.1.3) and discards a response that may
        already have been prepared. Safe to call when nothing is pending.
        """
        self._pending = None
        try:
            self._write(_ACK_FRAME)
        except PN532Error:
            return
        sleep_ms(2)
        if self._is_ready():
            self._read(_FRAME_OVERHEAD + 64)

    # ------------------------------------------------------------------
    # Command layer
    # ------------------------------------------------------------------

    def send_command(self, command, params=b""):
        """Send a command and wait for the PN532 to acknowledge it.

        The response must be collected with :py:meth:`read_response`.

        Raises:
            PN532TimeoutError: If the command is not acknowledged after
                :py:attr:`retries` attempts.
        """
        if self._pending is not None:
            self.abort()
        self._ensure_awake()
        frame = _build_frame(bytes((_TFI_HOST_TO_PN532, command)) + bytes(params))
        for _ in range(self.retries):
            self._write(frame)
            if self._read_ack():
                self._pending = command
                return
            sleep_ms(5)
        raise PN532TimeoutError("command 0x%02X was not acknowledged" % command)

    def response_ready(self):
        """``True`` if the response to the pending command can be read."""
        return self._pending is not None and self._is_ready()

    def read_response(self, command, response_len=32, timeout_ms=1000):
        """Read the response to ``command`` sent with :py:meth:`send_command`.

        Args:
            command: The command code that was sent.
            response_len: Expected payload length. Used to size the first read;
                longer responses are fetched transparently.
            timeout_ms: How long to wait for the response, ``None`` to wait
                forever. On timeout the command is aborted.

        Returns:
            The response payload without TFI and response code as ``bytes``.

        Raises:
            PN532TimeoutError: On timeout.
            PN532ProtocolError: If the response stays corrupted after
                :py:attr:`retries` retransmissions.
        """
        size = response_len + _FRAME_OVERHEAD
        start = ticks_ms()
        nacks = 0
        while True:
            remaining = None
            if timeout_ms is not None:
                remaining = timeout_ms - ticks_diff(ticks_ms(), start)
            if (remaining is not None and remaining <= 0) or not self._wait_ready(remaining):
                self.abort()
                raise PN532TimeoutError("no response to command 0x%02X" % command)
            buf = self._read(size)
            if buf is None:
                continue
            try:
                kind, value = _parse_frame(buf, 1)
            except PN532ProtocolError:
                if nacks >= self.retries:
                    self._pending = None
                    raise
                nacks += 1
                self._write(_NACK_FRAME)
                continue
            if kind == _KIND_TRUNCATED:
                # The frame is longer than expected: ask for it again in full.
                if nacks >= self.retries:
                    self._pending = None
                    raise PN532ProtocolError("response could not be read completely")
                nacks += 1
                size = value
                self._write(_NACK_FRAME)
                continue
            if kind == _KIND_ERROR:
                self._pending = None
                raise PN532ProtocolError("PN532 rejected command 0x%02X (syntax error)" % command)
            if kind != _KIND_DATA:
                continue  # stray ACK/NACK
            if len(value) < 2 or value[0] != _TFI_PN532_TO_HOST or value[1] != command + 1:
                continue  # stale response to an earlier command
            self._pending = None
            return value[2:]

    def call(self, command, params=b"", response_len=32, timeout_ms=1000):
        """Send ``command`` and return its response payload."""
        self.send_command(command, params)
        return self.read_response(command, response_len, timeout_ms)

    # ------------------------------------------------------------------
    # General commands
    # ------------------------------------------------------------------

    def firmware_version(self):
        """Return ``(ic, version, revision, support)``.

        ``ic`` is ``0x32`` for a PN532; ``support`` is a bit mask of the
        supported protocols (bit 0 ISO14443A, bit 1 ISO14443B, bit 2 ISO18092).
        """
        response = self.call(_CMD_GET_FIRMWARE_VERSION, response_len=4, timeout_ms=500)
        if len(response) != 4:
            raise PN532ProtocolError("unexpected firmware version response")
        return tuple(response)

    def sam_configuration(self, mode=0x01, timeout=0x14, use_irq=True):
        """Configure the Security Access Module.

        Args:
            mode: ``0x01`` normal mode (no SAM), ``0x02`` virtual card,
                ``0x03`` wired card, ``0x04`` dual card.
            timeout: Virtual card timeout in 50 ms steps (``0x14`` = 1 s).
            use_irq: Let the PN532 drive its IRQ pin.
        """
        params = bytes((mode, timeout, 1 if use_irq else 0))
        self.call(_CMD_SAM_CONFIGURATION, params, 0)
        self._sam_params = params

    def general_status(self):
        """Return the raw ``GetGeneralStatus`` response (error, field, targets...)."""
        return self.call(_CMD_GET_GENERAL_STATUS, response_len=12)

    def read_register(self, *addresses):
        """Read one or more 16-bit SFR/XRAM registers. Returns ``bytes``."""
        params = b"".join(struct.pack(">H", a) for a in addresses)
        return self.call(_CMD_READ_REGISTER, params, response_len=len(addresses))

    def write_register(self, address, value):
        """Write one 16-bit SFR/XRAM register."""
        self.call(_CMD_WRITE_REGISTER, struct.pack(">HB", address, value), 0)

    def rf_field(self, enabled, auto_rfca=False):
        """Switch the RF field on or off."""
        self.call(
            _CMD_RF_CONFIGURATION,
            bytes((0x01, (0x02 if auto_rfca else 0x00) | (0x01 if enabled else 0x00))),
            0,
        )

    def set_passive_activation_retries(self, retries=0xFF):
        """Set how often the PN532 retries to activate a card (``0xFF`` = forever).

        The default is to retry forever; the driver's own timeout aborts the
        search. Lower values make a failed :py:meth:`read_passive_target`
        return earlier without an abort.
        """
        self.call(_CMD_RF_CONFIGURATION, bytes((0x05, 0xFF, 0x01, retries & 0xFF)), 0)

    def power_down(self, wakeup_sources=0x88):
        """Put the PN532 into power-down mode.

        Args:
            wakeup_sources: WakeUpEnable bit mask. The default ``0x88`` wakes
                on I2C traffic and on an RF field. The next command wakes the
                PN532 up automatically.

        Returns:
            ``True`` if the PN532 accepted the request.
        """
        response = self.call(_CMD_POWER_DOWN, bytes((wakeup_sources,)), 1)
        ok = len(response) > 0 and (response[0] & 0x3F) == 0
        if ok:
            self._powered_down = True
            self.target = None
            sleep_ms(2)  # host must not talk to the PN532 for 1 ms
        return ok

    # ------------------------------------------------------------------
    # Initiator / reader commands
    # ------------------------------------------------------------------

    @staticmethod
    def _passive_target_params(card_type):
        if card_type in (CardType.FELICA_212, CardType.FELICA_424):
            # Polling request: system code FFFF, request code 01, 1 time slot
            return bytes((0x01, card_type, 0x00, 0xFF, 0xFF, 0x01, 0x00))
        if card_type == CardType.ISO14443B:
            return bytes((0x01, card_type, 0x00))  # AFI 0x00: all families
        return bytes((0x01, card_type))

    def start_passive_target_detection(self, card_type=CardType.ISO14443A):
        """Start looking for a card without blocking.

        Poll :py:meth:`get_passive_target` (or wait for the IRQ pin to go low)
        to collect the result.
        """
        self.target = None
        self.send_command(_CMD_IN_LIST_PASSIVE_TARGET, self._passive_target_params(card_type))
        self._pending_card_type = card_type

    def get_passive_target(self, timeout_ms=0):
        """Collect the card found after :py:meth:`start_passive_target_detection`.

        Args:
            timeout_ms: How long to wait for a card. ``0`` checks once and
                returns immediately; the search keeps running in the PN532.

        Returns:
            A :py:class:`Target`, or ``None`` if no card has been found yet.
        """
        if self._pending != _CMD_IN_LIST_PASSIVE_TARGET:
            raise PN532Error("no passive target detection in progress")
        if timeout_ms == 0:
            if not self._is_ready():
                return None
            timeout_ms = 100  # the response is ready, just read it
        elif not self._wait_ready(timeout_ms):
            return None
        response = self.read_response(_CMD_IN_LIST_PASSIVE_TARGET, 64, timeout_ms)
        self.target = self._parse_passive_target(self._pending_card_type, response)
        return self.target

    def read_passive_target(self, card_type=CardType.ISO14443A, timeout_ms=1000):
        """Wait for a card and select it.

        Args:
            card_type: One of the :py:class:`CardType` values.
            timeout_ms: How long to wait, ``None`` to wait forever.

        Returns:
            A :py:class:`Target`, or ``None`` if no card showed up in time.
        """
        self.start_passive_target_detection(card_type)
        try:
            response = self.read_response(_CMD_IN_LIST_PASSIVE_TARGET, 64, timeout_ms)
        except PN532TimeoutError:
            return None
        self.target = self._parse_passive_target(card_type, response)
        return self.target

    @staticmethod
    def _parse_passive_target(card_type, data):
        if not data or data[0] == 0:
            return None
        if len(data) < 2:
            raise PN532ProtocolError("truncated target data")
        number = data[1]
        raw = bytes(data[2:])
        try:
            if card_type == CardType.ISO14443A:
                atqa = (raw[0] << 8) | raw[1]
                sak = raw[2]
                uid_len = raw[3]
                uid = raw[4 : 4 + uid_len]
                if len(uid) != uid_len:
                    raise IndexError
                ats = None
                pos = 4 + uid_len
                if pos < len(raw):
                    ats_len = raw[pos]
                    ats = raw[pos + 1 : pos + ats_len]
                return Target(number, card_type, uid, atqa, sak, ats, raw)
            if card_type in (CardType.FELICA_212, CardType.FELICA_424):
                # POL_RES length, response code 0x01, IDm (8), PMm (8), [system code]
                uid = raw[2:10]
                if len(uid) != 8:
                    raise IndexError
                return Target(number, card_type, uid, raw=raw)
            if card_type == CardType.ISO14443B:
                # ATQB: 0x50, PUPI (4), application data (4), protocol info (3)
                uid = raw[1:5]
                if len(uid) != 4:
                    raise IndexError
                return Target(number, card_type, uid, raw=raw)
            if card_type == CardType.JEWEL:
                # SENS_RES (2), JEWELID (4)
                uid = raw[2:6]
                if len(uid) != 4:
                    raise IndexError
                return Target(number, card_type, uid, raw=raw)
        except IndexError:
            raise PN532ProtocolError("truncated target data")
        return Target(number, card_type, b"", raw=raw)

    def _target_number(self, target):
        if target is not None:
            return target
        if self.target is None:
            raise PN532Error("no card selected, call read_passive_target() first")
        return self.target.number

    def data_exchange(self, data, response_len=32, timeout_ms=1000, target=None):
        """Exchange data with the selected card (``InDataExchange``).

        The PN532 adds and checks CRCs and handles ISO-DEP framing, so for an
        ISO/IEC 14443-4 card ``data`` is a plain APDU.

        Returns:
            The card's response as ``bytes``.

        Raises:
            PN532CardError: If the PN532 reports a communication error.
        """
        tg = self._target_number(target)
        response = self.call(
            _CMD_IN_DATA_EXCHANGE, bytes((tg,)) + bytes(data), response_len + 1, timeout_ms
        )
        if not response:
            raise PN532ProtocolError("empty InDataExchange response")
        if response[0] & 0x3F:
            raise PN532CardError(response[0] & 0x3F, data[0] if data else None)
        return response[1:]

    def communicate_thru(self, data, response_len=32, timeout_ms=1000):
        """Send raw bytes to the selected card (``InCommunicateThru``).

        The PN532 appends and checks the CRC but adds no protocol framing.
        """
        response = self.call(_CMD_IN_COMMUNICATE_THRU, bytes(data), response_len + 1, timeout_ms)
        if not response:
            raise PN532ProtocolError("empty InCommunicateThru response")
        if response[0] & 0x3F:
            raise PN532CardError(response[0] & 0x3F, data[0] if data else None)
        return response[1:]

    def release(self, target=0):
        """Release a target (``0`` = all). The card must be selected again afterwards."""
        response = self.call(_CMD_IN_RELEASE, bytes((target,)), 1)
        self.target = None
        if response and response[0] & 0x3F:
            raise PN532CardError(response[0] & 0x3F)

    def deselect(self, target=0):
        """Deselect a target (``0`` = all), keeping its information in the PN532."""
        response = self.call(_CMD_IN_DESELECT, bytes((target,)), 1)
        if response and response[0] & 0x3F:
            raise PN532CardError(response[0] & 0x3F)

    # ------------------------------------------------------------------
    # MIFARE Classic
    # ------------------------------------------------------------------

    def mifare_classic_authenticate(self, block, key, key_type=KeyType.KEY_A, uid=None):
        """Authenticate a block of the selected MIFARE Classic card.

        Args:
            block: Block number (authenticates the whole sector).
            key: 6-byte key, e.g. ``b"\\xFF" * 6``.
            key_type: :py:attr:`KeyType.KEY_A` or :py:attr:`KeyType.KEY_B`.
            uid: Card UID; defaults to the UID of the selected card.

        Raises:
            PN532CardError: With ``code == 0x14`` if the key is wrong. The card
                then has to be selected again with :py:meth:`read_passive_target`.
        """
        if len(key) != 6:
            raise ValueError("MIFARE key must be 6 bytes")
        if key_type not in (KeyType.KEY_A, KeyType.KEY_B):
            raise ValueError("invalid key type")
        if uid is None:
            if self.target is None:
                raise PN532Error("no card selected, call read_passive_target() first")
            uid = self.target.uid
        # Authentication uses 4 UID bytes; for 7-byte UIDs these are the last 4.
        self.data_exchange(bytes((key_type, block)) + bytes(key) + bytes(uid[-4:]), 0)

    def mifare_classic_read_block(self, block):
        """Read a 16-byte block. The sector must be authenticated."""
        data = self.data_exchange(bytes((_MIFARE_READ, block)), 16)
        if len(data) != 16:
            raise PN532ProtocolError("expected 16 bytes, got %d" % len(data))
        return data

    def mifare_classic_write_block(self, block, data):
        """Write a 16-byte block. The sector must be authenticated.

        Writing a sector trailer (every 4th block in the lower sectors) changes
        keys and access bits: a wrong value locks the sector permanently.
        """
        if len(data) != 16:
            raise ValueError("MIFARE Classic blocks are 16 bytes")
        self.data_exchange(bytes((_MIFARE_WRITE, block)) + bytes(data), 0)

    def mifare_classic_format_value_block(self, block, value, address=None):
        """Turn ``block`` into a value block holding the signed 32-bit ``value``."""
        address = block if address is None else address
        raw = struct.pack("<i", value)
        inverted = bytes(b ^ 0xFF for b in raw)
        data = raw + inverted + raw + bytes((address, address ^ 0xFF, address, address ^ 0xFF))
        self.mifare_classic_write_block(block, data)

    def mifare_classic_get_value_block(self, block):
        """Read a value block and return its signed 32-bit value."""
        data = self.mifare_classic_read_block(block)
        value = data[0:4]
        inverted = bytes(b ^ 0xFF for b in data[4:8])
        if value != inverted or value != data[8:12]:
            raise PN532Error("block %d is not a valid value block" % block)
        if data[12] != data[14] or data[13] != data[15] or data[12] != data[13] ^ 0xFF:
            raise PN532Error("block %d is not a valid value block" % block)
        return struct.unpack("<i", value)[0]

    def _value_operation(self, operation, block, amount, transfer_block):
        self.data_exchange(bytes((operation, block)) + struct.pack("<I", amount), 0)
        target_block = block if transfer_block is None else transfer_block
        self.data_exchange(bytes((_MIFARE_TRANSFER, target_block)), 0)

    def mifare_classic_increment(self, block, amount, transfer_block=None):
        """Add ``amount`` to a value block and transfer the result."""
        self._value_operation(_MIFARE_INCREMENT, block, amount, transfer_block)

    def mifare_classic_decrement(self, block, amount, transfer_block=None):
        """Subtract ``amount`` from a value block and transfer the result."""
        self._value_operation(_MIFARE_DECREMENT, block, amount, transfer_block)

    def mifare_classic_restore(self, block, transfer_block):
        """Copy value block ``block`` to ``transfer_block`` (restore + transfer)."""
        self._value_operation(_MIFARE_RESTORE, block, 0, transfer_block)

    # ------------------------------------------------------------------
    # NTAG2xx / MIFARE Ultralight
    # ------------------------------------------------------------------

    def ntag2xx_read_pages(self, page):
        """Read 16 bytes (4 consecutive 4-byte pages) starting at ``page``."""
        data = self.data_exchange(bytes((_MIFARE_READ, page)), 16)
        if len(data) != 16:
            raise PN532ProtocolError("expected 16 bytes, got %d" % len(data))
        return data

    def ntag2xx_read_page(self, page):
        """Read a single 4-byte page."""
        return self.ntag2xx_read_pages(page)[:4]

    def ntag2xx_write_page(self, page, data):
        """Write a 4-byte page.

        Pages 2 and 3 hold lock bits and the capability container; writing
        them is irreversible.
        """
        if len(data) != 4:
            raise ValueError("NTAG2xx pages are 4 bytes")
        self.data_exchange(bytes((_MIFARE_ULTRALIGHT_WRITE, page)) + bytes(data), 0)

    def ntag2xx_get_version(self):
        """Return the 8-byte ``GET_VERSION`` response of an NTAG21x.

        Byte 6 identifies the storage size: ``0x0F`` NTAG213, ``0x11`` NTAG215,
        ``0x13`` NTAG216.
        """
        data = self.communicate_thru(bytes((_NTAG_GET_VERSION,)), 8)
        if len(data) != 8:
            raise PN532ProtocolError("expected 8 bytes, got %d" % len(data))
        return data
