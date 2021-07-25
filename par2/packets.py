__author__ = "Arthur Moore <Arthur.Moore.git@cd-net.net>"
__copyright__ = "Copyright (C) 2021 Arthur Moore"
__license__ = "MIT"

import struct
from collections.abc import Sized, Hashable
from hashlib import md5
from typing import NamedTuple, SupportsBytes, Union, Tuple

MD5_FORMAT = "16s"


# This is used so often, it's worth just defining it
PACKET_HEADER_SIZE = 64


# noinspection PyNamedTuple
class PacketHeader(NamedTuple):
    """ The header for every par2 packet """
    _format = "<" + "8s" + "Q" + MD5_FORMAT + MD5_FORMAT + "16s"
    _magic_expected = b'PAR2\x00PKT'
    magic: bytes  # Should always be b'PAR2\x00PKT'
    length: int  # Of entire packet (including header)
    hash: bytes  # md5 of entire packet. Excluding first 3 fields of header (32 bytes)
    set_id: bytes
    signature: bytes  # Should be in PACKET_TYPES.values()

    @classmethod
    def from_bytes(cls, data: bytes) -> "PacketHeader":
        """ Create from raw binary data """
        out = cls._make(struct.unpack_from(cls._format, data))
        if not out.is_valid():
            raise ValueError("Not a valid par2 packet header")
        return out

    @classmethod
    def size_bytes(cls) -> int:
        """
        Get the size of data as bytes

        Useful for determining offsets and minimum data for `from_bytes`.
        """
        return struct.calcsize(cls._format)

    def is_valid(self) -> bool:
        """ If the header matches what it is supposed to (does not check hash) """
        return self.magic == self._magic_expected

    def __bytes__(self) -> bytes:
        return struct.pack(self._format, *self)


class Packet(Sized, Hashable):  # SupportsBytes
    """
    A Par2 Packet
    WARNING: Watch out for memory limitations with large data / many packets
    """

    @classmethod
    def expected_signature(cls) -> bytes:
        """
        The signature for a type of packet.
        Children should override this function.
        cls.from_bytes(...) will fail if this is not empty, and does not match.
        """
        return b''

    def __init__(self, signature: bytes = b'', set_id: bytes = b'', data: bytes = b''):
        """
        Create a new packet
        """
        header = PacketHeader(magic=PacketHeader._magic_expected,
                              length=PACKET_HEADER_SIZE + len(data), hash=b'', set_id=set_id,
                              signature=signature)
        self._header: PacketHeader = header  # Make sure someone knows what they're doing when writing to this
        self._data_after_header: bytes = data
        if signature != b'':
            # Don't bother doing a hash when the data is likely to be overwritten immediately
            self._header = self._header._replace(hash=self._generate_hash())

    def __repr__(self):
        sig = self.header.signature
        if sig.startswith(b'PAR 2.0'):
            sig = sig[7:]
        sig=sig.strip(b'\0')
        return "<Par2 Packet: {} ({} bytes)>".format(sig, self.__len__())

    @classmethod
    def from_bytes(cls, data: Union[bytes, memoryview]) -> "Packet":
        """
        Read a packet from raw bytes.

        If fed a memoryview, then non-header data is kept that way.
        WARNING: Header data is never kept as a memoryview

        Internally handles all the variable sizing, so for offsets you can just do `...(data=buffer[offset:])`
        """
        packet = cls()
        packet._header = PacketHeader.from_bytes(data)
        packet._data_after_header = data[PACKET_HEADER_SIZE:packet.header.length]
        if cls.expected_signature() and packet.header.signature != cls.expected_signature():
            raise ValueError("Packet signature '{}' does not match expected '{}'"
                             .format(packet.header.signature, cls.expected_signature()))
        if not packet.is_valid():
            raise ValueError("Not a valid par2 packet")
        return packet

    def _generate_hash(self) -> bytes:
        """ Generate the hash that should be in the header """
        return md5(self.__bytes__()[32:]).digest()

    def __bytes__(self) -> bytes:
        """
        Get the packet as raw data
        WARNING: Even if the packet was built from a memoryview, this still returns bytes.
        """
        return bytes(self.header) + self._data_after_header

    @property
    def header(self) -> PacketHeader:
        return self._header

    def is_valid(self) -> bool:
        """
        If the packet is (seems) valid

        Does not perform extensive internal checks, just basic matching to header
        """
        signature_matches = not self.expected_signature() or self.header.signature == self.expected_signature()
        return self.header.is_valid() and \
               (len(self._data_after_header) + PACKET_HEADER_SIZE) == self.header.length and \
               (self._generate_hash() == self.header.hash) and signature_matches

    def __len__(self):
        """ The size of the entire packet (including header) """
        return self.header.length

    def __eq__(self, other: "Packet"):
        """
        Check if the other packet is the same (fast)

        This mostly just compares headers.  It assumes both are valid!
        """
        if not isinstance(other, self.__class__):
            return False
        return self.header == other.header

    def __hash__(self):
        return self.header.__hash__()


class MainPacket(Packet):
    # Only one of these per recovery set
    # size: header + 8 + 4 + (16 * <number_of_FileDescription/FileVerification_packets>)
    _single_format = "<" + "QL"  # + Variable length data

    @classmethod
    def expected_signature(cls) -> bytes:
        return b'PAR 2.0\x00Main\x00\x00\x00\x00'

    @classmethod
    def from_bytes(cls, data: Union[bytes, memoryview]) -> "MainPacket":
        # Use parent for parsing
        parent = super().from_bytes(data)
        # Convert to the real class by copying
        packet = cls()
        packet._header = parent._header
        packet._data_after_header = parent._data_after_header
        if not packet.is_valid():
            raise ValueError("Not a valid par2 packet")
        return packet

    def is_valid(self) -> bool:
        """ A more strict validity check """
        return super().is_valid() and self.file_count == len(self.file_ids) + len(self.non_recovery_set_file_ids)

    @property
    def _raw_struct(self) -> tuple:
        """ The raw data unpacked """
        return struct.unpack_from(self._single_format, self._data_after_header)

    @property
    def block_size(self) -> int:
        """
        The size of each recovery block (must be a multiple of 4)
        """
        return self._raw_struct[0]

    @property
    def file_count(self) -> int:
        """ The number of recoverable in the recovery set. """
        return self._raw_struct[1]

    @property
    def file_ids(self) -> Tuple[bytes]:
        """
        The File IDs (MD5 Hash) of all the files in the recovery set.
        """
        offset = struct.calcsize(self._single_format)
        return struct.unpack_from(MD5_FORMAT * self.file_count, self._data_after_header[offset:])

    @property
    def non_recovery_set_file_ids(self) -> Tuple[bytes]:
        """
        The File IDs (MD5 Hash) of all the files in the non-recovery set.
        These files can **NOT** be recovered.
        """
        offset = struct.calcsize(self._single_format)
        offset += struct.calcsize(MD5_FORMAT * self.file_count)
        return tuple(struct.iter_unpack(MD5_FORMAT, self._data_after_header[offset:]))


class CreatorPacket(Packet):
    # Only one of these per recovery set
    # size: header + 4 + variable (Fixed per compiled program)

    @classmethod
    def expected_signature(cls) -> bytes:
        return b'PAR 2.0\x00Creator\x00'

    def __init__(self, client: str = "", set_id: bytes = b''):
        data = client.encode()
        padding = 4 - len(data) % 4
        if padding == 4:
            padding = 0
        data += b'\0' * padding
        super().__init__(self.expected_signature(), set_id=set_id, data=data)

    def __repr__(self):
        return "<Par2 Creator Packet: \"{}\" ({} bytes)>".format(self.client, self.__len__())

    def __str__(self):
        return self.client

    @classmethod
    def from_bytes(cls, data: Union[bytes, memoryview]) -> "CreatorPacket":
        # Use parent for parsing
        parent = super().from_bytes(data)
        # Convert to the real class by copying
        packet = cls()
        packet._header = parent._header
        packet._data_after_header = parent._data_after_header
        return packet

    @property
    def client(self) -> str:
        """ Get the client encoded by the packet """
        return bytes(self._data_after_header).rstrip(b'\0').decode()


class FileDescriptionPacket(Packet):
    # Number of files used to create the ".par2" file per recovery set
    # size: 16 + 16 + 16 + variable

    _format = "<" + MD5_FORMAT + MD5_FORMAT + MD5_FORMAT + "Q"  # + Variable length data

    @classmethod
    def expected_signature(cls) -> bytes:
        return b'PAR 2.0\x00FileDesc'

    @classmethod
    def from_bytes(cls, data: Union[bytes, memoryview]) -> "FileDescriptionPacket":
        # Use parent for parsing
        parent = super().from_bytes(data)
        # Convert to the real class by copying
        packet = cls()
        packet._header = parent._header
        packet._data_after_header = parent._data_after_header
        return packet

    @property
    def _raw_struct(self) -> tuple:
        """ The raw data unpacked, excluding file name """
        return struct.unpack_from(self._format, self._data_after_header)

    @property
    def id(self) -> bytes:
        """ File ID is currently defined as hash of everything else in this packet """
        return self._raw_struct[0]

    @property
    def hash16k(self) -> bytes:
        """MD5 of first 16k of file (useful for identification if file name corrupted) """
        return self._raw_struct[1]

    @property
    def hash(self) -> bytes:
        """ MD5 of the entire file """
        return self._raw_struct[2]

    @property
    def name(self) -> str:
        """ File's name """
        offset = struct.calcsize(self._format)
        return bytes(self._data_after_header[offset:]).rstrip(b'\0').decode()


class FileVerificationPacket(Packet):
    # Number of files used to create the ".par2" file per recovery set
    # size: variable

    _format = "<"  # + Variable length data

    @classmethod
    def expected_signature(cls) -> bytes:
        return b'PAR 2.0\x00IFSC\x00\x00\x00\x00'

    @classmethod
    def from_bytes(cls, data: Union[bytes, memoryview]) -> "FileVerificationPacket":
        # Use parent for parsing
        parent = super().from_bytes(data)
        # Convert to the real class by copying
        packet = cls()
        packet._header = parent._header
        packet._data_after_header = parent._data_after_header
        return packet


class RecoveryPacket(Packet):
    # Number: variable
    # size: variable
    # size: header + 4 + Main.blocksize (Fixed at file creation)

    _format = "<"  # + Variable length data

    @classmethod
    def expected_signature(cls) -> bytes:
        return b'PAR 2.0\x00RecvSlic'

    @classmethod
    def from_bytes(cls, data: Union[bytes, memoryview]) -> "RecoveryPacket":
        # Use parent for parsing
        parent = super().from_bytes(data)
        # Convert to the real class by copying
        packet = cls()
        packet._header = parent._header
        packet._data_after_header = parent._data_after_header
        return packet


# Since signatures are stored in the class, this is useful
KNOWN_PACKETS = [MainPacket, CreatorPacket, FileDescriptionPacket, FileVerificationPacket, RecoveryPacket]


def packet_factory(data: Union[bytes, memoryview]):
    """
    Convert data into a par 2 packet
    :param data: The data to convert
    :return: A Packet of the appropriate type or Packet if the type is not known
    """
    # Accept the overhead of decoding the header twice. It's not worth the trouble.
    header = PacketHeader.from_bytes(data)
    for packet_class in KNOWN_PACKETS:
        if header.signature == packet_class.expected_signature():
            return packet_class.from_bytes(data)
    return Packet.from_bytes(data)
