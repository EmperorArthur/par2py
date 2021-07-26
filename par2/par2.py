__author__ = "Arthur Moore <Arthur.Moore.git@cd-net.net>"
__copyright__ = "Copyright (C) 2021 Arthur Moore"
__license__ = "MIT"

from collections.abc import MutableSet
from logging import getLogger
from pathlib import Path
from typing import Optional, Dict, Iterator, Union, List, Set

from . import packets
from .reader import Par2FileReader

logger = getLogger()


class PacketPointer:
    """
    A pointer to a packet within a Par2FileReader instance.

    This is an optimization for larger packets, so they don't have to be read into RAM.

    WARNING: The provided hash function could lead to issues if a pointer is stored in the same location as real packets
    """
    def __init__(self, header: packets.PacketHeader, reader: Par2FileReader, index: int):
        self._header = header
        self._reader = reader
        self._index = index

    @property
    def header(self):
        return self._header

    def get(self) -> packets.Packet:
        return self._reader[self._index]

    def __hash__(self):
        return self._header.__hash__()

    def __eq__(self, other):
        return isinstance(other, PacketPointer) and self.header == other.header


class RecoverySetPackets(MutableSet):
    """
    The packets in a Par2 Recovery set.  This is a collection of packets used to restore some files.
    """

    def __init__(self, set_id: bytes):
        self._set_id = set_id
        self._main_packet: Optional[packets.MainPacket] = None
        self._creator_packet: Optional[packets.CreatorPacket] = None
        self._packets: Set[packets.Packet] = set()
        self._packet_pointers: Set[PacketPointer] = set()

    def __len__(self) -> int:
        size = len(self._packets) + len(self._packet_pointers)
        if self._main_packet is not None:
            size += 1
        if self._creator_packet is not None:
            size += 1
        return size

    def __contains__(self, element: packets.Packet) -> bool:
        if element in self._packets:
            return True
        for pointer in self._packet_pointers:
            if element.header == pointer.header:
                return True
        return False

    def __iter__(self) -> Iterator[packets.Packet]:
        """
        Iterates through all packets.
        Note: Converts all pointers to real packets!
        """
        for packet in self._packets:
            yield packet
        for pointer in self._packet_pointers:
            yield pointer.get()

    def _validate_header(self, header: packets.PacketHeader):
        """ Make sure the packet header has a matching set_id """
        if header.set_id != self._set_id:
            raise ValueError("Packet set_id '{}', does not match RecoverySet id '{}'"
                             .format(header.set_id.hex(), self._set_id.hex()))

    def _add_packet(self, packet: packets.Packet):
        """ Add a packet. """
        if not packet.is_valid():  # Consider removing this if the cost is too high
            raise ValueError("Packet is not valid: {}".format(packet))
        self._validate_header(packet.header)
        if isinstance(packet, packets.MainPacket):
            if self._main_packet is None:
                self._main_packet = packet
            elif self._main_packet != packet:
                raise ValueError("Can not add another (different) \"Main\" packet.")
            return
        if isinstance(packet, packets.CreatorPacket):
            if self._creator_packet is None:
                self._creator_packet = packet
            elif self._creator_packet != packet:
                raise ValueError("Can not add another (different) \"Creator\" packet.")
            return
        for pointer in self._packet_pointers:
            # Duplicate check (with pointers)
            if packet.header == pointer.header:
                # Actually remove the pointer, since the whole packet is being added
                self._packet_pointers.discard(pointer)
                break
        self._packets.add(packet)

    def _add_pointer(self, pointer: PacketPointer):
        """Use this for large packets like "RecoveryBlock". """
        self._validate_header(pointer.header)
        for packet in self._packets:
            # Duplicate check (with packets)
            if packet.header == pointer.header:
                return
        self._packet_pointers.add(pointer)

    def add(self, element: Union[packets.Packet, PacketPointer]):
        """
        Add a packet or pointer to a packet.
        NOTE: This function will convert some pointers into packets!
        """
        important_packet_signatures = [
            packets.MainPacket.expected_signature(),
            packets.CreatorPacket.expected_signature(),
            packets.FileDescriptionPacket.expected_signature(),
            packets.FileVerificationPacket.expected_signature(),
        ]
        if isinstance(element, packets.Packet):
            return self._add_packet(element)
        if not isinstance(element, PacketPointer):
            raise ValueError("Only packets.Packet and PacketPointer are allowed here!")
        if element.header.signature in important_packet_signatures:
            return self._add_packet(element.get())
        return self._add_pointer(element)

    def discard(self, element: Union[packets.Packet, PacketPointer]) -> None:
        if isinstance(element, PacketPointer):
            element = element.get()
        if not isinstance(element, packets.Packet):
            return
        self._packets.discard(element)
        for pointer in self._packet_pointers:
            if pointer.header == element.header:
                self._packet_pointers.discard(pointer)
                break

    @property
    def main(self) -> packets.MainPacket:
        """ Get the main packet """
        if self._main_packet is None:
            raise ValueError("Packet not found")
        return self._main_packet

    @property
    def creator(self) -> packets.CreatorPacket:
        """ Get the creator packet """
        if self._creator_packet is None:
            raise ValueError("Packet not found")
        return self._creator_packet

    @property
    def file_description(self) -> Iterator[packets.FileDescriptionPacket]:
        return filter(lambda p: isinstance(p, packets.FileDescriptionPacket), self._packets)

    @property
    def file_verification(self) -> Iterator[packets.FileVerificationPacket]:
        return filter(lambda p: isinstance(p, packets.FileVerificationPacket), self._packets)

    @property
    def recovery(self) -> Iterator[packets.RecoveryPacket]:
        for packet in filter(lambda p: isinstance(p, packets.RecoveryPacket), self._packets):
            yield packet
        # Deal with pointers
        for pointer in self._packet_pointers:
            if pointer.header.signature == packets.RecoveryPacket.expected_signature():
                yield pointer.get()

    @property
    def unknown(self) -> Iterator[packets.Packet]:
        known_signatures = [packet.expected_signature() for packet in packets.KNOWN_PACKETS]
        for packet in self._packets:
            if not isinstance(packet, packets.KNOWN_PACKETS):
                yield packet
        # Deal with pointers
        for pointer in self._packet_pointers:
            if pointer.header.signature not in known_signatures:
                yield pointer.get()


class RecoverySet:
    """ High Level interface used to deal with par2 Recovery Sets """
    def __init__(self, set_id: bytes):
        self._set_id = set_id
        self.packets = RecoverySetPackets(set_id)

    @property
    def files(self) -> List[str]:
        """ The file names/paths this set can recover """
        return [packet.name for packet in self.packets.file_description]


class Par2:
    """ A class for interacting with Par2 data """

    def __init__(self, file: Union[str, Path] = None):
        self.recovery_sets: Dict[bytes, RecoverySet] = dict()  # Store the Recovery Sets found by set_id
        self.readers: List[Par2FileReader] = list()
        if file is not None:
            self.load(file)

    def load(self, file):
        """ Load a ".par2" file """
        reader = Par2FileReader(file)
        self.readers.append(reader)
        logger.info("Found {} packets".format(len(reader)))
        self._read_packets(reader)

    def __len__(self):
        """ The total number of packets in all recovery sets """
        count = 0
        for recovery_set in self.recovery_sets.values():
            count += len(recovery_set.packets)
        return count

    def _read_packets(self, reader: Par2FileReader):
        """
        Read all the small packets that are in the file, also store the offsets and set information of larger packets.

        WARNING: This may result in multiple large packets in memory until the garbage collector runs
        """
        start_count = len(self)
        for i, packet in enumerate(reader):
            set_id = packet.header.set_id
            if packet.header.set_id not in self.recovery_sets.keys():
                # Create a RecoverySet if needed
                self.recovery_sets[set_id] = RecoverySet(set_id)

            # Save the packet number (let the recovery set deal with details)
            # pylint: disable=protected-access
            self.recovery_sets[set_id].packets.add(PacketPointer(packet.header, reader, i))
        logger.info("Added {} new packets".format(len(self) - start_count))
