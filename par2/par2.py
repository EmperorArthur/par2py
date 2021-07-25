__author__ = "Arthur Moore <Arthur.Moore.git@cd-net.net>"
__copyright__ = "Copyright (C) 2021 Arthur Moore"
__license__ = "MIT"

from collections.abc import Set
from logging import getLogger
from pathlib import Path
from typing import Optional, Tuple, Dict, Iterator, Union, List

from . import packets
from .reader import Par2FileReader

logger = getLogger()


class RecoverySet(Set):
    """
    A Par2 Recovery set.  This is a collection of packets used to restore some files.
    """

    def __contains__(self, item) -> bool:
        if not isinstance(item, packets.Packet):
            return False
        if item == self._main_packet:
            return True
        if item == self._creator_packet:
            return True
        if item in self._packets:
            return True
        if item.header in self._packet_pointers.keys():
            return True
        return False

    def __init__(self, set_id: bytes):
        self._set_id = set_id
        self._main_packet: Optional[packets.MainPacket] = None
        self._creator_packet: Optional[packets.CreatorPacket] = None
        self._packets: Set[packets.Packet] = set()
        self._packet_pointers: Dict[packets.PacketHeader: Tuple[Par2FileReader, int]] = dict()

    def __len__(self) -> int:
        size = len(self._packets) + len(self._packet_pointers)
        if self._main_packet is not None:
            size += 1
        if self._creator_packet is not None:
            size += 1
        return size

    def __iter__(self) -> Iterator[packets.Packet]:
        return self.get_packets()

    def _validate_header(self, header: packets.PacketHeader):
        """ Make sure the packet header has a matching set_id """
        if header.set_id != self._set_id:
            raise ValueError("Packet set_id '{}', does not match RecoverySet id '{}'"
                             .format(header.set_id.hex(), self._set_id.hex()))

    def add(self, packet: packets.Packet):
        """
        Add a packet to the recovery set. Ready to be used, written, etc...
        """
        if not packet.is_valid():  # Consider removing this if the cost is too high
            raise ValueError("Packet is not valid: {}".format(packet))
        self._validate_header(packet.header)
        if isinstance(packet, packets.MainPacket):
            if self._main_packet is None:
                self._main_packet = packet
                return
            if self._main_packet == packet:
                return
            raise ValueError("Can not add another (different) \"Main\" packet.")
        if isinstance(packet, packets.CreatorPacket):
            if self._creator_packet is None:
                self._creator_packet = packet
                return
            if self._creator_packet == packet:
                return
            raise ValueError("Can not add another (different) \"Creator\" packet.")
        self._packets.add(packet)

    def _add_pointer(self, header: packets.PacketHeader, file: Par2FileReader, packet_number: int):
        """
        Add a Packet header and pointer information for that packet.
        Use this for large packets like "RecoveryBlock".

        Warning: This is an internal function and its functionality may change without notice.
        This function may decide to create a complete copy of any packet at any time!
        """
        self._validate_header(header)
        packet_type = header.type
        if packet_type in ["Main", "Creator", "FileDescription", "FileVerification"]:
            self.add(file[packet_number])
        if header in self._packet_pointers.keys():
            return  # Don't bother with duplicates
        self._packet_pointers[header] = (file, packet_number)

    @property
    def main_packet(self) -> packets.MainPacket:
        """ Get the main packet """
        if self._main_packet is None:
            raise ValueError("Packet not found")
        return self._main_packet

    @property
    def creator_packet(self) -> packets.CreatorPacket:
        """ Get the creator packet """
        if self._creator_packet is None:
            raise ValueError("Packet not found")
        return self._creator_packet

    def get_packets(self, packet_type: str = None) -> Iterator[packets.Packet]:
        """ Get all the packets of a particular type """
        if packet_type == "Main":
            yield self.main_packet
            return
        if packet_type == "Creator":
            yield self.creator_packet
            return
        # Normal packets
        for packet in self._packets:
            if packet_type is None:
                yield packet
            else:
                if packet.header.type == packet_type:
                    yield packet
        # Deal with pointers
        for header, (file, packet_number) in self._packet_pointers:
            if packet_type is None:
                yield file[packet_number]
            else:
                if header.type == packet_type:
                    yield file[packet_number]


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
            count += len(recovery_set)
        return count

    def _read_packets(self, reader: Par2FileReader):
        """
        Read all the small packets that are in the file, also store the offsets and set information of larger packets.

        WARNING: This may result in multiple large packets in memory until the garbage collector runs
        """
        start_count = len(self)
        small_packet_types = ["Main", "Creator", "FileDescription", "FileVerification"]
        for i, packet in enumerate(reader):
            set_id = packet.header.set_id
            if packet.header.set_id not in self.recovery_sets.keys():
                # Create a RecoverySet if needed
                self.recovery_sets[set_id] = RecoverySet(set_id)

            if packet.header.type in small_packet_types:
                # Save the entirety of the small packets
                self.recovery_sets[set_id].add(packet)
            else:
                # Just save the packet number
                # pylint: disable=protected-access
                self.recovery_sets[set_id]._add_pointer(packet.header, reader, i)
        logger.info("Added {} new packets".format(len(self) - start_count))
