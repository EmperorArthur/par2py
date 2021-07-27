__author__ = "Arthur Moore <Arthur.Moore.git@cd-net.net>"
__copyright__ = "Copyright (C) 2021 Arthur Moore"
__license__ = "MIT"

import mmap
import re
from collections.abc import Sequence
from functools import partial
from io import UnsupportedOperation
from math import ceil
from pathlib import Path
from typing import List, Union, BinaryIO, Set

from .packets import PacketHeader, Packet, packet_factory, PACKET_HEADER_SIZE


class DDPacketPointer:
    """
    A de-duplicating pointer to a packet within a Par2FileReader instance.

    This is an optimization for larger packets, so they don't have to be read into RAM.

    WARNING: Two pointers are considered identical if they have the same header.
    If placed into a `set`, only one will be stored.
    This is what makes them de-duplicating.
    """
    def __init__(self, header: PacketHeader, reader: "Par2FileReader", index: int):
        self._header = header
        self._reader = reader
        self._index = index

    @property
    def header(self):
        return self._header

    def get(self) -> Packet:
        return self._reader[self._index]

    def __hash__(self):
        return hash(self._header) ^ hash(self.__class__.__name__)

    def __eq__(self, other):
        return isinstance(other, DDPacketPointer) and self.header == other.header


class Par2FileReader(Sequence):
    """
    Provides a low level interface for reading Par2 files.

    This scrubs through the entire file searching for packets on first access, but not until.
    It strives for memory efficiency, and only saves the offset to each packet in the file.

    Large files may see small lag on first scan, but memory usage will stay low, even on huge files.

    If possible, files are memory mapped and where relevant the returned packets just contain views into that file.
    This means that massive files can be read in their entirety, with a minimal memory footprint.
    However, closing those files manually (or allowing the parent reader to be deleted)
    will invalidate the pointers in those packets!
    """

    def __init__(self, in_file: Union[str, Path, bytes, memoryview, mmap.mmap, BinaryIO]):
        """
        Create an instance pointing to a particular piece of data.

        Accepts either a filename as a string, or a Path, along with an open file, or raw data.

        The only requirements are that either (`read` and `seek`) or (`find` and `[:]`) must be implemented.
        :param in_file:  The file to read
        """
        if isinstance(in_file, str):
            in_file = Path(in_file)
        if isinstance(in_file, Path):
            in_file = in_file.open('rb')
        self.fileobj = in_file
        self._offset = 0  # Use for keeping track of where packets are in the file
        try:
            self._offset = self.fileobj.tell()
        except AttributeError:
            pass

        self._packet_offsets: List[int] = list()  # Keep track of the offset for every packet

        self._read_buffer = None  # Optimized read buffer (if available)
        # First try and see if self.fileobj supports the commands needed
        try:
            if callable(self.fileobj.find) and isinstance(bytes(self.fileobj[0:0]), bytes):
                self._read_buffer = self.fileobj
        except (AttributeError, TypeError):
            pass
        # Try an optimization of just using mmap instead of having to scrub through the file
        # Potentially saves significant amounts of memory
        try:
            self._read_buffer = mmap.mmap(in_file.fileno(), 0, access=mmap.ACCESS_READ)
        except (mmap.error, UnsupportedOperation, AttributeError):
            pass

    @property
    def _readable_and_seekable(self) -> bool:
        """ If the underlying fileobj supports the `read` and `seek` functions """
        try:
            return callable(self.fileobj.read) and callable(self.fileobj.seek)
        except AttributeError:
            return False

    def _get_packet_header_offsets(self):
        """
        Scrub through the entire file, and find the offset for all the headers by looking for the magic value.
        """
        self._packet_offsets = list()
        if self._read_buffer is not None:
            if isinstance(self._read_buffer, mmap.mmap) and self._read_buffer.closed:
                # Handle this being closed for some reason (error or otherwise)
                self._read_buffer = None
                self._get_packet_header_offsets()
                return
            packet_search = re.compile(PacketHeader._magic_expected)
            for match in packet_search.finditer(self._read_buffer):
                self._packet_offsets.append(match.start())
            return
        if self._readable_and_seekable:
            offset = self._offset
            # Sized so the header can't be missed, but duplicates can't occur
            buffer_size = int(2 * len(PacketHeader._magic_expected) - 1)  # Should always be odd
            read_size = ceil(buffer_size/2)  # Size of file reads (just over half buffer size)
            self.fileobj.seek(offset)
            buffer: bytes = self.fileobj.read(buffer_size-read_size)  # Pre-fill half (ish) the buffer
            for half_buffer in iter(partial(self.fileobj.read, read_size), b''):
                buffer += half_buffer
                packet_start = buffer.find(PacketHeader._magic_expected)
                if packet_start >= 0:
                    # Found and not a duplicate (buffer size just makes that possible)
                    self._packet_offsets.append(offset + packet_start)
                offset += read_size  # Advance the offset
                buffer = buffer[read_size:]  # Last thing is to remove old data from the buffer
            self.fileobj.seek(self._offset)
            return
        raise AttributeError("fileobj does not implement (`read` and `seek`) or (`find` and `[:]`)")

    def __len__(self):
        """
        The number of Packets in the file. Including duplicates.

        WARNING: This triggers reading (though not storing) the entire file if it has not been done yet.
        """
        if not self._packet_offsets:
            self._get_packet_header_offsets()
        return len(self._packet_offsets)

    def __getitem__(self, key: int) -> Packet:
        """ Get a packet from the file (by number) """
        if key >= len(self):
            # Side effect of populating self._packet_offsets if needed
            raise IndexError
        offset = self._packet_offsets[key]
        if self._read_buffer is not None:
            return packet_factory(memoryview(self._read_buffer[offset:]))
        if self._readable_and_seekable:
            self.fileobj.seek(offset)
            buffer: bytes = self.fileobj.read(PACKET_HEADER_SIZE)
            header = PacketHeader.from_bytes(buffer)
            buffer += self.fileobj.read(header.length - PACKET_HEADER_SIZE)
            self.fileobj.seek(self._offset)
            return packet_factory(buffer)

    def get_pointers(self) -> Set[DDPacketPointer]:
        """
        Get pointers to all the packets in the file.
        This is de-duplicated, but does require that every header in the file be read and stored.
        """
        if not self._packet_offsets:
            # Make sure offsets are known
            self._get_packet_header_offsets()
        pointers: Set[DDPacketPointer] = set()
        if self._read_buffer is not None:
            for i, offset in enumerate(self._packet_offsets):
                header = PacketHeader.from_bytes(self._read_buffer[offset:])
                pointers.add(DDPacketPointer(header, self, i))
        elif self._readable_and_seekable:
            for i, offset in enumerate(self._packet_offsets):
                self.fileobj.seek(offset)
                buffer: bytes = self.fileobj.read(PACKET_HEADER_SIZE)
                header = PacketHeader.from_bytes(buffer)
                pointers.add(DDPacketPointer(header, self, i))
            self.fileobj.seek(self._offset)
        return pointers  # Guaranteed not to raise, thanks to `self._get_packet_header_offsets()` already doing so
