__author__ = "Arthur Moore <Arthur.Moore.git@cd-net.net>"
__copyright__ = "Copyright (C) 2021 Arthur Moore"
__license__ = "MIT"

import mmap
from collections import Sequence
from functools import partial
from io import BufferedIOBase, UnsupportedOperation
from pathlib import Path
from typing import List, Union

from .packets import PacketHeader, packet_factory, PACKET_HEADER_SIZE


class Par2FileReader(Sequence):
    """
    Provides a low level interface for reading Par2 files.
    """

    def __init__(self, in_file: Union[str, Path, bytes, memoryview, mmap.mmap, BufferedIOBase]):
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
        offset = self._offset
        if self._read_buffer is not None:
            while True:
                packet_start = self._read_buffer[offset:].find(PacketHeader._magic_expected)
                if packet_start < 0:
                    break
                offset += packet_start
                self._packet_offsets.append(offset)
            return
        if self._readable_and_seekable:
            read_size = len(PacketHeader._magic_expected)  # Size of file reads (half the buffer size)
            self.fileobj.seek(offset)
            buffer: bytes = self.fileobj.read(read_size)
            offset += read_size
            for half_buffer in iter(partial(self.fileobj.read, read_size), b''):
                offset += read_size
                buffer += half_buffer
                packet_start = buffer.find(PacketHeader._magic_expected)
                if packet_start >= 0:
                    self._packet_offsets.append(offset + packet_start)
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

    def __getitem__(self, key: int):
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