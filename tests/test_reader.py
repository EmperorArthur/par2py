import mmap
from pathlib import Path

from par2.packets import Packet
from par2.reader import Par2FileReader, DDPacketPointer

from .conftest import in_sample_dir, SAMPLES_PATH, factory_packet_header


def test_reader_empty_bytes():
    """ Make sure it at least works with bytes """
    reader = Par2FileReader(b'')
    assert len(reader) == 0


def test_reader_par2_file_str(in_sample_dir):
    reader = Par2FileReader("testfile.txt.par2")
    assert isinstance(reader._read_buffer, mmap.mmap), "File should be memmapped"
    assert reader._packet_offsets == [], "File should not be parsed immediately"
    assert reader._readable_and_seekable is True, "File should support regular file operations"
    assert len(reader) == 4, "Parser should have found the packets.  Found offsets: {}".format(reader._packet_offsets)
    assert reader._packet_offsets == [0, 92, 224, 724], "Offsets should always be here"


def test_reader_par2_file_str_mmap_closed(in_sample_dir):
    """ Similar to above, but this time simulating a mmap being closed """
    reader = Par2FileReader("testfile.txt.par2")
    assert isinstance(reader._read_buffer, mmap.mmap), "File should be memmapped"
    reader._read_buffer.close()
    assert len(reader) == 4, "Parser should have found the packets.  Found offsets: {}".format(reader._packet_offsets)
    assert reader._packet_offsets == [0, 92, 224, 724], "Offsets should always be here"


def test_reader_par2_file_path(in_sample_dir):
    """ Similar to above, but just checking input type """
    reader = Par2FileReader(SAMPLES_PATH.joinpath("testfile.txt.par2"))
    assert len(reader) == 4, "Parser should have found the packets.  Found offsets: {}".format(reader._packet_offsets)


def test_reader_par2_open_file(in_sample_dir):
    """ Similar to above, but just checking input type """
    file = Path("testfile.txt.par2").open('rb')
    reader = Par2FileReader(file)
    assert len(reader) == 4, "Parser should have found the packets.  Found offsets: {}".format(reader._packet_offsets)


def test_pointer_set():
    """ Make sure two identical pointers properly de-duplicate """
    header = factory_packet_header()
    reader0 = Par2FileReader(b'')
    reader1 = Par2FileReader(b'')
    pointer0 = DDPacketPointer(header, reader0, 0)
    pointer1 = DDPacketPointer(header, reader1, 1)
    assert pointer0 == pointer1
    assert hash(pointer0) == hash(pointer1)
    assert len({pointer0, pointer1}) == 1


def test_get_pointers(in_sample_dir):
    """ Test getting packet pointers, and that they work """
    reader = Par2FileReader("testfile.txt.par2")
    pointers = reader.get_pointers()
    assert isinstance(pointers, set)
    assert len(pointers) == 4
    for pointer in pointers:
        assert pointer.header.set_id.hex() == "be22b3624317366207908eb8aed92827"
        packet = pointer.get()
        assert isinstance(packet, Packet)
