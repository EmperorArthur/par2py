import mmap
from pathlib import Path

from par2.reader import Par2FileReader

from .conftest import in_sample_dir, SAMPLES_PATH


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


def test_reader_par2_open_file(in_sample_dir):
    """ Similar to above, but just checking input type """
    file = Path("testfile.txt.par2").open('rb')
    reader = Par2FileReader(file)
    assert len(reader) == 4, "Parser should have found the packets.  Found offsets: {}".format(reader._packet_offsets)
