from par2 import Par2, RecoverySet
from par2.reader import Par2FileReader
from tests.conftest import SAMPLES_PATH


def test_par2_create_empty():
    p2 = Par2()
    assert p2.recovery_sets == dict()
    assert p2.readers == []


def test_par2_read_simple_file_path():
    p2 = Par2(SAMPLES_PATH.joinpath("testfile.txt.par2"))
    assert len(p2.readers) == 1
    assert isinstance(p2.readers[0], Par2FileReader)
    assert len(p2.recovery_sets) == 1
    assert list(p2.recovery_sets.keys())[0].hex() == "be22b3624317366207908eb8aed92827"
    rs = p2.recovery_sets[bytes.fromhex("be22b3624317366207908eb8aed92827")]
    assert isinstance(rs, RecoverySet)
    assert rs.files == ["testfile.txt"]
