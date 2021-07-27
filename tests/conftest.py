import os
import random
from pathlib import Path

import pytest

SAMPLES_PATH = Path(__file__).resolve().parent.joinpath("samples")


@pytest.fixture(scope="function")
def change_test_dir(request):
    """ From https://stackoverflow.com/questions/62044541/change-pytest-working-directory-to-test-case-directory """
    os.chdir(request.fspath.dirname)
    yield
    os.chdir(request.config.invocation_dir)


@pytest.fixture(scope="function")
def in_sample_dir(request):
    os.chdir(str(SAMPLES_PATH))
    yield
    os.chdir(request.config.invocation_dir)


def randbytes(size) -> bytes:
    """Custom implementation of random.randbytes, since that's a Python 3.9 feature """
    return bytes(random.sample(list(range(0, 255)), size))


def factory_packet_header():
    """ Create random packet headers for testing """

    from par2.packets import PacketHeader, PACKET_HEADER_SIZE
    return PacketHeader(
        magic=PacketHeader._magic_expected,
        length=random.randrange(PACKET_HEADER_SIZE, 255),
        hash=randbytes(16),
        set_id=randbytes(16),
        signature=randbytes(16),
    )
