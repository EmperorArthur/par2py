import os
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
