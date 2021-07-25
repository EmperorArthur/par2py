import os

import pytest


@pytest.fixture(scope="function")
def change_test_dir(request):
    """ From https://stackoverflow.com/questions/62044541/change-pytest-working-directory-to-test-case-directory """
    os.chdir(request.fspath.dirname)
    yield
    os.chdir(request.config.invocation_dir)
