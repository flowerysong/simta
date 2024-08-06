#!/usr/bin/env python3

import subprocess

import pytest


def test_snet_basic(tool_path):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-',
        ],
        check=True,
        capture_output=True,
        input=b"hello\nworld\r\nit's\rya\n\rboi",
    )

    # snet regularizes all line endings to \r\n
    assert res.stdout == b"hello\r\nworld\r\nit's\r\nya\r\n\r\nboi\r\n"


@pytest.mark.parametrize(
    'test_pair',
    [
        # \r\n split by the boundary
        (b'0123456\r\n78', b'0123456\r\n78\r\n'),
        # \r\n after the boundary
        (b'01234567\r\n8', b'01234567\r\n8\r\n'),
        # \r\n before the boundary
        (b'012345\r\n678', b'012345\r\n678\r\n'),
        # \r\r split by the boundary
        (b'0123456\r\r78', b'0123456\r\n\r\n78\r\n'),
        # \n\n split by the boundary
        (b'0123456\n\n78', b'0123456\r\n\r\n78\r\n'),
    ]
)
def test_snet_buffer_boundary(tool_path, test_pair):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-b', '4',  # initial yasl allocation will be double this
            '-',
        ],
        check=True,
        capture_output=True,
        input=test_pair[0],
    )

    assert res.stdout == test_pair[1]


def test_snet_buffer_max(tool_path):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-b', '4',
            '-m', '8',
            '-',
        ],
        capture_output=True,
        input=b'0123456\n012345678',
    )

    assert res.returncode == 1
    assert res.stdout == b'0123456\r\n'
    assert res.stderr == b'snet_eof: Cannot allocate memory\n'


def test_snet_null(tool_path):
    res = subprocess.run(
        [
            tool_path('snetcat'),
            '-',
        ],
        check=True,
        capture_output=True,
        input=b'hello\0world',
    )

    # snet_getline() returns null-terminated strings, so output is truncated
    assert res.stdout == b'hello\r\n'
