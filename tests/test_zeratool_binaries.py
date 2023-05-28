from zeratool_lib import ZeratoolExploit, ZeratoolInputStreams, exploit


def test_bof() -> None:
    exploit_data = exploit(
        "zeratool_binaries/bin/bof_32.elf",
        input_stream=ZeratoolInputStreams.STDIN,
        overflow_only=False,
        force_shellcode=True,
        skip_check=True,
    )

    assert exploit_data.payload is not None
    assert exploit_data.outcome == ZeratoolExploit.Outcomes.SHELL


def test_bof_with_nx() -> None:
    exploit_data = exploit(
        "zeratool_binaries/bin/bof_nx_32.elf",
        input_stream=ZeratoolInputStreams.STDIN,
        overflow_only=False,
        leak_format=b"{.*}",
        skip_check=True,
    )

    assert exploit_data.payload is not None
    assert exploit_data.outcome == ZeratoolExploit.Outcomes.SHELL


def test_bof_with_win_function() -> None:
    exploit_data = exploit(
        "zeratool_binaries/bin/bof_win_32.elf",
        input_stream=ZeratoolInputStreams.STDIN,
        overflow_only=True,
        win_funcs=["get_secret"],
        leak_format=b"{.*}",
        skip_check=True,
    )

    assert exploit_data.payload is not None
    assert exploit_data.outcome == ZeratoolExploit.Outcomes.CALL_TO_WIN


def test_format_string_attack_for_leak() -> None:
    exploit(
        "zeratool_binaries/bin/read_stack_32.elf",
        input_stream=ZeratoolInputStreams.STDIN,
        format_only=True,
        leak_format=b"(.*)BEGIN PRIVATE KEY(.*)",
        skip_check=False,
    )

    # TODO: Check why this is not generating an exploit despite the replication of the
    #       test from original README.md and tests/format_test.py.


def test_format_string_attack_for_win_call() -> None:
    exploit(
        "zeratool_binaries/bin/format_pc_write_32.elf",
        input_stream=ZeratoolInputStreams.STDIN,
        format_only=True,
        win_funcs=["secret_function"],
        leak_format=b"(.*)BEGIN PRIVATE KEY(.*)",
    )

    # TODO: Check why this is not generating an exploit despite the replication of the
    #       test from original README.md and tests/format_test.py.
