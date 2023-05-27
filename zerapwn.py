#!/usr/bin/env python
from __future__ import print_function

import logging
import os
import subprocess

from zeratool import (
    formatDetector,
    formatExploiter,
    formatLeak,
    inputDetector,
    overflowDetector,
    overflowExploiter,
    overflowExploitSender,
    protectionDetector,
)

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


def get_libc_path() -> str:
    return subprocess.check_output(["gcc", "--print-file-name=libc.so"]).decode("utf-8")


class WinFunction:
    name: str
    address: int


def exploit(
    file: str,
    format_only: bool = False,
    overflow_only: bool = False,
    win_functions: list(WinFunction) = None,
    leak_format: str = "",
    skip_check: bool = False,
    force_shellcode: bool = False,
    force_dlresolve: bool = False,
) -> None:
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
    properties["input_type"] = inputDetector.checkInputType(file)
    properties["libc"] = get_libc_path()
    properties["force_shellcode"] = force_shellcode
    properties["pwn_type"] = {}
    properties["pwn_type"]["type"] = None
    properties["force_dlresolve"] = force_dlresolve
    properties["win_functions"] = win_functions if win_functions else []

    log.info("[+] Checking pwn type...")

    # Checking if overflow attack is possible
    if not format_only and not skip_check:
        log.info("[+] Checking for overflow pwn type...")
        properties["pwn_type"] = overflowDetector.checkOverflow(
            file, inputType=properties["input_type"]
        )

    # Checking if format attack is possible
    if not overflow_only and not skip_check:
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

    # Leak the flag with format string attacks
    if properties["pwn_type"]["type"] == "Format":
        log.info("[+] Checking for flag leak")
        created_exploit = formatLeak.checkLeak(file, properties, leak_format)

        if created_exploit:
            return created_exploit

    # Exploit with overflow attack
    if properties["pwn_type"]["type"] == "Overflow":
        log.info("[+] Exploiting overflow")

        properties["pwn_type"]["results"] = {}
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            file, properties, inputType=properties["input_type"]
        )
        if properties["pwn_type"]["results"]["type"]:
            properties["send_results"] = overflowExploitSender.sendExploit(
                file, properties
            )

    # Exploit with overflow attack for function
    elif properties["pwn_type"]["type"] == "overflow_variable":
        properties["pwn_type"]["results"] = properties["pwn_type"]
        properties["send_results"] = overflowExploitSender.sendExploit(file, properties)

    # Exploit with format string attack
    elif properties["pwn_type"]["type"] == "Format":
        properties["pwn_type"]["results"] = formatExploiter.exploitFormat(
            file, properties
        )
    else:
        log.info("[-] Can not determine vulnerable type")
