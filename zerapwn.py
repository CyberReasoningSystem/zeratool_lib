#!/usr/bin/env python
from __future__ import print_function

import logging
import os

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


class WinFunction:
    name: str
    address: int


# TODO (@iosifache): Return the exploit
def exploit(
    file: str,
    libc: str,
    win_functions: list(WinFunction),
    verbose: bool = False,
    force_shellcode: bool = False,
    force_dlresolve: bool = False,
    skip_check: bool = False,
    format_only: bool = False,
    overflow_only: bool = False,
) -> None:
    if file is None:
        log.info("[-] Exitting no file specified")
        exit(1)

    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        for loud_logger in loud_loggers:
            logging.getLogger(loud_logger).setLevel(logging.ERROR)
            logging.getLogger("angr.project").disabled = True

    # For stack problems where env gets shifted
    # based on path, using the abs path everywhere
    # makes it consistent
    file = os.path.abspath(file)

    properties = {}
    properties["file"] = file
    properties["input_type"] = inputDetector.checkInputType(file)
    properties["libc"] = libc
    properties["force_shellcode"] = force_shellcode
    properties["pwn_type"] = {}
    properties["pwn_type"]["type"] = None
    properties["force_dlresolve"] = force_dlresolve
    log.info("[+] Checking pwn type...")

    # Is there an easy win function
    properties["win_functions"] = win_functions if win_functions else []

    if not format_only and not skip_check:
        log.info("[+] Checking for overflow pwn type...")
        properties["pwn_type"] = overflowDetector.checkOverflow(
            file, inputType=properties["input_type"]
        )
    if not overflow_only and not skip_check:
        if properties["pwn_type"]["type"] is None:
            log.info("[+] Checking for format string pwn type...")
            properties["pwn_type"] = formatDetector.checkFormat(
                file, inputType=properties["input_type"]
            )

    if skip_check and overflow_only:
        properties["pwn_type"]["type"] = "Overflow"
    if skip_check and format_only:
        properties["pwn_type"]["type"] = "Format"

    # Get problem mitigations
    log.info("[+] Getting binary protections")
    properties["protections"] = protectionDetector.getProperties(file)

    # Is it a leak based one?
    if properties["pwn_type"]["type"] == "Format":
        log.info("[+] Checking for flag leak")
        properties["pwn"] = formatLeak.checkLeak(file, properties)
        if properties["pwn"]["flag_found"]:
            exit(0)

    # Exploit overflows
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

    elif properties["pwn_type"]["type"] == "overflow_variable":
        properties["pwn_type"]["results"] = properties["pwn_type"]
        properties["send_results"] = overflowExploitSender.sendExploit(file, properties)

    elif properties["pwn_type"]["type"] == "Format":
        properties["pwn_type"]["results"] = formatExploiter.exploitFormat(
            file, properties
        )
    else:
        log.info("[-] Can not determine vulnerable type")
