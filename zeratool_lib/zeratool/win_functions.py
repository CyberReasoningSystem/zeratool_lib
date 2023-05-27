import json
import logging

import r2pipe

log = logging.getLogger(__name__)


def translate_win_names_to_refs(binary_name, win_function_names):
    win_functions_refs = {}

    radare = r2pipe.open(binary_name)
    radare.cmd("aaa")

    strings = [string for string in json.loads(radare.cmd("izj"))]
    for string in strings:
        value = string["string"]
        if any([x in value for x in win_function_names]):
            address = string["vaddr"]

            # Get XREFs
            refs = [func for func in json.loads(radare.cmd(f"axtj @ {address}"))]
            for ref in refs:
                if "fcn_name" in ref:
                    win_functions_refs[ref["fcn_name"]] = ref

    return win_functions_refs
