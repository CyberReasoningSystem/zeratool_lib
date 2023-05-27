import angr
import IPython

stdin = "STDIN"
arg = "ARG"


def checkInputType(binary_name):
    p = angr.Project(binary_name, load_options={"auto_load_libs": False})

    #    CFG = p.analyses.CFGFast()

    # Functions which MIGHT grab from STDIN
    reading_functions = ["fgets", "gets", "scanf", "read", "__isoc99_scanf"]
    #    binary_functions = [str(x[1].name) for x in CFG.kb.functions.items()]
    binary_functions = list(p.loader.main_object.imports.keys())

    # Match reading functions against local functions
    if any([x in reading_functions for x in binary_functions]):
        return "STDIN"
    return "ARG"
