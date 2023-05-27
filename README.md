# `zeratool_lib` 🗡️

## Description

`zeratool_lib` is a fork of [Zeratool](https://github.com/ChrisTheCoolHut/Zeratool). Its purpose is to port the CLI tool into a **Python 3 library** for **exploiting executables on the local machine**.

> **Notice**: `zeratool_lib` is not a rewrite of Zeratool. It still uses the exploitation logic implemented by Zeratool's developers, but it has the modifications stated in the next section.

### Differences Compared to the Parent Repository

- The CLI was replaces with a unique function that can be called by programs which imports the library. All relevant parameters are exposed as parameters of this function.
- All remote exploitation logic was removed.
- The exploit is returned by the main function.
- `libpwnable` is no more an input stream. The only ones supported now are `stdin` and arguments.

## Setup

Install the required Python 3 packages via `poetry install --no-dev`.

## Usage

```python
from zeratool_lib import exploit, SupportedInputStreams

payload, outcome = exploit(
    "key-manager.elf",
    input_stream=SupportedInputStreams.STDIN,
    overflow_only=True,
    win_functions=["get_private_key"],
    leak_format="(.*)BEGIN PRIVATE KEY(.*)"
)
```
