"""

    main.py
    ~~~~~~~

    Provides a demonstration of the step-by-step working of the block cipher modes of operations.

    Author: Kinshuk Vasisht
    Dated : 13/03/2022

"""

import re
import sys
import secrets

from math import ceil
import traceback

import modes
from cipher import des

MODE_OF_OPERATIONS = {
    'ECB': modes.ElectronicCodeBookMode,
    'CBC': modes.CipherBlockChainingMode,
    'CFB': modes.CipherFeedBackMode,
    'OFB': modes.OutputFeedBackMode,
    'CTR': modes.CounterMode,
}
PADDING_STRATEGIES = {
    'NONE' : modes.padding.PaddingMode.PAD_NONE ,
    'ZEROS': modes.padding.PaddingMode.PAD_ZEROS,
    'PKCS7': modes.padding.PaddingMode.PAD_PKCS7
}

def compatible(mode, padding_mode):
    if mode == "CFB" or mode == "OFB": return True
    else: return padding_mode != "NONE"

def read_crypt_variable(label, bit_size):
    value = input(f"< | Enter {label} to use (leave blank for random): ")
    if not value: value = secrets.token_bytes(bit_size >> 3)
    if isinstance(value, str):
        if value.startswith("0x"): value = bytes.fromhex(value[2:])
        else: value = value.encode()

    if len(value) != (bit_size >> 3):
        print(f"X | error: incorrect size ({len(value) << 3}) for {label}, ({bit_size}) bits required")
        sys.exit(1)

    print(      "> | Chosen", label, "(hex)                         :", value.hex(' ', 2))
    return value

def to_hex(byte_str: bytes, sep = ' ', bytes_per_sep = 2):
    """ Converts bytes to a hex string, with segment division from left """
    hexstr = byte_str.hex()
    if bytes_per_sep < 1: bytes_per_sep = len(hexstr)
    chunks = [
        hexstr[ i : i + (bytes_per_sep << 1) ]
        for i in range(0, len(hexstr), bytes_per_sep << 1)
    ]
    return sep.join(chunks)

def print_blocks(expression, *values):
    """ Prints tokens in the given expression in blocks/boxes. """
    matches = re.findall(r"(?<!\\)\$(\d+)", expression)
    chunks = re.split(r"(?<!\\)\$\d+", expression)

    print(len(chunks[0]) * ' ', end = '')
    for i, (match, chunk) in enumerate(zip(matches, chunks[1:]), 1):
        start_char = "┬" if (chunks[i-1] == "|") else "┌"
        end_char   = "" if (chunk == "|") else "┐"
        print(start_char + "─" + '─' * len(values[int(match)-1]) + "─" + end_char, end = '')
        print(len(chunk if chunk != '|' else '') * ' ', end = '')
    print()

    print(chunks[0], end = '')
    for i, (match, chunk) in enumerate(zip(matches, chunks[1:]), 1):
        end_char   = "" if (chunk == "|") else "│"
        print("│ " + values[int(match)-1] + " " + end_char, end = '')
        print(chunk if chunk != '|' else '', end = '')
    print()

    print(len(chunks[0]) * ' ', end = '')
    for i, (match, chunk) in enumerate(zip(matches, chunks[1:]), 1):
        start_char = "┴" if (chunks[i-1] == "|") else "└"
        end_char   = "" if (chunk == "|") else "┘"
        print(start_char + "─" + '─' * len(values[int(match)-1]) + "─" + end_char, end = '')
        print(len(chunk if chunk != '|' else '') * ' ', end = '')
    print()

def to_str(value):
    """ Maps mode of operation arguments to string representation. """
    if isinstance(value, bytes): return "0x"+value.hex()
    elif isinstance(value, str): return value
    elif isinstance(value, int): return str(value)
    elif isinstance(value, modes.padding.PaddingMode): return value.name
    else: return value.__class__.__name__

if __name__ == "__main__":
    print("> | Modes of Operations: Demonstration\n")

    block_size = des.DES.BLOCK_SIZE
    key_size   = des.DES.KEY_SIZE

    try:
        key = read_crypt_variable("key", key_size  ); print()
        base_cipher = des.DES(key, validate_key=False)

        print("> | Select a mode of operation:")
        for i, (mode, class_) in enumerate(MODE_OF_OPERATIONS.items(), 1):
            print(f"  | {i})", class_.__name__[:-4], f"({mode})")
        mode = input("< | Select a mode of operation               : ")
        while mode not in MODE_OF_OPERATIONS:
            print(
                f"X | error: invalid mode of operation: {mode}, choose from",
                ', '.join(MODE_OF_OPERATIONS.keys())
            )
            mode = input("< | Select a mode of operation               : ")
        print()

        print("> | Select a padding strategy:")
        for i, (padding_mode, class_) in enumerate(PADDING_STRATEGIES.items(), 1):
            print(f"  | {i})", class_.name, f"({padding_mode})")
        padding_mode = input("< | Select a padding strategy                : ")
        while (padding_mode and padding_mode not in PADDING_STRATEGIES) or not compatible(mode, padding_mode):
            if not compatible(mode, padding_mode):
                print(
                    f"X | error: invalid padding strategy:", padding_mode,
                    "for", mode, "mode of operation"
                )
            else:
                print(
                    f"X | error: invalid padding strategy: {padding_mode}, choose from",
                    ', '.join(PADDING_STRATEGIES.keys())
                )
            padding_mode = input("< | Select a padding strategy                : ")
        print()

        mode_of_operation_args = { 'cipher': base_cipher }
        if padding_mode:
            mode_of_operation_args['padding_mode'] = PADDING_STRATEGIES[padding_mode]

        if mode != "ECB":
            IV  = read_crypt_variable("IV ", block_size); print()
            mode_of_operation_args["IV"] = IV

        if mode == "CFB" or mode == "OFB":
            chunk_size = input(f"< | Enter the stream block size (bits) for use with {mode}: ")
            if not chunk_size: chunk_size = "0"
            chunk_size = int(chunk_size)
            while not ( 8 <= chunk_size <= block_size ):
                print(f"X | error: invalid stream block size ({chunk_size}), must be in the range 8-{block_size}")
                chunk_size = int(input(f"< | Enter the stream block size (bits) for use with {mode}: "))
            print()
        else:
            chunk_size = block_size
        mode_of_operation_args['block_size'] = chunk_size

        print("< | Enter some plaintext to encrypt          :\n")
        lines = []
        while True:
            line = input("    ")
            if line == "": break
            lines.append(line)
        print()
        plaintext = '\n'.join(lines)

        if not plaintext:
            plaintext = "Some dummy data to encrypt and decrypt because the user did not specify any input."

        mode_cipher = MODE_OF_OPERATIONS[mode](**mode_of_operation_args)
        arg_str = ', '.join([ arg+"="+to_str(val) for arg, val in mode_of_operation_args.items() ])
        print("> | Using the", mode, f"mode of operation ({arg_str}):\n")

        print("> | Supplied plaintext                       :")
        for line in plaintext.split('\n'): print("  |", line)
        print()

        plaintext = plaintext.encode()
        print("> | Encoded plaintext                        :")
        for i in range(0, len(plaintext), block_size >> 1):
            print("  |", to_hex(plaintext[ i : i + (block_size >> 1) ], ' ', block_size >> 3))
        print()

        block_width = ((block_size >> 4) - 1) + (block_size >> 2)
        chunk_width = ((chunk_size >> 4) - 1) + (chunk_size >> 2)
        block_count_width = len(str(ceil(len(plaintext) / (chunk_size >> 3))))
        enc_widths = {
            'ECB': (block_count_width<<1) + 16,
            'CBC': (block_count_width*3)  + 21,
            'CFB': (block_count_width*3)  + 25,
            'OFB': (block_count_width*3)  + 23,
            'CTR': (block_count_width*3)  + 18
        }

        print("> | Encrypting the given plaintext           :\n")

        ciphertext      = bytearray()
        chunk_generator = modes.utils.block_generator(plaintext, chunk_size)

        for i, block_data in enumerate(mode_cipher.encrypt(chunk_generator, debug = True)):
            print("  | Block #", i+1)

            if block_data['padded'] != block_data['original']:
                print_blocks(
                    f"    {'After padding':{enc_widths[mode]}}: $1 => $2",
                    f"{to_hex(block_data['original'], ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['padded']  , ' ', 2):{chunk_width}}"
                )

            if   mode == "ECB":
                print_blocks(
                    f"    C_{i+1:{block_count_width}} = E(P_{i+1:{block_count_width}}, K) = E($1, $2) = $3",
                    f"{to_hex(block_data['padded']   , ' ', 2):{chunk_width}}",
                    f"{to_hex(key                    , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['encrypted'], ' ', 2):{chunk_width}}"
                )
            elif mode == "CBC":
                print_blocks(
                    f"    C_{i+1:{block_count_width}} = E(P_{i+1:{block_count_width}} "+
                        f"^ C_{i:{block_count_width}}, K) = E($1 ^ $2, $3) = $4",
                    f"{to_hex(block_data['padded']        , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['last_encrypted'], ' ', 2):{chunk_width}}",
                    f"{to_hex(key                         , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['encrypted']     , ' ', 2):{chunk_width}}"
                )
            elif mode == "CFB":
                IV_LSB = block_data['E_IV'][chunk_size >> 3:]
                label = f"C_{i+1:{block_count_width}} = P_{i+1:{block_count_width}} ^ " + \
                        f"MSB(IV'_{i+1:{block_count_width}}, {chunk_size})"
                print_blocks(
                    f"    IV'_{i+1:{block_count_width}} = E(IV_{i+1:{block_count_width}}, K) = E($1, $2) = $3|$4",
                    f"{to_hex(block_data['IV']      , ' ', 2):{block_width}}",
                    f"{to_hex(key                   , ' ', 2):{block_width}}",
                    f"{to_hex(block_data['MSB_E_IV'], ' ', 2):{chunk_width}}",
                    f"{to_hex(IV_LSB                , ' ', 2):{block_width - chunk_width}}"
                )
                print_blocks(
                    f"    {label:{enc_widths[mode]}} = $1 ^ $2 = $3",
                    f"{to_hex(block_data['padded']   , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['MSB_E_IV'] , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['encrypted'], ' ', 2):{chunk_width}}",
                )
                print_blocks(
                    f"    IV_{i+2:{block_count_width}} = LSB(IV'_{i+1:{block_count_width}}, " +
                        f"{block_size-chunk_size}) || C_{i+1:{block_count_width}} = $1 || $2 = $3|$4",
                    f"{to_hex(IV_LSB                 , ' ', 2):{block_width - chunk_width}}",
                    f"{to_hex(block_data['encrypted'], ' ', 2):{chunk_width}}",
                    f"{to_hex(IV_LSB                 , ' ', 2):{block_width - chunk_width}}",
                    f"{to_hex(block_data['encrypted'], ' ', 2):{chunk_width}}"
                )
            elif mode == "OFB":
                print_blocks(
                    f"    IV'_{i+1:{block_count_width}} = E(IV_{i+1:{block_count_width}}, K) = E($1, $2) = $3|$4",
                    f"{to_hex(block_data['IV']                    , ' ', 2):{block_width}}",
                    f"{to_hex(key                                 , ' ', 2):{block_width}}",
                    f"{to_hex(block_data['MSB_E_IV']              , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['E_IV'][chunk_size >> 3:], ' ', 2):{block_width - chunk_width}}"
                )
                print_blocks(
                    f"    C_{i+1:{block_count_width}} = P_{i+1:{block_count_width}} ^ MSB" +
                        f"(IV'_{i+1:{block_count_width}}, {chunk_size}) = $1 ^ $2 = $3",
                    f"{to_hex(block_data['padded']   , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['MSB_E_IV'] , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['encrypted'], ' ', 2):{chunk_width}}",
                )
                label = f"IV_{i+2:{block_count_width}} = IV'_{i+1:{block_count_width}}"
                print_blocks(
                    f"    {label:{enc_widths[mode]}} = $1",
                    f"{to_hex(block_data['E_IV'], ' ', 2):{block_width}}",
                )
            elif mode == "CTR":
                print_blocks(
                    f"    IV'_{i+1:{block_count_width}} = E(IV_{i+1:{block_count_width}}, K) = E($1, $2) = $3",
                    f"{to_hex(block_data['IV']  , ' ', 2):{chunk_width}}",
                    f"{to_hex(key               , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['E_IV'], ' ', 2):{chunk_width}}"
                )
                label = f"C_{i+1:{block_count_width}} = P_{i+1:{block_count_width}} ^ IV'_{i+1:{block_count_width}}"
                print_blocks(
                    f"    {label:{enc_widths[mode]}}= $1 ^ $2 = $3",
                    f"{to_hex(block_data['padded']   , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['E_IV']     , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['encrypted'], ' ', 2):{chunk_width}}",
                )

            ciphertext += block_data['encrypted']
        print()

        print("> | Obtained ciphertext                      :")
        for i in range(0, len(ciphertext), block_size >> 1):
            print("  |", to_hex(ciphertext[ i : i + (block_size >> 1) ], ' ', block_size >> 3))
        print()

        print("> | Decrypting the obtained ciphertext       :\n")

        plaintext       = bytearray(); ciphertext      = bytes(ciphertext)
        chunk_generator = modes.utils.block_generator(ciphertext, chunk_size)

        dec_widths = {
            'ECB': (block_count_width<<1) + 16,
            'CBC': (block_count_width*3)  + 19,
            'CFB': (block_count_width*3)  + 25,
            'OFB': (block_count_width*3)  + 23,
            'CTR': (block_count_width*3)  + 18
        }

        for i, block_data in enumerate(mode_cipher.decrypt(chunk_generator, debug = True)):
            print("  | Block #", i+1)
            if   mode == "ECB":
                print_blocks(
                    f"    P_{i+1:{block_count_width}} = D(C_{i+1:{block_count_width}}, K) = E($1, $2) = $3",
                    f"{to_hex(block_data['encrypted']   , ' ', 2):{chunk_width}}",
                    f"{to_hex(key                    , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['decrypted'], ' ', 2):{chunk_width}}"
                )
            elif mode == "CBC":
                print_blocks(
                    f"    P_{i+1:{block_count_width}} = C_{i:{block_count_width}} ^ " +
                        f"D(C_{i+1:{block_count_width}}, K) = $1 ^ D($2, $3) = $4",
                    f"{to_hex(block_data['last_encrypted'], ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['encrypted']     , ' ', 2):{chunk_width}}",
                    f"{to_hex(key                         , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['decrypted']     , ' ', 2):{chunk_width}}"
                )
            elif mode == "CFB":
                IV_LSB = block_data['E_IV'][chunk_size >> 3:]
                label = f"P_{i+1:{block_count_width}} = C_{i+1:{block_count_width}} ^ " + \
                        f"MSB(IV'_{i+1:{block_count_width}}, {chunk_size})"
                print_blocks(
                    f"    IV'_{i+1:{block_count_width}} = E(IV_{i+1:{block_count_width}}, K) = E($1, $2) = $3|$4",
                    f"{to_hex(block_data['IV']      , ' ', 2):{block_width}}",
                    f"{to_hex(key                   , ' ', 2):{block_width}}",
                    f"{to_hex(block_data['MSB_E_IV'], ' ', 2):{chunk_width}}",
                    f"{to_hex(IV_LSB                , ' ', 2):{block_width - chunk_width}}"
                )
                print_blocks(
                    f"    {label:{dec_widths[mode]}} = $1 ^ $2 = $3",
                    f"{to_hex(block_data['encrypted'], ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['MSB_E_IV'] , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['decrypted'], ' ', 2):{chunk_width}}",
                )
                print_blocks(
                    f"    IV_{i+2:{block_count_width}} = LSB(IV'_{i+1:{block_count_width}}, " +
                        f"{block_size-chunk_size}) || C_{i+1:{block_count_width}} = $1 || $2 = $3|$4",
                    f"{to_hex(IV_LSB                 , ' ', 2):{block_width - chunk_width}}",
                    f"{to_hex(block_data['encrypted'], ' ', 2):{chunk_width}}",
                    f"{to_hex(IV_LSB                 , ' ', 2):{block_width - chunk_width}}",
                    f"{to_hex(block_data['encrypted'], ' ', 2):{chunk_width}}"
                )
            elif mode == "OFB":
                print_blocks(
                    f"    IV'_{i+1:{block_count_width}} = E(IV_{i+1:{block_count_width}}, K) = E($1, $2) = $3|$4",
                    f"{to_hex(block_data['IV']                    , ' ', 2):{block_width}}",
                    f"{to_hex(key                                 , ' ', 2):{block_width}}",
                    f"{to_hex(block_data['MSB_E_IV']              , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['E_IV'][chunk_size >> 3:], ' ', 2):{block_width - chunk_width}}"
                )
                print_blocks(
                    f"    P_{i+1:{block_count_width}} = C_{i+1:{block_count_width}} ^ MSB" +
                        f"(IV'_{i+1:{block_count_width}}, {chunk_size}) = $1 ^ $2 = $3",
                    f"{to_hex(block_data['encrypted'], ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['MSB_E_IV'] , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['decrypted'], ' ', 2):{chunk_width}}",
                )
                label = f"IV_{i+2:{block_count_width}} = IV'_{i+1:{block_count_width}}"
                print_blocks(
                    f"    {label:{dec_widths[mode]}} = $1",
                    f"{to_hex(block_data['E_IV'], ' ', 2):{block_width}}",
                )
            elif mode == "CTR":
                print_blocks(
                    f"    IV'_{i+1:{block_count_width}} = E(IV_{i+1:{block_count_width}}, K) = E($1, $2) = $3",
                    f"{to_hex(block_data['IV']  , ' ', 2):{chunk_width}}",
                    f"{to_hex(key               , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['E_IV'], ' ', 2):{chunk_width}}"
                )
                label = f"P_{i+1:{block_count_width}} = C_{i+1:{block_count_width}} ^ IV'_{i+1:{block_count_width}}"
                print_blocks(
                    f"    {label:{dec_widths[mode]}}= $1 ^ $2 = $3",
                    f"{to_hex(block_data['encrypted'], ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['E_IV']     , ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['decrypted'], ' ', 2):{chunk_width}}",
                )

            if block_data['unpadded'] != block_data['decrypted']:
                print_blocks(
                    f"    {'After unpadding':{dec_widths[mode]}}: $1 => $2",
                    f"{to_hex(block_data['decrypted'], ' ', 2):{chunk_width}}",
                    f"{to_hex(block_data['unpadded'] , ' ', 2):{chunk_width}}"
                )

            plaintext += block_data['unpadded']
        print()

        print("> | Decrypted plaintext                      :")
        for i in range(0, len(plaintext), block_size >> 1):
            print("  |", to_hex(plaintext[ i : i + (block_size >> 1) ], ' ', block_size >> 3))
        print()

        plaintext = plaintext.decode('utf-8')
        for line in plaintext.split('\n'): print("  |", line)

    except Exception as reason:
        print("X | error:", reason)
        traceback.print_exc()