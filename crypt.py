"""

    crypt.py
    ~~~~~~~~

    Performs encryption and decryption of files using common modes of operations for block ciphers.

    Operations:

    -   Encrypt: A file can be encrypted using a block cipher mode of operation.
        Example:

        # Encrypts the file using the OFB mode of operation, and random keys and IV.
        # The keys and IV are saved in a .crypt file for decryption in future,
        # so this file must be kept securely.
        >>> $ crypt.py "<file>" --mode "OFB"

    -   Decrypt: A file can be decrypted using the block cipher mode of operation and
               cryptographic variables used at the time of encryption (key and IV).
        Example:

        # Decrypts the file data present in the .enc file based on the encryption settings as
        # recorded in the .crypt file.
        >>> $ crypt.py "<file>.enc" --decrypt --credentials "<file>.crypt"


    Author: Kinshuk Vasisht
    Dated : 12/03/2022

"""

import os
import sys
import json
import timeit
import base64
import secrets
import argparse

from math import ceil, floor

import modes
from cipher import des

CIPHERS = {
    'DES': des.DES
}

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

class ProgressBar:
    """ Defines a progress bar with fractional increments. """
    states = ( ' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█' )
    def __init__(self, limit = 100, size = 60):
        self.width = len(str(limit))
        self.length = size
        self.limit = limit
        self.reset()
    def reset(self, limit = None):
        if limit:
            self.width = len(str(limit))
            self.limit = limit
        self.position = 0
        self._completed = False
    def set(self, position):
        self.position = position
        if self.position >= self.limit: self._completed = True
    def advance(self, increment = 1):
        if(self.position < self.limit): self.position += increment
        else: self._completed = True
    @property
    def completed(self):
        return self._completed
    def count(self): return f"({self.position:{self.width}}/{self.limit})"
    def __str__(self):
        fill_length          = floor(self.length * 100 * (self.position/self.limit))
        fill_length_fraction = fill_length % 100
        fill_length          = fill_length // 100
        progress     = fill_length * self.states[-1]
        sub_progress = self.states[floor(fill_length_fraction/12.5)] if fill_length < self.length else ''
        left         = (self.length-1-fill_length) * self.states[0]
        return f"│{progress}{sub_progress}{left}│"

def chunk_generator(file, chunk_size):
    """ Generates chunks of a given size from a file. """
    while True:
        chunk = file.read(chunk_size >> 3)
        if not chunk: break
        yield chunk

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description = (
            "Performs encryption and decryption of files "
            "using common modes of operations for block ciphers."
        ),
        epilog = (
            "Multiple modes, padding strategies and ciphers may be chosen from. "
            "Keys and IVs may be specified on the command line directly or loaded using a .crypt file."
        )
    )

    parser.add_argument(
        "-d", "--decrypt", action = "store_true",
        help = "perform decryption of file contents"
    )

    parser.add_argument("path", help = "path of file to encrypt")
    parser.add_argument(
        "-o", "--output", help = "path to output file", default = None
    )
    parser.add_argument(
        "-c", "--cipher", help = "cipher to use for encryption/decryption",
        default = 'DES', choices = [ *CIPHERS.keys() ]
    )
    parser.add_argument(
        '-m', '--mode', help = "block cipher mode of operation to use",
        default = "CFB", choices = [ *MODE_OF_OPERATIONS.keys() ]
    )
    parser.add_argument(
        '-p', '--padding', help = "padding strategy to use",
        choices = [ *PADDING_STRATEGIES.keys() ], default = None
    )

    parser.add_argument(
        '-k', '--key', default = None,
        help = "key to use for encryption, defaulting to a randomly generated value",
    )
    parser.add_argument(
        '--iv', '--vector', dest = "init_vector", default = None,
        help = "IV to use in the mode of operation, defaulting to a randomly generated value",
    )
    parser.add_argument(
        '-B', '--stream-size', default = 8, type = int,
        help = "Size of stream blocks for CFB and OFB mode of operations, in bits"
    )
    parser.add_argument(
        '--no-save', dest = "save", action = "store_false",
        help = "whether to save key and IV in a crypt file for use later"
    )
    parser.add_argument(
        '-q', '--credentials', default = None,
        help = "path to credentials file to load key and IV values for encryption/decryption"
    )

    args = parser.parse_args()

    IV   = args.init_vector
    key  = args.key

    if args.credentials and not (IV and key):
        if not os.path.exists(args.credentials):
            print(parser.prog + f": error: file '{args.credentials}' does not exist", file = sys.stderr)
            sys.exit(1)

        with open(args.credentials, 'r+') as file:
            data = base64.b64decode(file.read())
            credentials = json.loads(data)
            IV               = credentials["IV"]
            key              = credentials["key"]
            args.cipher      = credentials["cipher"]
            args.mode        = credentials["mode"]
            args.padding     = credentials["padding_mode"]
            args.stream_size = credentials["chunk_size"]

    key_size = CIPHERS[args.cipher].KEY_SIZE
    if not key:
        if args.decrypt:
            print(
                parser.prog + ": warning: using random key in a decryption operation",
                file = sys.stderr
            )
        key = secrets.token_bytes(key_size >> 3)
    if isinstance(key, str):
        if key.startswith("0x"): key = bytes.fromhex(key[2:])
        else: key = key.encode()

    block_size = CIPHERS[args.cipher].BLOCK_SIZE
    if not IV:
        if args.decrypt:
            print(
                parser.prog + ": warning: using random IV in a decryption operation",
                file = sys.stderr
            )
        IV = secrets.token_bytes(block_size >> 3)
    if isinstance(IV, str):
        if IV.startswith("0x"): IV = bytes.fromhex(IV[2:])
        else: IV = IV.encode()

    if args.stream_size > block_size:
        print(
            parser.prog + f": error: stream size block (s, {args.stream_size}) cannot " +
            f"be larger than the block size (b, {block_size})", file = sys.stderr
        )
        sys.exit(1)

    chunk_size = (args.stream_size or 8) if args.mode == 'CFB' or args.mode == 'OFB' else block_size

    if not os.path.exists(args.path):
        print(parser.prog + f": error: file '{args.path}' does not exist", file = sys.stderr)
        sys.exit(1)

    mode_of_operation_args = { 'cipher': CIPHERS[args.cipher](key) }
    if args.mode != 'ECB':
        mode_of_operation_args['IV'] = IV
    if args.padding is not None:
        mode_of_operation_args['padding_mode'] = PADDING_STRATEGIES[args.padding]

    cipher_mode = MODE_OF_OPERATIONS[args.mode](**mode_of_operation_args)

    if args.decrypt:
        output_path = args.output
        if output_path is None:
            if args.path.endswith(".enc"):
                output_path = args.path[:-4]
            else:
                output_path = args.path + ".dec"
    else:
        output_path = args.output or args.path + ".enc"

    print(
        parser.prog + ":", ("decrypting" if args.decrypt else "encrypting"),
        f"'{os.path.basename(args.path)}' to '{os.path.basename(output_path)}' ..."
    )

    path_stats = os.stat(args.path)
    bar = ProgressBar(limit = ceil(path_stats.st_size / (chunk_size >> 3)), size = 40)

    with open(args.path, "rb") as file:
        with open(output_path, "wb") as output_file:
            start = timeit.default_timer()

            chunks = chunk_generator(file, chunk_size)

            if args.decrypt: processed_chunks = cipher_mode.decrypt(chunks)
            else           : processed_chunks = cipher_mode.encrypt(chunks)

            width = len(str(bar.limit))
            print(f"\r> Chunk/Segment #{0:0{width}}:", bar, end = "")
            for i, chunk in enumerate(processed_chunks):
                output_file.write(chunk); bar.advance()
                print(f"\r> Chunk/Segment #{i:0{width}}:", bar, end = "")
            print()

            end = timeit.default_timer()

    print(
        parser.prog + ":", ("decryption" if args.decrypt else "encryption"),
        f"of '{os.path.basename(args.path)}' completed in {end-start:.3f}s"
    )

    if args.save and not args.decrypt:
        credential_path = args.credentials or args.path + ".crypt"

        credential_data = json.dumps({
            'mode': args.mode, 'cipher': args.cipher,
            'key': "0x"+key.hex(), 'IV': "0x"+IV.hex(),
            'padding_mode': args.padding, 'chunk_size': chunk_size
        }, indent = 4, ensure_ascii = False)

        with open(credential_path, "w+") as credential_file:
            credential_data = base64.b64encode(credential_data.encode()).decode('utf-8')
            credential_file.write(credential_data)

        print(parser.prog + f": credentials saved to {os.path.basename(credential_path)}")