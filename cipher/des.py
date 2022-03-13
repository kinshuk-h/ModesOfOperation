"""

    des
    ~~~

    This module provides an implementation of the DES & 3-DES block ciphers, without the modes of operation.
    The individual components used prior to the Feistel rounds and those used within each round are
    also exposed for use. The implementation follows the standard DES guidelines.

    - Constants (Components):
        - INITIAL_PERMUTATION_BOX: Straight P-Box used in the initial and final permutation operations.
        - IN_ROUND_EXPANSION_PBOX: Expansion P-Box to be used within each round of DES, as the
          first operation over the right half.
        - IN_ROUND_SUBSTITUTION_BOXES: Set of S-Boxes used within each round of DES, after
          XOR-ing the key with the output of the Expansion P-Box.
        - IN_ROUND_STRAIGHT_PBOX: Straight P-Box to be used within each round of DES, after
          substitution with the S-Boxes.
        - INITIAL_KEY_PERMUTED_CHOICE_BOX: Initial P-Box to select 56-bits from the 64-bit key,
          discarding parity bits.
        - IN_ROUND_KEY_PERMUTED_CHOICE_BOX: P-Box used within each round of DES, after the
          circular left shift operation to select a 48-bit key.

    - Functions:
        - generate_round_keys: Generates 16 round keys from a given base key with
          parity bits as per the DES specifications.

    - Classes:
        - DES: Implementation of the DES block cipher.
        - TripleDES: Implementation of the 3-DES block cipher.

    Author: Kinshuk Vasisht
    Dated : 11/03/2022

"""

from . import utils
from .core import BlockCipher
from .components import substitution
from .components.transforms import common, pipeline
from .components.permutation import straight, resize

# Number of rounds in the DES cipher.
ROUND_COUNT          = 16
# Size of the key in bits, including parity bits.
KEY_SIZE_WITH_PARITY = 64

def cell_index(data: "int | str | bytes | list | tuple"):
    """ Mapping function to map received data to S-box table indices. """
    if isinstance(data, str): data = data.encode()
    if isinstance(data, bytes): data = int.from_bytes(data, byteorder='big')
    if not isinstance(data, int): data = int(''.join(data), 2)

    # row index is determined by concatenating the 1st and 6th bits of the data chunk.
    row    = (((data >> 5) & 1) << 1) | (data & 1)
    # column index is determined by the middle 4, bits of the data chunk
    column = (data >> 1) & 0xf
    return row, column

# Straight P-Box used in the initial and final permutation operations.
INITIAL_PERMUTATION_BOX = straight.StraightPBox(
    [
        58, 50, 42, 34, 26, 18, 10, 2 ,
        60, 52, 44, 36, 28, 20, 12, 4 ,
        62, 54, 46, 38, 30, 22, 14, 6 ,
        64, 56, 48, 40, 32, 24, 16, 8 ,
        57, 49, 41, 33, 25, 17, 9 , 1 ,
        59, 51, 43, 35, 27, 19, 11, 3 ,
        61, 53, 45, 37, 29, 21, 13, 5 ,
        63, 55, 47, 39, 31, 23, 15, 7 ,
    ], start = 1
)

# Expansion P-Box to be used within each round of DES, as the first operation over the right half.
IN_ROUND_EXPANSION_PBOX = resize.ExpansionPBox(
    [
        32, 1 , 2 , 3 , 4 , 5 ,
        4 , 5 , 6 , 7 , 8 , 9 ,
        8 , 9 , 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1 ,
    ], start = 1
)
# Set of S-Boxes used within each round of DES, after XOR-ing the key with the output of the Expansion P-Box.
IN_ROUND_SUBSTITUTION_BOXES = pipeline.HorizontalPipeline(
    [
        substitution.SBox([
            [ 14, 4 , 13, 1 , 2 , 15, 11, 8 , 3 , 10, 6 , 12, 5 , 9 , 0 , 7 , ],
            [ 0 , 15, 7 , 4 , 14, 2 , 13, 1 , 10, 6 , 12, 11, 9 , 5 , 3 , 8 , ],
            [ 4 , 1 , 14, 8 , 13, 6 , 2 , 11, 15, 12, 9 , 7 , 3 , 10, 5 , 0 , ],
            [ 15, 12, 8 , 2 , 4 , 9 , 1 , 7 , 5 , 11, 3 , 14, 10, 0 , 6 , 13, ],
        ], index_mapping = cell_index),
        substitution.SBox([
            [ 15, 1 , 8 , 14, 6 , 11, 3 , 4 , 9 , 7 , 2 , 13, 12, 0 , 5 , 10, ],
            [ 3 , 13, 4 , 7 , 15, 2 , 8 , 14, 12, 0 , 1 , 10, 6 , 9 , 11, 5 , ],
            [ 0 , 14, 7 , 11, 10, 4 , 13, 1 , 5 , 8 , 12, 6 , 9 , 3 , 2 , 15, ],
            [ 13, 8 , 10, 1 , 3 , 15, 4 , 2 , 11, 6 , 7 , 12, 0 , 5 , 14, 9 , ],
        ], index_mapping = cell_index),
        substitution.SBox([
            [ 10, 0 , 9 , 14, 6 , 3 , 15, 5 , 1 , 13, 12, 7 , 11, 4 , 2 , 8 , ],
            [ 13, 7 , 0 , 9 , 3 , 4 , 6 , 10, 2 , 8 , 5 , 14, 12, 11, 15, 1 , ],
            [ 13, 6 , 4 , 9 , 8 , 15, 3 , 0 , 11, 1 , 2 , 12, 5 , 10, 14, 7 , ],
            [ 1 , 10, 13, 0 , 6 , 9 , 8 , 7 , 4 , 15, 14, 3 , 11, 5 , 2 , 12, ],
        ], index_mapping = cell_index),
        substitution.SBox([
            [ 7 , 13, 14, 3 , 0 , 6 , 9 , 10, 1 , 2 , 8 , 5 , 11, 12, 4 , 15, ],
            [ 13, 8 , 11, 5 , 6 , 15, 0 , 3 , 4 , 7 , 2 , 12, 1 , 10, 14, 9 , ],
            [ 10, 6 , 9 , 0 , 12, 11, 7 , 13, 15, 1 , 3 , 14, 5 , 2 , 8 , 4 , ],
            [ 3 , 15, 0 , 6 , 10, 1 , 13, 8 , 9 , 4 , 5 , 11, 12, 7 , 2 , 14, ],
        ], index_mapping = cell_index),
        substitution.SBox([
            [ 2 , 12, 4 , 1 , 7 , 10, 11, 6 , 8 , 5 , 3 , 15, 13, 0 , 14, 9 , ],
            [ 14, 11, 2 , 12, 4 , 7 , 13, 1 , 5 , 0 , 15, 10, 3 , 9 , 8 , 6 , ],
            [ 4 , 2 , 1 , 11, 10, 13, 7 , 8 , 15, 9 , 12, 5 , 6 , 3 , 0 , 14, ],
            [ 11, 8 , 12, 7 , 1 , 14, 2 , 13, 6 , 15, 0 , 9 , 10, 4 , 5 , 3 , ],
        ], index_mapping = cell_index),
        substitution.SBox([
            [ 12, 1 , 10, 15, 9 , 2 , 6 , 8 , 0 , 13, 3 , 4 , 14, 7 , 5 , 11, ],
            [ 10, 15, 4 , 2 , 7 , 12, 9 , 5 , 6 , 1 , 13, 14, 0 , 11, 3 , 8 , ],
            [ 9 , 14, 15, 5 , 2 , 8 , 12, 3 , 7 , 0 , 4 , 10, 1 , 13, 11, 6 , ],
            [ 4 , 3 , 2 , 12, 9 , 5 , 15, 10, 11, 14, 1 , 7 , 6 , 0 , 8 , 13, ],
        ], index_mapping = cell_index),
        substitution.SBox([
            [ 4 , 11, 2 , 14, 15, 0 , 8 , 13, 3 , 12, 9 , 7 , 5 , 10, 6 , 1 , ],
            [ 13, 0 , 11, 7 , 4 , 9 , 1 , 10, 14, 3 , 5 , 12, 2 , 15, 8 , 6 , ],
            [ 1 , 4 , 11, 13, 12, 3 , 7 , 14, 10, 15, 6 , 8 , 0 , 5 , 9 , 2 , ],
            [ 6 , 11, 13, 8 , 1 , 4 , 10, 7 , 9 , 5 , 0 , 15, 14, 2 , 3 , 12, ],
        ], index_mapping = cell_index),
        substitution.SBox([
            [ 13, 2 , 8 , 4 , 6 , 15, 11, 1 , 10, 9 , 3 , 14, 5 , 0 , 12, 7 , ],
            [ 1 , 15, 13, 8 , 10, 3 , 7 , 4 , 12, 5 , 6 , 11, 0 , 14, 9 , 2 , ],
            [ 7 , 11, 4 , 1 , 9 , 12, 14, 2 , 0 , 6 , 10, 13, 15, 3 , 5 , 8 , ],
            [ 2 , 1 , 14, 7 , 4 , 10, 8 , 13, 15, 12, 9 , 0 , 3 , 5 , 6 , 11, ],
        ], index_mapping = cell_index),
    ], input_size = 48, output_size = 32
)
# Straight P-Box to be used within each round of DES, after substitution with the S-Boxes.
IN_ROUND_STRAIGHT_PBOX = straight.StraightPBox(
    [
        16, 7 , 20, 21,
        29, 12, 28, 17,
        1 , 15, 23, 26,
        5 , 18, 31, 10,
        2 , 8 , 24, 14,
        32, 27, 3 , 9 ,
        19, 13, 30, 6 ,
        22, 11, 4 , 25,
    ], start = 1
)

# The number of times to shift the bits of key halves across every round.
KEY_SHIFT_SCHEDULE = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
]

# Initial P-Box to select 56-bits from the 64-bit key, discarding parity bits.
INITIAL_KEY_PERMUTED_CHOICE_BOX = resize.CompressionPBox(
    [
        57, 49, 41, 33, 25, 17, 9 ,
        1 , 58, 50, 42, 34, 26, 18,
        10, 2 , 59, 51, 43, 35, 27,
        19, 11, 3 , 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7 , 62, 54, 46, 38, 30, 22,
        14, 6 , 61, 53, 45, 37, 29,
        21, 13, 5 , 28, 20, 12, 4 ,
    ], start = 1
)
# P-Box used within each round of DES, after the circular left shift operation to select a 48-bit key.
IN_ROUND_KEY_PERMUTED_CHOICE_BOX = resize.CompressionPBox(
    [
        14, 17, 11, 24, 1 , 5 ,
        3 , 28, 15, 6 , 21, 10,
        23, 19, 12, 4 , 26, 8 ,
        16, 7 , 27, 20, 13, 2 ,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32,
    ], start = 1
)

def generate_round_keys(key: "str | bytes | list | tuple", validate_key = True) -> "list[bytes|list]":
    """ Generates round keys as part of the key schedule for the DES cipher, using a given key with parity bits.

    Args:
        `key` (`list|tuple|str|bytes`): The key to use. Must contain exactly 64, bits, with
        the 8th LSB from each byte storing the parity status of the 7, bits to its left.

        `validate_key` (`bool`) If true, a parity check of each byte is performed prior to key schedule generation.

    Returns:
        `list[bytes|list]`: A list of 16, 48-bit keys (as bytes or a list of binary values)
            for use in each of the 16, rounds of the DES cipher algorithm.
    """

    key_size = utils.input_size(key)
    if key_size != KEY_SIZE_WITH_PARITY:
        raise ValueError(generate_round_keys.__name__+": incorrect key size")

    if validate_key:
        # Validate parity bits in the given key:
        if isinstance(key, (str, bytes)):
            if isinstance(key, str): key = key.encode()
            for byte in key:
                bit_xor = 0
                for _ in range(8):
                    bit_xor ^= byte & 1
                    byte >>= 1
                if bit_xor != 0:
                    raise ValueError(
                        generate_round_keys.__name__+": parity "+
                        "mismatch in possibly corrupted key"
                    )

    # Generate round keys:
    key = INITIAL_KEY_PERMUTED_CHOICE_BOX.encrypt(key)
    key_half_size = utils.input_size(key) >> 1

    key_left, key_right = utils.binary_split(key)

    round_keys = []
    for round_shift in KEY_SHIFT_SCHEDULE:
        key_left  = utils.circular_shift_left(key_left , round_shift, key_half_size)
        key_right = utils.circular_shift_left(key_right, round_shift, key_half_size)

        key_base = utils.binary_join(key_left, key_right, key_half_size)
        round_key = IN_ROUND_KEY_PERMUTED_CHOICE_BOX.encrypt(key_base)
        round_keys.append(round_key)

    return round_keys

class DES(BlockCipher):
    """ Implementation the DES Block cipher. The implementation follows the DES specifications.

        Permutation tables used in involved operations may be verified from
        [Wikipedia](https://en.wikipedia.org/wiki/DES_supplementary_material).
    """
    BLOCK_SIZE = 64
    KEY_SIZE   = 64 # Includes parity bits

    def __init__(self, key: "str | bytes | list | tuple", validate_key = False):
        """ Creates a new DES cipher instance.

        Args:
            key (str | bytes | list | tuple): The key to use for encryption and decryption.
            Must be a 64-bit data object where the 8th bit of every byte is a parity bit
            for the previous 7, bits.

            validate_key (bool, optional): Whether to validate the key, i.e., perform a parity check
            prior to round key generation. Defaults to True.
        """
        super().__init__()

        self.key = key
        self.round_keys = generate_round_keys(self.key, validate_key)

    def encrypt(self, plaintext: "str | bytes | list | tuple"):
        """ Encrypts a given plaintext using a DES cipher instance.

        Args:
            plaintext (int | str | bytes | list | tuple): The plaintext to encrypt.

        Returns:
            int | bytes | list: The encrypted ciphertext.
        """

        plaintext_size = utils.input_size(plaintext)
        if plaintext_size != self.BLOCK_SIZE:
            raise ValueError(
                self.__class__.__name__ + ": incorrect plaintext block size, "+
                "the standard implementation operates only over a 64 bit block (8 bytes). "+
                "For other sizes, use the cipher with a mode of operation."
            )

        # Initial Permutation: over the bits of the plaintext.
        ciphertext = INITIAL_PERMUTATION_BOX.encrypt(plaintext)

        # Divide block into left and right parts
        left_subblock, right_subblock = utils.binary_split(ciphertext)

        # Execute 16 Feistel rounds over the left and right halves.
        for round in range(ROUND_COUNT):
            old_right_subblock = right_subblock

            # Defines the function: F(R_(i-1), K_i) ^ L_(i-1)
            round_function = pipeline.Pipeline([
                IN_ROUND_EXPANSION_PBOX,
                common.XorKey(self.round_keys[round]),
                IN_ROUND_SUBSTITUTION_BOXES,
                IN_ROUND_STRAIGHT_PBOX,
                common.XorKey(left_subblock)
            ], order = pipeline.Order.ORIGINAL)

            right_subblock = round_function.encrypt(right_subblock)
            left_subblock  = old_right_subblock

        # Perform a final swap of the blocks, followed by concatenation.
        ciphertext = utils.binary_join(right_subblock, left_subblock)

        # Final Permutation: over the bits of the ciphertext.
        ciphertext = INITIAL_PERMUTATION_BOX.decrypt(ciphertext)

        return ciphertext

    def decrypt(self, ciphertext: "str | bytes | list | tuple"):
        """ Decrypts a given ciphertext using a DES cipher instance with the same key as used during encryption.

            The decryption procedure is effectively the same encryption procedure except that the order of
            round keys as used during encryption is reversed.

        Args:
            plaintext (int | str | bytes | list | tuple): The ciphertext to decrypt.

        Returns:
            int | bytes | list: The decrypted plaintext.
        """

        ciphertext_size = utils.input_size(ciphertext)
        if ciphertext_size != self.BLOCK_SIZE:
            raise ValueError(
                self.__class__.__name__ + ": incorrect plaintext block size, "+
                "the standard implementation operates only over a 64 bit block (8 bytes). "+
                "For other sizes, use the cipher with a mode of operation."
            )

        # Initial Permutation: over the bits of the ciphertext.
        plaintext = INITIAL_PERMUTATION_BOX.encrypt(ciphertext)

        # Divide block into left and right parts
        left_subblock, right_subblock = utils.binary_split(plaintext)

        # Execute 16 Feistel rounds over the left and right halves.
        for round in range(ROUND_COUNT):
            old_right_subblock = right_subblock

            # Defines the function: F(R_(i-1), K_(16-i)) ^ L_(i-1)
            round_function = pipeline.Pipeline([
                IN_ROUND_EXPANSION_PBOX,
                common.XorKey(self.round_keys[ROUND_COUNT-round-1]),
                IN_ROUND_SUBSTITUTION_BOXES,
                IN_ROUND_STRAIGHT_PBOX,
                common.XorKey(left_subblock)
            ], order = pipeline.Order.ORIGINAL)

            right_subblock = round_function.encrypt(right_subblock)
            left_subblock  = old_right_subblock

        # Perform a final swap of the blocks, followed by concatenation.
        plaintext = utils.binary_join(right_subblock, left_subblock)

        # Final Permutation: over the bits of the plaintext.
        plaintext = INITIAL_PERMUTATION_BOX.decrypt(plaintext)

        return plaintext

class TripleDES(BlockCipher):
    """ Implementation the Triple DES Block cipher. The implementation follows the 3-DES specifications.
        A total of two DES sized keys specified as a single object with 112 bits are used in this implementation.
    """
    BLOCK_SIZE = 64
    KEY_SIZE   = 128 # Includes parity bits

    def __init__(self, key: "str | bytes | list | tuple", validate_key = False):
        """ Creates a new 3-DES cipher instance.

        Args:
            key (str | bytes | list | tuple): The key to use for encryption and decryption.
            Must be a 128-bit data object where the 8th bit of every byte is a parity bit
            for the previous 7, bits.

            validate_key (bool, optional): Whether to validate the key, i.e., perform a parity check
            prior to round key generation. Defaults to True.
        """
        super().__init__()

        key_1 = key[ : (self.KEY_SIZE >> 4) ]
        key_2 = key[ (self.KEY_SIZE >> 4) : ]

        des_1 = DES(key_1, validate_key=validate_key)
        des_2 = DES(key_2, validate_key=validate_key)

        self.cipher = pipeline.Pipeline([ des_1, des_2, des_1 ])

    def encrypt(self, plaintext: "str | bytes | list | tuple"):
        """ Encrypts a given plaintext using a 3-DES cipher instance.

        Args:
            plaintext (int | str | bytes | list | tuple): The plaintext to encrypt.

        Returns:
            int | bytes | list: The encrypted ciphertext.
        """
        return self.cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: "str | bytes | list | tuple"):
        """ Decrypts a given ciphertext using a 3-DES cipher instance with the same key as used during encryption.

        Args:
            plaintext (int | str | bytes | list | tuple): The ciphertext to decrypt.

        Returns:
            int | bytes | list: The decrypted plaintext.
        """
        return self.cipher.decrypt(ciphertext)