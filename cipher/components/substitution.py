"""
    substitution
    ~~~~~~~~~~~~

    This module provides component ciphers for substitution operations, such as S-Boxes.

    - Classes
        - SBox: Defines a common S-Box which utilizes a substitution table to encrypt data.

    Author: Kinshuk Vasisht
    Dated : 11/03/2022
"""

import typing

from .. import utils

class SBox:
    """
        A substitution box, which given a data chunk maps it to row and column indices
            and returns the data value at this position from the substitution table.
    """

    def __init__(
        self, substitution_table: "list[list[int | str | bytes | list | tuple]]",
        index_mapping: typing.Callable[[ "int | str | bytes | list | tuple" ], tuple[int, int]],
        # inverse_subsitution_table: "list[list[int | str | bytes | list | tuple]] | None" = None
    ):
        """ Creates a new SBox cipher instance.

        Args:
            substitution_table (list[list[int | str | bytes | list | tuple]]): A substitution table providing
            values to return as the substitution.

            index_mapping (typing.Callable[[ int | str | bytes | list | tuple ], tuple[int, int]]): A function mapping
            a data object to row and column indices for the substitution table.
        """
        self.substitution_table        = substitution_table
        self.index_mapping             = index_mapping
        self.inverse_subsitution_table = None

        # TODO: Implement support for inverse substitution tables.
        # if inverse_subsitution_table:
        #     self.inverse_subsitution_table = inverse_subsitution_table

    def encrypt(self, plaintext: "int | str | bytes | list | tuple"):
        """ Encrypts the given plaintext using an SBox cipher instance.

        Args:
            plaintext (int | str | bytes | list | tuple): The plaintext to encrypt.

        Returns:
            int | str | bytes | list | tuple: The encrypted ciphertext.
        """
        row, column = self.index_mapping(plaintext)
        ciphertext = self.substitution_table[row][column]

        if isinstance(plaintext, (str, bytes)):
            if isinstance(ciphertext, bytes): return ciphertext
            elif isinstance(ciphertext, str): return ciphertext.encode()
            elif not isinstance(ciphertext, int):
                ciphertext = int(''.join(ciphertext), 2)
            bit_count = utils.input_size(ciphertext)
            byte_count = bit_count >> 3
            if (byte_count << 3) < bit_count: byte_count += 1
            return ciphertext.to_bytes(byte_count, byteorder='big')

        elif isinstance(plaintext, int):
            if isinstance(ciphertext, int): return ciphertext
            elif isinstance(ciphertext, (str, bytes)):
                if isinstance(ciphertext, str): ciphertext = ciphertext.encode()
                return int.from_bytes(ciphertext, byteorder='big')
            return int(''.join(ciphertext), 2)

        else:
            if isinstance(ciphertext, str): ciphertext = ciphertext.encode()
            if isinstance(ciphertext, bytes):
                ciphertext = int.from_bytes(ciphertext, byteorder='big')
            if not isinstance(ciphertext, int): return ciphertext
            return [ int(bit) for bit in bin(ciphertext)[2:].split('') ]

    def decrypt(self, _: "int | str | bytes | list | tuple"):
        """ Decrypts the given ciphertext using an SBox cipher index with the same substitution table.
        Unless an inverse substitution table is specified, this is a no-op included only for compatibility purposes.

        Args:
            ciphertext (int | str | bytes | list | tuple): The ciphertext to decrypt.

        Raises:
            ValueError: For a missing inverse substitution table, an error is raised to indicate the problem.
        """
        # TODO: Implement support for decryption using the inverse substitution table.
        # if not self.inverse_subsitution_table:
        raise ValueError(
            self.__class__.__name__ + ": component behaviour is non-invertible "+
            "without an explicitly provided inverse substitution table."
        )