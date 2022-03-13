"""

    straight
    ~~~~~~~~

    This module provides an implementation of a straight P-Box,
    useful for generating permutations of a data object.

    - Classes
        - StraightPBox: Performs a permutation of data using a lookup table.

    Author: Kinshuk Vasisht
    Dated : 09/03/2022

"""

from ... import utils

class StraightPBox:
    """ A simple straightforward permutation box. Given a lookup table and
        data, the result is a permutation of the bits of the data using the
        positions from the lookup table. """

    def __init__(self, lookup_table: "list[int] | tuple[int]", start = 0):
        """ Creates a new StraightPBox instance.

        Args:
            lookup_table (list|tuple): A lookup table of positions for permutation.
            start (int, optional): The start index of the first bit in the table. Defaults to 0.
        """
        self.lookup_table = [ position - start for position in lookup_table ]
        self.inverse_lookup_table = list(range(len(lookup_table)))
        for index, position in enumerate(self.lookup_table):
            self.inverse_lookup_table[position] = index

    def encrypt(self, plaintext: "int | str | bytes | list | tuple"):
        """ Encrypts a given plaintext using a StraightPBox cipher instance.

        Args:
            plaintext (int | str | bytes | list | tuple): The plaintext to encrypt.

        Returns:
            int | bytes | list: The encrypted ciphertext.
        """
        plaintext_size = utils.input_size(plaintext)

        if plaintext_size != len(self.lookup_table):
            raise Exception(
                f"{self.__class__.__name__}: component requires length of "+
                "plaintext to match that of the lookup table."
            )

        if isinstance(plaintext, (str, bytes)):
            if isinstance(plaintext, str): plaintext = plaintext.encode()
            bits = int.from_bytes(plaintext, byteorder = 'big', signed = False)
            permuted_bits = 0
            for index, position in enumerate(self.lookup_table):
                if (bits >> (plaintext_size - position - 1)) & 1:
                    permuted_bits |= (1 << (plaintext_size - index - 1))
            return permuted_bits.to_bytes(plaintext_size >> 3, byteorder = 'big', signed = False)
        elif isinstance(plaintext, int):
            permuted_bits = 0
            for index, position in enumerate(self.lookup_table):
                if (plaintext >> (plaintext_size - position - 1)) & 1:
                    permuted_bits |= (1 << (plaintext_size - index - 1))
            return permuted_bits
        else:
            return [ plaintext[position] for position in self.lookup_table ]

    def decrypt(self, ciphertext: "int | str | bytes | list | tuple"):
        """ Decrypts the given ciphertext encrypted using a StraightPBox cipher instance with the same lookup table.
        Decryption is performed using the inverse of the lookup table.

        Args:
            ciphertext (int | str | bytes | list | tuple): The ciphertext to decrypt.

        Returns:
            int | bytes | list: The decrypted plaintext.
        """
        ciphertext_size = utils.input_size(ciphertext)

        if ciphertext_size != len(self.lookup_table):
            raise Exception(
                f"{self.__class__.__name__}: component requires length of "+
                "ciphertext to match that of the inverse lookup table."
            )

        if isinstance(ciphertext, (str, bytes)):
            if isinstance(ciphertext, str):
                ciphertext = ciphertext.encode()
            bits = int.from_bytes(ciphertext, byteorder='big', signed=False)
            permuted_bits = 0
            for index, position in enumerate(self.inverse_lookup_table):
                if (bits >> (ciphertext_size - position - 1)) & 1:
                    permuted_bits |= (1 << (ciphertext_size - index - 1))
            return permuted_bits.to_bytes(ciphertext_size >> 3, byteorder='big', signed=False)
        elif isinstance(ciphertext, int):
            permuted_bits = 0
            for index, position in enumerate(self.inverse_lookup_table):
                if (ciphertext >> (ciphertext_size - position - 1)) & 1:
                    permuted_bits |= (1 << (ciphertext_size - index - 1))
            return permuted_bits
        else:
            return [ ciphertext[position] for position in self.inverse_lookup_table ]