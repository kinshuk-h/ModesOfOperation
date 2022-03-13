"""

    resize
    ~~~~~~

    This module provides permutation boxes with a resizing effect,
    i.e. boxes which either increase or decrease the number of bits
    in the output.

    - Classes:
        - ExpansionPBox: P-Box for expansion.
        - CompressionPBox: P-Box for compression.

    Author: Kinshuk Vasisht
    Dated : 09/03/2022

"""

from ... import utils

class ExpansionPBox:
    """ A permutation box to perform an expansion effect, i.e, a permutation of the
        data bits along with some introduced bit repetitions is returned upon encryption. """

    def __init__(self, lookup_table: "list[int] | tuple[int]", start = 0):
        """ Creates a new ExpansionPBox instance.

        Args:
            lookup_table (list|tuple): A lookup table of positions for permutation. Must contain some
            repeated positions to produce the expansion.
            start (int, optional): The start index of the first bit in the table. Defaults to 0.
        """
        self.lookup_table = [ position - start for position in lookup_table ]
        self.inverse_lookup_table = list(range(max(lookup_table)-start+1))
        for index, position in enumerate(self.lookup_table):
            self.inverse_lookup_table[position] = index

    def encrypt(self, plaintext: "int | str | bytes | list | tuple"):
        """ Encrypts a given plaintext using an ExpansionPBox cipher instance.

        Args:
            plaintext (int | str | bytes | list | tuple): The plaintext to encrypt.

        Returns:
            int | bytes | list: The encrypted ciphertext.
        """
        plaintext_size = utils.input_size(plaintext)
        expanded_size  = len(self.lookup_table)

        if isinstance(plaintext, (str, bytes)):
            if isinstance(plaintext, str): plaintext = plaintext.encode()
            bits = int.from_bytes(plaintext, byteorder = 'big', signed = False)
            permuted_bits = 0
            for index, position in enumerate(self.lookup_table):
                if (bits >> (plaintext_size - position - 1)) & 1:
                    permuted_bits |= (1 << (expanded_size - index - 1))
            return permuted_bits.to_bytes(expanded_size >> 3, byteorder='big', signed=False)
        elif isinstance(plaintext, int):
            permuted_bits = 0
            for index, position in enumerate(self.lookup_table):
                if (plaintext >> (plaintext_size - position - 1)) & 1:
                    permuted_bits |= (1 << (expanded_size - index - 1))
            return permuted_bits
        else:
            return [
                plaintext[position]
                for position in self.lookup_table
            ]

    def decrypt(self, ciphertext: "int | str | bytes | list | tuple"):
        """ Decrypts the given ciphertext encrypted using an ExpansionPBox cipher instance with the same lookup table.
        Decryption is performed using the inverse of the lookup table.

        Args:
            ciphertext (int | str | bytes | list | tuple): The ciphertext to decrypt.

        Returns:
            int | bytes | list: The decrypted plaintext.
        """
        ciphertext_size = utils.input_size(ciphertext)
        compressed_size = len(self.inverse_lookup_table)

        if isinstance(ciphertext, (str, bytes)):
            if isinstance(ciphertext, str): ciphertext = ciphertext.encode()
            bits = int.from_bytes(ciphertext, byteorder = 'big', signed = False)
            permuted_bits = 0
            for index, position in enumerate(self.inverse_lookup_table):
                if (bits >> (ciphertext_size - position - 1)) & 1:
                    permuted_bits |= (1 << (compressed_size - index - 1))
            return permuted_bits.to_bytes(compressed_size >> 3, byteorder = 'big', signed = False)
        elif isinstance(ciphertext, int):
            permuted_bits = 0
            for index, position in enumerate(self.inverse_lookup_table):
                if (ciphertext >> (ciphertext_size - position - 1)) & 1:
                    permuted_bits |= (1 << (compressed_size - index - 1))
            return permuted_bits
        else:
            return [
                ciphertext[position]
                for position in self.inverse_lookup_table
            ]

class CompressionPBox:
    """ A permutation box to perform a compression effect, i.e., a
        permutation of select bits from the original data is returned upon encryption.
        Does not support decryption. """

    def __init__(self, lookup_table, start = 0):
        """ Creates a new CompressionPBox instance.

        Args:
            lookup_table (_type_): A lookup table of positions for permutation. Must be of a
            reduced size with missing positions to produce the compression.
            start (int, optional): The start index of the first bit in the table. Defaults to 0.
        """
        self.lookup_table = [ position - start for position in lookup_table ]

    def encrypt(self, plaintext: "int | str | bytes | list | tuple"):
        """ Encrypts a given plaintext using a CompressionPBox cipher instance.

        Args:
            plaintext (int | str | bytes | list | tuple): The plaintext to encrypt.

        Returns:
            int | bytes | list: The encrypted ciphertext.
        """
        plaintext_size  = utils.input_size(plaintext)
        compressed_size = len(self.lookup_table)

        if isinstance(plaintext, (str, bytes)):
            if isinstance(plaintext, str): plaintext = plaintext.encode()
            bits = int.from_bytes(plaintext, byteorder = 'big', signed = False)
            permuted_bits = 0
            for index, position in enumerate(self.lookup_table):
                if (bits >> (plaintext_size - position - 1)) & 1:
                    permuted_bits |= (1 << (compressed_size - index - 1))
            return permuted_bits.to_bytes(compressed_size >> 3, byteorder = 'big', signed = False)
        elif isinstance(plaintext, int):
            permuted_bits = 0
            for index, position in enumerate(self.lookup_table):
                if (plaintext >> (plaintext_size - position - 1)) & 1:
                    permuted_bits |= (1 << (compressed_size - index - 1))
            return permuted_bits
        else:
            return [
                plaintext[position]
                for position in self.lookup_table
            ]

    def decrypt(self, _):
        """ Decrypts the given ciphertext encrypted using a CompressionPBox cipher instance with the same lookup table.
        This is a dummy function equivalent to a no-op, included for compatibility purposes.

        Args:
            ciphertext (int | str | bytes | list | tuple): The ciphertext to decrypt.

        Raises:
            Exception: A general exception indicating the no-op behaviour of the function,
            due to the involvement of a non-invertible operation of finding bits removed
            from the original plaintext.
        """
        raise Exception(
            f"{self.__class__.__name__}: Component does not support decryption "+
            "due to involvement of a non-invertible operation."
        )