"""
    common
    ~~~~~~

    This module provides common ciphers which result in simple transformations.

    - Classes
        - Swapper: Swaps left and right halves of a given data object
        - XorKey: Acts as a One-Time Pad, XOR-ing a key with the given data

    Author: Kinshuk Vasisht
    Dated : 10/03/2022
"""

from ... import utils

class Swapper:
    """ Defines a simple transformation component which swaps two halves of a given input. """

    def encrypt(self, plaintext: "str | bytes | list | tuple"):
        """ Encrypts the given plaintext by swapping the halves. """
        plaintext_half_size = utils.input_size(plaintext) >> 1

        if isinstance(plaintext, (str, bytes)):
            if isinstance(plaintext, str): plaintext = plaintext.encode()
            bits = int.from_bytes(plaintext, byteorder = 'big', signed = False)
            low_bits_half  = (bits & ((1 << plaintext_half_size) - 1))
            high_bits_half = (bits >> plaintext_half_size)
            swapped_bits = (low_bits_half << plaintext_half_size) | high_bits_half
            return swapped_bits.to_bytes(plaintext_half_size >> 2, byteorder = 'big', signed = False)
        else:
            return plaintext[plaintext_half_size:] + plaintext[:plaintext_half_size]

    def decrypt(self, ciphertext: "str | bytes | list | tuple"):
        """ Decrypts the given ciphertext by swapping the halves. """
        return self.encrypt(ciphertext)

class XorKey:
    """
        Defines a One-Time Pad cipher. Encryption and decryption is achieved
        by bitwise XOR-ing the key with the plaintext and ciphertext.
    """
    def __init__(self, key: "int | str | bytes | list | tuple"):
        if isinstance(key, str): self.key = key.encode()
        else: self.key = key
        self.key_size = utils.input_size(self.key)

    def encrypt(self, plaintext: "int | str | bytes | list | tuple"):
        """ Encrypts a given plaintext using a XorKey cipher instance.

        Args:
            plaintext (int | str | bytes | list | tuple): The plaintext to encrypt.

        Returns:
            int | bytes | list: The encrypted ciphertext.
        """
        plaintext_size = utils.input_size(plaintext)
        if self.key_size != plaintext_size:
            raise ValueError(self.__class__.__name__ + ": key and data length mismatch")

        if isinstance(plaintext, (str, bytes, int)):
            if not isinstance(self.key, (int, bytes)):
                raise TypeError(self.__class__.__name__ + ": key and data type mismatch")
            if isinstance(plaintext, str): plaintext = plaintext.encode()

            as_bytes = isinstance(plaintext, bytes)
            if as_bytes: plaintext = int.from_bytes(plaintext, byteorder = 'big', signed = False)

            if isinstance(self.key, bytes):
                key_bits = int.from_bytes(self.key , byteorder = 'big', signed = False)
            else: key_bits = self.key

            ciphertext = (plaintext ^ key_bits)
            if as_bytes: ciphertext = ciphertext.to_bytes(plaintext_size >> 3, byteorder='big', signed=False)
            return ciphertext

        else:
            if isinstance(self.key, (int, bytes)):
                raise TypeError(self.__class__.__name__ + ": key and data type mismatch")

            return [ ki ^ pi for ki, pi in zip(self.key, plaintext) ]

    def decrypt(self, ciphertext: "int | str | bytes | list | tuple"):
        """ Decrypts the given ciphertext encrypted using a XorKey cipher instance with the same key.

        Args:
            ciphertext (int | str | bytes | list | tuple): The ciphertext to decrypt.

        Returns:
            int | bytes | list: The decrypted plaintext.
        """
        # Initially, encryption yields:
        #   => E(M, K) => M ^ K
        # Double encryption yields:
        #   => E(E(M, K), K) => E(M, K) ^ K => M ^ K ^ K => M
        return self.encrypt(ciphertext)