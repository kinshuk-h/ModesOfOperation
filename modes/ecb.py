"""

    ecb
    ~~~

    This module provides an implementation for the Electronic Codebook (ECB)
    block cipher mode of operation.

    Author: Kinshuk Vasisht
    Dated : 12/03/2022

"""

import typing

from .core import ModeOfOperation
from .padding import PaddingMode

class ElectronicCodeBookMode(ModeOfOperation):
    """
        Implementation of the Electronic Codebook mode of operation.

        This mode of operation divides the plaintext into segments of a fixed
            block size each, after adding any padding as required, then the segments are
                individually encrypted using the same cipher and key.

        Encryption:
            => C_i = E(P_i, K), where
                C_i = ciphertext block i,
                    P_i = plaintext block i
                        K = key used with the cipher

        Decryption:
            => P_i = D(C_i, K)
    """

    def __init__(self, cipher, padding_mode = PaddingMode.PAD_PKCS7, block_size = None):
        super().__init__(cipher, padding_mode, block_size)

    def encrypt(self, plaintext: "typing.Iterable[str | bytes]", debug = False):
        """ Encrypts multiple blocks of data using the ECB mode of operation.

        Args:
            plaintext (typing.Iterable[str | bytes]): Iterable yielding blocks of plaintext to encrypt.
            debug (bool, optional): If true, outputs extra data to view the steps of the procedure.

        Yields:
            str | bytes: The ciphertext blocks.
        """
        plaintext = self.padding_mode.pad(plaintext, debug)

        for plaintext_block in plaintext:
            if debug:
                ciphertext_block = self.cipher.encrypt(plaintext_block['padded'])
                plaintext_block['encrypted'] = ciphertext_block
                yield plaintext_block
            else: yield self.cipher.encrypt(plaintext_block)

    def decrypt(self, ciphertext: "typing.Iterable[str | bytes]", debug = False):
        """ Decrypts blocks encrypted using the ECB mode of operation.

        Args:
            ciphertext (typing.Iterable[str | bytes]): Iterable yielding blocks of ciphertext to decrypt.
            debug (bool, optional): If true, outputs extra data to view the steps of the procedure.

        Yields:
            str | bytes: The plaintext blocks.
        """
        def plaintext_generator():
            for ciphertext_block in ciphertext:
                plaintext_block = self.cipher.decrypt(ciphertext_block)
                if debug: yield { 'encrypted': ciphertext_block, 'decrypted': plaintext_block }
                else: yield plaintext_block

        return self.padding_mode.unpad(plaintext_generator(), debug)