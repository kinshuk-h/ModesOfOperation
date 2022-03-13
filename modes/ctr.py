"""

    ctr
    ~~~

    This module provides an implementation for the Counter (CTR)
    block cipher mode of operation.

    Author: Kinshuk Vasisht
    Dated : 12/03/2022

"""

import typing
import secrets

from .core import ModeOfOperation
from .padding import PaddingMode
from .utils import xor

class CounterMode(ModeOfOperation):
    """
        Implementation of the Counter mode of operation.

        This mode of operation divides the plaintext into segments of a fixed block size each, after adding any
            padding as required, then the segments are encrypted individually, where each plaintext is XOR-ed with
                the encrypted version of IV_i, where the ith IV is defined as IV + i - 1. For the first block, IV_0 = IV.

        Encryption:
            => C_i = P_i ^ E(IV + i - 1, K), where
                C_i = ciphertext block i,
                    P_i = plaintext block i
                        K = key used with the cipher
                            IV = Initialization Vector

        Decryption:
            => P_i = C_i ^ E(IV + i - 1, K), as a result the decryption process
                also uses the encryption operation of the cipher.
    """

    def __init__(self, cipher, IV = None, padding_mode = PaddingMode.PAD_PKCS7, block_size = None):
        """ Creates a new CTR mode of operation instance.

        Args:
            cipher (BlockCipher): A block cipher providing an encrypt and decrypt method.
            IV (str | bytes | None, optional): Initialization vector to use in the operation.
                Defaults to None, for which a random IV is generated.
            padding_mode (PaddingStrategy, optional): Padding Strategy to use. Defaults to PaddingMode.PAD_ZEROS.
            block_size (int | None, optional): Block size used by the cipher. Defaults to None, where it is
                inferred from the cipher instance.
        """
        super().__init__(cipher, padding_mode, block_size)
        self.IV = IV or secrets.token_bytes(self.block_size >> 3)

    def encrypt(self, plaintext: "typing.Iterable[str | bytes]", debug = False):
        """ Encrypts multiple blocks of data using the CTR mode of operation.

        Args:
            plaintext (typing.Iterable[str | bytes]): Iterable yielding blocks of plaintext to encrypt.
            debug (bool, optional): If true, outputs extra data to view the steps of the procedure.

        Yields:
            str | bytes: The ciphertext blocks.
        """
        # Pad the data to make the length an integral multiple of the block size.
        plaintext = self.padding_mode.pad(plaintext, debug)

        # Encrypt blocks following the CTR procedure:
        last_IV = self.IV
        for block_data in plaintext:
            if debug: plaintext_block = block_data['padded']
            else    : plaintext_block = block_data

            # IV'_i = E(IV_i, K) = E(IV + i - 1, K)
            encrypted_IV = self.cipher.encrypt(last_IV)
            # C_i = P_i ^ IV'_i = P_i ^ E(IV + i - 1, K)
            ciphertext_block = xor(plaintext_block, encrypted_IV)

            if debug:
                block_data['encrypted'] = ciphertext_block
                block_data['IV']        = last_IV
                block_data['E_IV']      = encrypted_IV
                yield block_data
            else: yield ciphertext_block

            IV_bits = int.from_bytes(last_IV, byteorder='big')
            # IV_(i+1) = IV_i + 1 = IV + i
            last_IV = ((IV_bits + 1) & ((1 << self.block_size) - 1))
            last_IV = last_IV.to_bytes(self.block_size >> 3, byteorder='big')

    def decrypt(self, ciphertext: "typing.Iterable[str | bytes]", debug = False):
        """ Decrypts blocks encrypted using the CBC mode of operation.

        Args:
            ciphertext (typing.Iterable[str | bytes]): Iterable yielding blocks of ciphertext to decrypt.
            debug (bool, optional): If true, outputs extra data to view the steps of the procedure.

        Yields:
            str | bytes: The plaintext blocks.
        """
        # Decrypt blocks following the CBC procedure:
        def plaintext_generator():
            last_IV = self.IV
            for ciphertext_block in ciphertext:
                # IV'_i = E(IV_i, K) = E(IV + i - 1, K)
                encrypted_IV = self.cipher.encrypt(last_IV)
                # C_i = P_i ^ IV'_i = P_i ^ E(IV + i - 1, K)
                plaintext_block = xor(ciphertext_block, encrypted_IV)

                if debug:
                    yield {
                        'encrypted': ciphertext_block,
                        'decrypted': plaintext_block,
                        'IV'       : last_IV,
                        'E_IV'     : encrypted_IV
                    }
                else: yield plaintext_block

                IV_bits = int.from_bytes(last_IV, byteorder='big')
                # IV_(i+1) = IV_i + 1 = IV + i
                last_IV = ((IV_bits + 1) & ((1 << self.block_size) - 1))
                last_IV = last_IV.to_bytes(self.block_size >> 3, byteorder='big')

        # Unpad the data to restore the original contents
        return self.padding_mode.unpad(plaintext_generator(), debug)