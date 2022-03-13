"""

    cbc
    ~~~

    This module provides an implementation for the Cipher Block Chaining (CBC)
    block cipher mode of operation.

    Author: Kinshuk Vasisht
    Dated : 12/03/2022

"""

import typing
import secrets

from .core import ModeOfOperation
from .padding import PaddingMode
from .utils import xor

class CipherBlockChainingMode(ModeOfOperation):
    """
        Implementation of the Cipher Block Chaining mode of operation.

        This mode of operation divides the plaintext into segments of a fixed block size each, after adding any
            padding as required, then the segments are encrypted sequentially, where each plaintext is XOR-ed with
                the ciphertext of the previous block prior to encryption. For the first block, the role of
                ciphertext is fulfilled using an initialization vector (IV).

        Encryption:
            => C_i = E(P_i ^ C_(i-1), K), where
                C_i = ciphertext block i,
                    P_i = plaintext block i
                        K = key used with the cipher
                            C_0 = IV (Initialization Vector)

        Decryption:
            => P_i = D(C_i, K) ^ C_(i-1)
    """

    def __init__(self, cipher, IV = None, padding_mode = PaddingMode.PAD_PKCS7, block_size = None):
        """ Creates a new CBC mode of operation instance.

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
        """ Encrypts multiple blocks of data using the CBC mode of operation.

        Args:
            plaintext (typing.Iterable[str | bytes]): Iterable yielding blocks of plaintext to encrypt.
            debug (bool, optional): If true, outputs extra data to view the steps of the procedure.

        Yields:
            str | bytes: The ciphertext blocks.
        """
        # Pad the data to make the length an integral multiple of the block size.
        plaintext = self.padding_mode.pad(plaintext, debug)

        # Encrypt blocks following the CBC procedure:
        last_ciphertext_block = self.IV
        for block_data in plaintext:
            if debug: plaintext_block = block_data['padded']
            else:     plaintext_block = block_data
            # P'_i = C_(i-1) ^ P_i
            plaintext_block = xor(plaintext_block, last_ciphertext_block)
            # C_i = E(P'_i, K) = E(C_(i-1) ^ P_i, K)
            ciphertext_block = self.cipher.encrypt(plaintext_block)

            if debug:
                block_data['encrypted'] = ciphertext_block
                block_data['last_encrypted'] = last_ciphertext_block
                yield block_data
            else:
                yield ciphertext_block
            last_ciphertext_block = ciphertext_block

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
            last_ciphertext_block = self.IV
            for ciphertext_block in ciphertext:
                # P'_i = D(C_i, K)
                plaintext_block = self.cipher.decrypt(ciphertext_block)
                # P_i = C_(i-1) ^ P'_i = C_(i-1) ^ D(C_i, K)
                plaintext_block = xor(plaintext_block, last_ciphertext_block)

                if debug:
                    yield {
                        'encrypted': ciphertext_block,
                        'decrypted': plaintext_block,
                        'last_encrypted': last_ciphertext_block
                    }
                else: yield plaintext_block
                last_ciphertext_block = ciphertext_block

        # Unpad the data to restore the original contents
        return self.padding_mode.unpad(plaintext_generator(), debug)