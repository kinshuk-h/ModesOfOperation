"""

    cfb
    ~~~

    This module provides an implementation for the Cipher Feedback (CFB)
    block cipher mode of operation.

    Author: Kinshuk Vasisht
    Dated : 12/03/2022

"""

import typing
import secrets

from .core import ModeOfOperation
from .padding import PaddingMode
from .utils import xor

class CipherFeedBackMode(ModeOfOperation):
    """
        Implementation of the Cipher Feedback mode of operation.

        This mode of operation divides the plaintext into segments of a fixed stream size, without requiring any padding,
            then the segments are encrypted sequentially, where each plaintext is XOR-ed with
                the most significant bits of encryption of a IV at the n-th stage. For the nth stage, the IV is obtained
                    by shifting the bits of the previous IV to the left and adding the ciphertext to it at the end.

        Since the IV is the data actually passed to the cipher, the plaintext may be divided into chunks much smaller
            than the block size, which avoids need of padding and allows operation as a stream cipher.

        Encryption:
            => C_i = P_i ^ MSB(E(IV_i, K), s), & IV_(i+1) = LSB(IV_i, b-s) | C^i) where
                C_i = ciphertext block i,
                    P_i = plaintext block i
                        K = key used with the cipher
                            IV_1 = IV (Initialization Vector)
                                s = stream block size
                                    b = block size

        Decryption:
            => P_i = C_i ^ MSB(E(IV_i, K), s), as a result the decryption process
                also uses the encryption operation of the cipher.
    """

    def __init__(self, cipher, IV = None, padding_mode = PaddingMode.PAD_NONE, block_size = None):
        """ Creates a new CFB mode of operation instance.

        Args:
            cipher (BlockCipher): A block cipher providing an encrypt and decrypt method.
            IV (str | bytes | None, optional): Initialization vector to use in the operation.
                Defaults to None, for which a random IV is generated.
            padding_mode (PaddingStrategy, optional): Padding Strategy to use. Defaults to PaddingMode.PAD_NONE.
            block_size (int | None, optional): Block size used by the cipher. Defaults to None, where it is
                inferred from the cipher instance.
        """
        super().__init__(cipher, padding_mode, block_size)
        self.IV = IV or secrets.token_bytes(self.block_size >> 3)

    def encrypt(self, plaintext: "typing.Iterable[str | bytes]", debug = False):
        """ Encrypts multiple blocks of data using the CFB mode of operation.

        Args:
            plaintext (typing.Iterable[str | bytes]): Iterable yielding blocks of plaintext to encrypt.
            debug (bool, optional): If true, outputs extra data to view the steps of the procedure.

        Yields:
            str | bytes: The ciphertext blocks.
        """
        # Pad the data to make the length an integral multiple of the block size.
        # By default this is a no-op for cipher and output feedback modes.
        plaintext = self.padding_mode.pad(plaintext, debug)

        # Encrypt blocks following the CFB procedure:
        last_IV = self.IV
        for segment_data in plaintext:
            if debug: plaintext_segment = segment_data['padded']
            else    : plaintext_segment = segment_data

            # IV'_i = E(IV_i, K)
            encrypted_IV = self.cipher.encrypt(last_IV)
            # K'_i = MSB(IV'_i, s) = MSB(E(IV_i, K), s)
            IV_msb = encrypted_IV[ 0 : len(plaintext_segment) ]
            # C_i = P_i ^ K'_i = P_i ^ MSB(E(IV_i, K), s)
            ciphertext_segment = xor(plaintext_segment, IV_msb)

            if debug:
                segment_data.update({
                    'encrypted': ciphertext_segment,
                    'IV': last_IV, 'E_IV': encrypted_IV,
                    'MSB_E_IV': IV_msb
                })
                yield segment_data
            else: yield ciphertext_segment

            # IV_(i+1) = LSB(IV_i, b-s) | C^i)
            last_IV = last_IV [ len(plaintext_segment) : ] + ciphertext_segment

    def decrypt(self, ciphertext: "typing.Iterable[str | bytes]", debug = False):
        """ Decrypts blocks encrypted using the CFB mode of operation.

        Args:
            ciphertext (typing.Iterable[str | bytes]): Iterable yielding blocks of ciphertext to decrypt.
            debug (bool, optional): If true, outputs extra data to view the steps of the procedure.

        Yields:
            str | bytes: The plaintext blocks.
        """
        # Decrypt blocks following the CFB procedure:
        def plaintext_generator():
            last_IV = self.IV
            for ciphertext_segment in ciphertext:
                # IV'_i = E(IV_i, K)
                encrypted_IV = self.cipher.encrypt(last_IV)
                # K'_i = MSB(IV'_i, s) = MSB(E(IV_i, K), s)
                IV_msb = encrypted_IV[ 0 : len(ciphertext_segment) ]
                # P_i = C_i ^ K'_i = P_i ^ MSB(E(IV_i, K), s)
                plaintext_segment = xor(ciphertext_segment, IV_msb)

                if debug:
                    yield {
                        'encrypted': ciphertext_segment,
                        'decrypted': plaintext_segment,
                        'IV': last_IV, 'E_IV': encrypted_IV,
                        'MSB_E_IV': IV_msb
                    }
                else: yield plaintext_segment

                # IV_(i+1) = LSB(IV_i, b-s) | C^i)
                last_IV = last_IV [ len(plaintext_segment) : ] + ciphertext_segment

        # Unpad the data to restore the original contents
        # By default this is a no-op for cipher and output feedback modes.
        return self.padding_mode.unpad(plaintext_generator(), debug)