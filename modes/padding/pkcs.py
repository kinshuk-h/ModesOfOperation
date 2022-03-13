"""

    pkcs
    ~~~~

    This module provides an implementation of the padding strategy used in the
    Public-Key Cryptography Standards (PKCS#7 or PKCS7, etc).

    Author: Kinshuk Vasisht
    Dated : 12/03/2022

"""

import typing

from ..core import PaddingStrategy

class PadPKCS7(PaddingStrategy):
    """
        Padding strategy in accordance with the Public-Key Cryptography Standards #7 (PKCS#7 or PKCS7).
            PKCS #7 is the standard syntax for storing signed and/or encrypted data, defined in [RFC 5652](https://tools.ietf.org/html/rfc5652#section-6.3)

        This padding strategy adds whole bytes as padding to the plaintext, where the value of
            the byte to pad is exactly is the number of bytes being padded. Further, if the length of the
                original data is an integer multiple of the block size, then an entire extra block of bytes is added,
                    which helps avoid any form of ambiguity at the deciphering end.
    """

    def __init__(self):
        super().__init__()

    def pad(self, plaintext: "typing.Iterable[str | bytes]"):
        """ Pads the plaintext to complete the length of the last block.

        Args:
            plaintext (Iterable[str | bytes]): The plaintext to pad.

        Raises:
            AttributeError: Raised when the block_size property is not
                explicitly set prior to calling this method.

        Yields:
            str | bytes: The padded plaintext.
        """
        if self.block_size is None:
            raise AttributeError(
                self.__class__.__name__ + ": block_size value not explicitly set."
            )

        block = next(plaintext, None)
        while True:
            next_block = next(plaintext, None)

            if next_block is None:
                bytes_to_pad = (self.block_size >> 3) - len(block)
                if bytes_to_pad == 0: bytes_to_pad += (self.block_size >> 3)

                pad_byte = chr(bytes_to_pad).encode() if isinstance(block, bytes) else chr(bytes_to_pad)
                pad_block = (pad_byte * bytes_to_pad)

                if bytes_to_pad == (self.block_size >> 3):
                    yield block
                    yield pad_block
                else:
                    yield block + pad_block
                break

            else:
                yield block
                block = next_block

    def unpad(self, plaintext: "typing.Iterable[str | bytes]"):
        """ Unpads padded bytes from the plaintext to restore the original data.

        Args:
            plaintext (Iterable[str | bytes]): The padded plaintext.

        Yields:
            str | bytes: The plaintext without padding bytes.
        """
        block = next(plaintext, None)
        while True:
            next_block = next(plaintext, None)

            if next_block is None:
                pad_byte = block[-1]
                if pad_byte < (self.block_size >> 3):
                    yield block[:-pad_byte]
                break

            else:
                yield block
                block = next_block

