"""
    zeros
    ~~~~~

    This module defines the PadZeros padding strategy,
    where the last block is completed by padding zeros.

    Author: Kinshuk Vasisht
    Dated : 12/03/2022

"""

import typing

from ..core import PaddingStrategy

class PadZeros(PaddingStrategy):
    """
        Zero-Padding strategy, where the plaintext is padded with zeros until it may be
            divided into an integral number of segments of block_size bits each.

        This strategy may produce ambiguities, in cases where the original data itself ends with zeros.
        So this strategy is best suited for character data.
    """

    def __init__(self):
        super().__init__()

    def pad(self, plaintext: "typing.Iterable[str | bytes]", debug = False):
        """ Pads the plaintext to complete the length of the last block.

        Args:
            plaintext (Iterable[str | bytes]): The plaintext to pad.
            debug (bool, optional): If true, outputs extra data to view the steps of the procedure.

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
                zero_byte = b'\0' if isinstance(block, bytes) else '\0'
                zeros_to_pad = (self.block_size >> 3) - len(block)
                if zeros_to_pad == 0: zeros_to_pad += (self.block_size >> 3)
                pad_block = (zero_byte * zeros_to_pad)

                if zeros_to_pad == (self.block_size >> 3):
                    if debug:
                        yield { 'original': block, 'padded': block }
                        yield { 'original': pad_block[0:0], 'padded': pad_block }
                    else:
                        yield block
                        yield pad_block
                else:
                    if debug: yield { 'original': block, 'padded': block + pad_block }
                    else: yield block + pad_block
                break

            else:
                if debug: yield { 'original': block, 'padded': block }
                else: yield block
                block = next_block

    def unpad(self, plaintext: "typing.Iterable[str | bytes]", debug = False):
        """ Unpads padded bytes from the plaintext to restore the original data.

        Args:
            plaintext (Iterable[str | bytes]): The padded plaintext.
            debug (bool, optional): If true, outputs extra data to view the steps of the procedure.

        Yields:
            str | bytes: The plaintext without padding bytes.
        """

        block = next(plaintext, None)
        while True:
            next_block = next(plaintext, None)

            if next_block is None:
                if debug:
                    zero_byte = b'\0' if isinstance(block['decrypted'], bytes) else '\0'
                    block['unpadded'] = block['decrypted'].rstrip(zero_byte)
                else:
                    zero_byte = b'\0' if isinstance(block, bytes) else '\0'
                    yield block.rstrip(zero_byte)
                break

            else:
                if debug:
                    block['unpadded'] = block['decrypted']
                    yield block
                else: yield block
                block = next_block