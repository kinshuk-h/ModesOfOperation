"""

    padding
    ~~~~~~~

    This module provides implementation of common padding strategies.

    - Sub-Modules
        - zeros: provides the PadZeros padding strategy to pad 0s at the end of the data.
        - pkcs7: provides the PadPKCS7 padding strategy to pad data as per the PKCS7 specification.

    - Classes
        - PaddingMode: Enumeration for choosing among padding strategies.

    Author: Kinshuk Vasisht
    Dated : 12/03/2022

"""

import enum

from ..core import PaddingStrategy
from . import zeros, pkcs

class PadNone(PaddingStrategy):
    """ A no-op padding strategy, for use in stream ciphers,
        where padding is not required as such. """

    def pad(self, plaintext, debug = False):
        if debug:
            def plaintext_yielder():
                for block in plaintext:
                    yield { 'padded': block, 'original': block }
            return plaintext_yielder()
        else: return plaintext

    def unpad(self, plaintext, debug = False):
        if debug:
            def plaintext_yielder():
                for block in plaintext:
                    block['unpadded'] = block['decrypted']
                    yield block
            return plaintext_yielder()
        else: return plaintext

class PaddingMode(enum.Enum):
    """ An enumeration of common padding strategies. """
    PAD_NONE  = PadNone()
    PAD_ZEROS = zeros.PadZeros()
    PAD_PKCS7 = pkcs.PadPKCS7()

    @property
    def block_size(self):
        return self.value.block_size
    @block_size.setter
    def block_size(self, size):
        self.value.block_size = size

    def pad(self, plaintext, debug=False):
        return self.value.pad(plaintext, debug)
    def unpad(self, plaintext, debug=False):
        return self.value.unpad(plaintext, debug)

__version__ = "1.0"
__all__     = [ 'zeros', 'pkcs', 'PaddingMode' ]