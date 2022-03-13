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

    def pad(self, plaintext):
        return plaintext

    def unpad(self, plaintext):
        return plaintext

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

    def pad(self, plaintext):
        return self.value.pad(plaintext)
    def unpad(self, plaintext):
        return self.value.unpad(plaintext)

__version__ = "1.0"
__all__     = [ 'zeros', 'pkcs', 'PaddingMode' ]