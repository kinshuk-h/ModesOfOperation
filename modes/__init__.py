"""

    modes
    ~~~~~

    This module provides implementation of various modes of operations used with block ciphers to
    encrypt multiple blocks of data.

    - Sub-Modules:
        - cbc: Cipher-Block Chaining mode of operation.
        - cfb: Cipher Feedback mode of operation.
        - ctr: Counter mode of operation.
        - ecb: Electronic Codebook mode of operation.
        - ofb: Output Feedback mode of operation.
        - utils: Common utilities.
        - padding: Common padding strategies.

    Author: Kinshuk Vasisht
    Dated : 12/03/2022

"""

from .core import ModeOfOperation
from .ecb import ElectronicCodeBookMode
from .cbc import CipherBlockChainingMode
from .cfb import CipherFeedBackMode
from .ofb import OutputFeedBackMode
from .ctr import CounterMode

from . import core, utils, padding

__version__ = "1.0"
__all__     = [
    "ModeOfOperation",
    "ElectronicCodeBookMode" ,
    "CipherBlockChainingMode",
    "CipherFeedBackMode"     ,
    "OutputFeedBackMode"     ,
    "CounterMode"            ,
    "core"                   ,
    "utils"                  ,
    "padding"
]