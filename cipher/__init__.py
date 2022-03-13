"""

    cipher
    ~~~~~~

    This module provides implementations of block ciphers and various simple cipher components.

    - Sub-Modules:
        - core: Abstract classes for defining ciphers.
        - des: Implementation of the DES block cipher.
        - components: Common cipher components: S-Boxes, P-Boxes, One-Time Pads, etc.
        - utils: Common utilities for use in cipher components.

    Author: Kinshuk Vasisht
    Dated : 11/03/2022

"""

from . import components, core, des, utils

__version__ = "1.0"
__all__     = [ 'components', 'core', 'des', 'utils' ]