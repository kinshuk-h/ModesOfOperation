"""

    permutation
    ~~~~~~~~~~~

    This module provides classes for permutation boxes, which can perform general
    invertible or non-invertible mono-substitution of bits in a given input.

    - Sub-modules:
        - straight: Invertible permutation boxes (StraightPBox, etc.)
        - resize: Permutation boxes with a resizing effect (ExpansionPBox, CompressionPBox, etc.)

    Author: Kinshuk Vasisht
    Dated : 09/03/2022

"""

from . import resize, straight

__version__ = "1.0"
__all__     = [ 'straight', 'resize' ]