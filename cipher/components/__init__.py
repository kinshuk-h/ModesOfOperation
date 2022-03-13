"""

    components
    ~~~~~~~~~~

    This module provides components which may be used as building blocks for complex ciphers.
    Each component is effectively a simple or complex cipher in itself, and may be used for
    encryption and decryption.

    - Sub-Modules:
        - permutation: Provides components for permutations.
        - substitution: Provides components for substitution.
        - transforms: Provides components for simple and combining transformations.

    Author: Kinshuk Vasisht
    Dated : 10/03/2022

"""

from . import permutation, transforms, substitution

__version__ = "1.0"
__all__     = [ 'permutation', 'substitution', 'transforms' ]