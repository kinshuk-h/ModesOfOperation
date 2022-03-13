"""

    core
    ~~~~

    This module defines abstract notions of ciphers for defining ciphers throughout the module.

    - Classes:
        - BlockCipher: An abstract class representing block ciphers.

    Author: Kinshuk Vasisht
    Dated : 10/03/2022

"""

import abc

class BlockCipher(abc.ABC):
    """
    An abstract class representing block ciphers.

    Block ciphers expose an encrypt and decrypt function,
    along with the block size utilized by the cipher.
    """

    def __init__(self) -> None:
            super().__init__()

    @property
    @abc.abstractmethod
    def BLOCK_SIZE():
        pass

    @abc.abstractmethod
    def encrypt(self, plaintext: "int | str | bytes | list | tuple"):
        pass

    @abc.abstractmethod
    def decrypt(self, ciphertext: "int | str | bytes | list | tuple"):
        pass
