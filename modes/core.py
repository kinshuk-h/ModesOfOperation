"""

    core
    ~~~~

    This module provides core components such as abstract classes for use in the modes module.

    - Classes:
        - ModeOfOperation: Abstract Class for a block cipher mode of operation.
        - PaddingStrategy: Abstract Class for a padding strategy to use within a mode of operation.

    Author: Kinshuk Vasisht
    Dated : 12/03/2022
"""

import abc

class PaddingStrategy(abc.ABC):
    """
        Provides an abstract class for defining padding strategies.

        A padding strategy specifies how a plaintext which cannot be divided into an
            integral number of blocks must be padded.

        Such a strategy produces a reversible change, i.e., a padded plaintext can be
            unambiguously unpadded to obtain the original plaintext.
    """
    def __init__(self):
        super().__init__()
        self._block_size = None

    @property
    def block_size(self) -> "int | None":
        """ The block size to consider during padding. """
        return self._block_size

    @block_size.setter
    def block_size(self, size : "int"):
        """ Sets the block size for the padding operations. """
        self._block_size = size

    @abc.abstractmethod
    def pad(self, plaintext: "str | bytes"):
        pass

    @abc.abstractmethod
    def unpad(self, plaintext: "str | bytes"):
        pass

class ModeOfOperation(abc.ABC):
    """
        An abstract class representing a mode of operation.

        Modes of operation allow encryption and decryption of multiple blocks using an arbitrary block cipher
            which can work only with a fixed input size. Some modes even allow use of block ciphers as stream ciphers.

        Modes are initialized with the cipher to use, and an initial vector (IV) or nonce value
            to use for feedback purposes to initiate the encryption and decryption.
    """

    def __init__(self, cipher, padding_mode, block_size = None) -> None:
        super().__init__()
        self.cipher = cipher
        self.padding_mode = padding_mode
        self.block_size = block_size or cipher.BLOCK_SIZE
        self.padding_mode.block_size = self.block_size

    @abc.abstractmethod
    def encrypt(self, plaintext: "int | str | bytes | list | tuple"):
        pass

    @abc.abstractmethod
    def decrypt(self, ciphertext: "int | str | bytes | list | tuple"):
        pass
