"""

    pipeline
    ~~~~~~~~

    This module defines pipeline and combining transformations,
    which combine multiple ciphers together to form a complex cipher.
    The encryption and decryption algorithms are pipelined to produce
    the overall encryption and decryption effect.

    - Classes
        - Pipeline: Creates a pipeline which combines ciphers in a vertical fashion, where the ciphertext of one
          cipher is the plaintext for the next.
        - HorizontalPipeline: Creates a pipeline which combines ciphers in a horizontal fashion, where separate
          ciphers are applied over same sized chunks from the original plaintext and the results are combined.

    Author: Kinshuk Vasisht
    Dated : 11/03/2022

"""

import enum

from ... import utils

class Order(enum.Enum):
   """ Order of decryption to follow in the pipeline. """
   # Natural order: For ciphers C1 and C2 decryption is done using C2 then C1
   NATURAL = 1
   # Original order: For ciphers C1 and C2 decryption is done using C1 then C2
   ORIGINAL = 2

class Pipeline:
    """
        Defines a pipeline transformation for ciphers.

        Given a set of cipher objects, this transformation creates a new cipher
        whose encryption and decryption operations is equivalent to the respective
        encryption and decryption operations of the given ciphers in sequence.

        Example usage:
        >>> from cipher.components.transforms import Pipeline
        >>> from cipher.des import DES
        ...
        >>> des_1 = DES(key = "<some key K1>")
        >>> des_2 = DES(key = "<some key K2>")
        >>> triple_des = Pipeline([ des_1, des_2, des_1 ])
        ...
        >>> p = "<some 64-bit plaintext>"
        # Equivalent to des_1.encrypt(des_2.encrypt(des_1.encrypt(p)))
        >>> triple_des.encrypt(p)
    """
    def __init__(self, ciphers, order = Order.NATURAL):
        """ Creates a new Pipeline cipher instance.

        Args:
            ciphers (list): List of ciphers or cipher components to pipeline.
            order (Order, optional): The order of cipher execution to follow during decryption.
                Defaults to Order.NATURAL.
        """
        self.ciphers = ciphers
        self.process_order = order

    def encrypt(self, plaintext: "int | str | bytes | list | tuple"):
        """ Encrypts a given plaintext using the pipelined ciphers.

        Args:
            plaintext (int | str | bytes | list | tuple): The plaintext to encrypt.

        Returns:
            int | list | bytes: The encrypted ciphertext after the last stage of the pipeline.
        """
        ciphertext = plaintext
        for cipher in self.ciphers:
            ciphertext = cipher.encrypt(ciphertext)
        return ciphertext

    def decrypt(self, ciphertext: "int | str | bytes | list | tuple"):
        """ Decrypts a given ciphertext using the pipelined ciphers used to encrypt.

        Args:
            ciphertext (int | str | bytes | list | tuple): The ciphertext to decrypt.

        Returns:
            int | bytes | list: The decrypted plaintext after the last stage of the pipeline.
        """
        plaintext = ciphertext
        if self.process_order == Order.ORIGINAL:
            for cipher in self.ciphers:
                plaintext = cipher.decrypt(plaintext)
        else:
            for cipher in self.ciphers[::-1]:
                plaintext = cipher.decrypt(plaintext)
        return plaintext

class HorizontalPipeline:
    """
        Defines a horizontal pipeline transformation for ciphers.

        Given a set of cipher objects, this transformation creates a new cipher
        whose encryption and decryption operations is equivalent to the respective
        encryption and decryption operations of the given ciphers over equal-sized
        sub-blocks of the data object.

        Example Usage:
        >>> from cipher.components.transforms import HorizontalPipeline
        >>> from cipher.components.substitution import SBox
        ...
        >>> s = [ SBox(...), SBox(...), SBox(...), SBox(...) ]
        ...
        >>> combined_s = HorizontalPipeline(s)
        >>> p = "<some 64-bit plaintext>"
        # Equivalent to:
        #   s[0].encrypt(p[0:16]) + s[1].encrypt(p[16:32]) +
        #   s[1].encrypt(p[32:48]) + s[3].encrypt(p[48:64])
        >>> combined_s.encrypt(p)
    """

    def __init__(self, ciphers, input_size, output_size = None):
        """ Creates a new HorizontalPipeline instance.

        Args:
            ciphers (list): List of ciphers or cipher components to pipeline.
            input_size (int): The input size of the plaintext, in bits. Helps determine size per segment.
            output_size (int, optional): The output size of the ciphertext. Defaults to None.
        """
        self.ciphers = ciphers
        self.input_size  = input_size
        self.output_size = output_size or input_size
        self.input_chunk_size  = input_size // len(ciphers)
        self.output_chunk_size = self.output_size // len(ciphers)

    def encrypt(self, plaintext: "int | str | bytes | list | tuple"):
        """ Encrypts a given plaintext using the pipelined ciphers.

        Args:
            plaintext (int | str | bytes | list | tuple): The plaintext to encrypt.

        Returns:
            int | bytes | list: The encrypted ciphertext after passing segments to ciphers in the pipeline.
        """
        plaintext_size = utils.input_size(plaintext)
        if plaintext_size != self.input_size:
            raise ValueError(
                self.__class__.__name__ + f": size of plaintext ({plaintext_size}) " +
                f"does not match what was expected ({self.input_size})"
            )

        chunks = utils.n_ary_split(plaintext, self.input_chunk_size, self.input_size)
        chunks = [ cipher.encrypt(chunk) for cipher, chunk in zip(self.ciphers, chunks) ]
        return utils.n_ary_join(chunks, self.output_chunk_size, self.output_size)

    def decrypt(self, ciphertext: "int | str | bytes | list | tuple"):
        """ Decrypts a given ciphertext using the pipelined ciphers used to encrypt.

        Args:
            ciphertext (int | str | bytes | list | tuple): The ciphertext to decrypt.

        Returns:
            int | bytes | list: The decrypted plaintext after passing segments to ciphers in the pipeline.
        """
        ciphertext_size = utils.input_size(ciphertext)
        if ciphertext_size != self.output_size:
            raise ValueError(
                self.__class__.__name__ + f": size of ciphertext ({ciphertext_size}) " +
                f"does not match what was expected ({self.output_size})"
            )

        chunks = utils.n_ary_split(ciphertext, self.output_chunk_size, self.output_size)
        chunks = [ cipher.decrypt(chunk) for cipher, chunk in zip(self.ciphers, chunks) ]
        return utils.n_ary_join(chunks, self.input_chunk_size, self.input_size)