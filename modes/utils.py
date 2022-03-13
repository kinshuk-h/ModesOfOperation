"""

    utils
    ~~~~~

    This module provide common utility functions for use throughout the modes module.

    - Functions:
        - xor: Performs the XOR of two bytes objects.
        - block_generator: Creates a generator to iterate block-wise over the data.

    Author: Kinshuk Vasisht
    Dated : 12/03/2022

"""

def xor(block_a: "str | bytes", block_b: "str | bytes"):
    """ Computes the XOR of two bytes objects.

    Args:
        block_a (str | bytes): The first block of bytes
        block_b (str | bytes): The second block of bytes

    Returns:
        bytes: The result of block_a ^ block_b
    """
    if isinstance(block_a, str): block_a = block_a.encode()
    if isinstance(block_b, str): block_b = block_b.encode()

    result = bytearray(block_a)
    for index, byte in enumerate(block_b): result[index] ^= byte
    return bytes(result)

def block_generator(data: "str | bytes", block_size: int):
    """ Defines a generator over a data object to iterate it block-wise.

    Args:
        data (str | bytes): The data object to iterate over.
        block_size (int): The size of a block to yield.

    Yields:
        str | bytes: A block from the data.
    """
    byte_block_size = block_size >> 3

    for block in range(0, len(data), byte_block_size):
        yield data [ block : block + byte_block_size ]