"""

    utils
    ~~~~~

    This module provide common utility functions for use throughout the cipher module.

    - Functions:
        - input_size: Returns the size of a data object in bits
        - binary_split: Splits the data object into left and right halves.
        - binary_join: Combnes two halves into a single data object.
        - n_ary_split: Splits the data object into multiple segments.
        - n_ary_join: Combines multiple data object segments into a single data object.
        - circular_shift_left: Performs a circular shift left of bits in a data object.

    Author: Kinshuk Vasisht
    Dated : 09/03/2022

"""

def input_size(data: "int | str | bytes | list | tuple"):
    """ Returns the input size of the given data in bits.

    Args:
        data (str | bytes | list | tuple): A data object which may be a
        string, bytes, or a list/tuple of binary elements.

    Returns:
        int: Length of the data object, in bits
    """
    if isinstance(data, int): return len(hex(data)[2:]) << 2
    if isinstance(data, (str, bytes)): return len(data) << 3
    else: return len(data)

def binary_split(data: "str | bytes | list | tuple"):
    """ Splits a given data object into two left and right halves.

    Args:
        data (str | bytes | list | tuple): A data object which may be a
        string, bytes, or a list/tuple of binary elements.

    Returns:
        tuple[bytes|list]: Left and right halves of the data object.
    """

    data_half_size = input_size(data) >> 1

    if isinstance(data, (str, bytes)):
        if isinstance(data, str): data = data.encode()

        data_bits  = int.from_bytes(data, byteorder='big', signed=False)
        data_left  = data_bits >> data_half_size
        data_right = data_bits & ((1 << data_half_size) - 1)

        byte_count = data_half_size >> 3
        if (byte_count << 3) < data_half_size: byte_count += 1

        data_left  = data_left .to_bytes(byte_count, byteorder='big', signed = False)
        data_right = data_right.to_bytes(byte_count, byteorder='big', signed = False)
        return data_left, data_right

    else:
        return data[:data_half_size], data[data_half_size:]

def binary_join (chunk_1: "str | bytes | list | tuple", chunk_2: "str | bytes | list | tuple", length = None):
    if isinstance(chunk_1, (str, bytes)):
        chunk_size = input_size(chunk_1)
        if length is None: length = chunk_size
        joined_bits = int.from_bytes(chunk_1, byteorder='big')
        joined_bits <<= length
        joined_bits |= int.from_bytes(chunk_2, byteorder='big')
        return joined_bits.to_bytes(length >> 2, byteorder='big')
    else:
        return chunk_1 + chunk_2

def n_ary_split(data: "int | str | bytes | list | tuple", chunk_size: int, data_size: "int | None" = None):
    """ Splits a given data object into multiple data object chunks of a fixed size.

    Args:
        data (int | str | bytes | list | tuple): Data object to split.
        chunk_size (int): The size of each target data chunk, in bits. Useful for chunks with sub-byte sizes.
        data_size (int | None, optional): The sum of sizes of the chunks. Must be specified in
            case of integral chunks. Defaults to None.

    Returns:
        list[int | bytes | list]: The result of splitting of the data object.
    """
    data_size = data_size or input_size(data)

    if isinstance(data, (str, bytes, int)):
        if isinstance(data, str): data = data.encode()

        as_bytes = isinstance(data, bytes)
        if as_bytes: data = int.from_bytes(data, byteorder='big', signed=False)

        chunks = []
        for i in range(data_size // chunk_size):
            chunks.append(data & ((1 << chunk_size) - 1))
            data >>= chunk_size
        chunks = chunks[::-1]

        if as_bytes:
            byte_count = chunk_size >> 3
            if (byte_count << 3) < chunk_size: byte_count += 1
            chunks = [
                chunk.to_bytes(byte_count, byteorder='big', signed=False)
                for chunk in chunks
            ]

    else:
        chunks = [
            data[ index : index + chunk_size ]
            for index in range(0, data_size, chunk_size)
        ]

    return chunks

def n_ary_join (chunks: "list[int | str | bytes | list | tuple]", chunk_size: int, data_size: "int | None" = None):
    """ Returns the concatentation of multiple data object blocks as a single block.

    Args:
        chunks (list[int | str | bytes | list | tuple]): List of data objects to join.
        chunk_size (int): The size of each data chunk, in bits. Useful for chunks with sub-byte sizes.
        data_size (int | None, optional): The sum of sizes of the chunks. Must be specified in
            case of integral chunks. Defaults to None.

    Returns:
        int | bytes | list: The result of concatenation of the individual data objects.
    """
    if isinstance(chunks[0], (str, bytes, int)):
        if isinstance(chunks[0], str):
            chunks = [ chunk.encode() for chunk in chunks ]

        as_bytes = isinstance(chunks[0], bytes)
        if as_bytes:
            chunks = [
                int.from_bytes(chunk, byteorder='big', signed=False)
                for chunk in chunks
            ]

        data = 0
        for chunk in chunks:
            data <<= chunk_size; data |= chunk

        if as_bytes:
            data_size = data_size or input_size(data)
            data = data.to_bytes(data_size >> 3, byteorder='big', signed=False)

    else:
        data = sum(chunks, [])

    return data

def circular_shift_left(data: "str | bytes | list | tuple", positions: int, length = None):
    """ Returns the circular left shift variant of a given data object.

    Args:
        data (str | bytes | list | tuple): A data object which may be a
        string, bytes, or a list/tuple of binary elements.
        positions (int): The number of positions to shift.
        length (int|None): The bit length of the string to consider.
        Defaults to 8 times the byte length.

    Returns:
        bytes | list: The object post circular shift.
    """
    data_size = input_size(data)
    if length is None: length = data_size
    positions %= length

    if isinstance(data, (str, bytes)):
        if isinstance(data, str): data = data.encode()
        data_bits     = int.from_bytes(data, byteorder='big', signed=False)
        shift_mask    = ((1 << positions) - 1) << (length - positions)
        bits_to_shift = (data_bits & shift_mask) >> (length - positions)
        data_bits     = ((data_bits & ~shift_mask) << positions) | bits_to_shift
        return data_bits.to_bytes(data_size >> 3, byteorder='big', signed=False)

    else:
        return data[positions:] + data[:positions]
