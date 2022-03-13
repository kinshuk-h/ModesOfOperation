from modes import *
from cipher import des

def dump(data, label = "", sep = ' ', bits_per_sep = 8):
    if isinstance(data, int):
        strrep = bin(data)[2:]
    elif isinstance(data, bytes):
        print(label, ":", data.hex(sep, max(bits_per_sep >> 3, 1)))
        bits = int.from_bytes(data, byteorder='big', signed=False)
        strrep = bin(bits)[2:]
    else:
        strrep = ''.join([ str(i) for i in data ])

    if (len(strrep) / bits_per_sep) != (len(strrep) // bits_per_sep):
        strrep = strrep.zfill((1+(len(strrep) // bits_per_sep)) * bits_per_sep)
    print(label, ":", ' '.join(strrep[i:i+bits_per_sep] for i in range(0, len(strrep), bits_per_sep)))

if __name__ == "__main__":
    # base_key = bytes.fromhex("133457799BBCDFF1")
    # base_key = bytes.fromhex("5B5A57676A56676E")
    base_key = bytes.fromhex("5B5B57676B57676E")
    dump(base_key, "K", bits_per_sep=8); print()

    des_cipher = des.DES(base_key, False)

    # padding_mode = padding.zeros.PadZeros()
    # padding_mode = padding.pkcs7.PadPKCS7()
    # padding_mode = padding.PadNone()
    # cipher = ElectronicCodeBookMode(des_cipher, padding_mode = padding_mode)
    # cipher = CipherBlockChainingMode(des_cipher, padding_mode = padding_mode)
    # cipher = CipherFeedBackMode(des_cipher, padding_mode = padding_mode)
    # cipher = OutputFeedBackMode(des_cipher, padding_mode = padding_mode)
    cipher = CounterMode(des_cipher, IV = bytes.fromhex("e763759597c6dc5e"))

    plaintext  = b"hello there bois, this will be good I guess, amirite?"
    dump(plaintext, "P", bits_per_sep=32); print()

    ciphertext = bytearray()
    for block in cipher.encrypt(utils.block_generator(plaintext, cipher.block_size)):
        ciphertext += block
    dump(bytes(ciphertext), "C", bits_per_sep=32); print()

    # for block in padding_mode.pad(utils.block_generator(plaintext, cipher.block_size)):
    #     print(block.hex(sep = ' ', bytes_per_sep = 2))

    plaintext = bytearray()
    for block in cipher.decrypt(utils.block_generator(bytes(ciphertext), cipher.block_size)):
        plaintext += block
    dump(bytes(plaintext), "P", bits_per_sep=32); print()