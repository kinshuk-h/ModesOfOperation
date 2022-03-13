# Modes of Operation
---

This project implements the common modes of operation used along with block ciphers
for general purpose encryption of arbitrary data.

## Requirements:

- The project does not have any dependency over any third-party library, however, third-party libraries providing  
implementation of ciphers can easily be combined with the modes of operations using simple wrapper classes.

- The minimum python version required is Python 3.6, due to the use of the `secrets` module for generating  
random cryptographic initialization vectors (IVs).

## Hierarchy:

The project defines the following modules in the following hierarchy:

```
────┬─── cipher
    │       ├─── components
    │       │       ├─── permutation
    │       │       │       ├─── resize.py
    │       │       │       └─── straight.py
    │       │       ├─── transforms
    │       │       │       ├─── common.py
    │       │       │       └─── pipeline.py
    │       │       └─── substitution.py
    │       ├─── core.py
    │       ├─── des.py
    │       └─── utils.py
    ├─── modes
    │       ├─── padding
    │       │       ├─── zeros.py
    │       │       └─── pkcs7.py
    │       ├─── cbc.py
    │       ├─── cfb.py
    │       ├─── core.py
    │       ├─── ctr.py
    │       ├─── ecb.py
    │       ├─── ofb.py
    │       └─── utils.py
    ├─── crypt.py
    ├─── demo.py
    └─── main.py
```

### `cipher`

Provides simple and complex ciphers, notably the DES block cipher which is
used for demonstration of the modes of operation.

- `components`: Provides components which may be used as building blocks for complex ciphers.  
        Each component is effectively a simple or complex cipher in itself, and may be used for
        encryption and decryption.
  - `permutation`: Provides classes for permutation boxes, which can perform general mono-substitution of bits in a given input.
    - `resize`: Provides permutation boxes with a resizing effect, where the size of the data object is altered.
    - `straight`: Provides an implementation of a straight P-Box, useful for generating permutations of a data object
  - `transforms`: Provides transformation components as ciphers.
    - `common`: Provides common ciphers which result in simple transformations, such as a One-Time pad cipher.
    - `pipeline`: Defines pipeline and combining transformations, which combine multiple ciphers together to form a complex cipher.
  - `substitution`: Provides component ciphers for substitution operations, such as S-Boxes.
- `core`: Defines abstract notions of ciphers for defining ciphers throughout the module.
- `des`: Provides an implementation of the DES block cipher, without the modes of operation.
- `utils`: Common utility functions for use throughout the `cipher` module

### `modes`

Module for modes of operation for block ciphers, where a cipher can be any
object offering an encrypt and decrypt method.

- `padding`: Provides implementation of common padding strategies.
    - `zeros`: Defines the `PadZeros` padding strategy, where the last block is completed by padding zeros.
    - `pkcs7`: Provides an implementation of the padding strategy used in the
                [*Public-Key Cryptography Standards #7*](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7) (PKCS#7 or PKCS7).
- `cbc`: Defines an implementation for the Cipher Block Chaining (CBC) block cipher mode of operation.
- `cfb`: Defines an implementation for the Cipher Feedback (CFB) block cipher mode of operation.
- `core`: Provides core components such as abstract classes for use in the `modes` module.
- `ctr`: Defines an implementation for the Counter (CTR) block cipher mode of operation.
- `ecb`: Deines an implementation for the Electronic Codebook (ECB) block cipher mode of operation.
- `ofb`: Defines an implementation for the Output Feedback (OFB) block cipher mode of operation.
- `utils`: Common utility functions for use throughout the `modes` module

## Usage:

The following files & tools are provided for testing and working with the modules:
- `demo.py`: Provides a demonstration of the working of the modes of operations, with simple visualizations
             of the step-by-step procedure.
- `main.py`: Provides a driver script to run the various modes of operation over input data.
- `crypt.py`: Command-line script to encrypt files and/or input data
              using various ciphers and modes of operations.

## License:

Copyright &copy; 2022, Kinshuk Vasisht

Licensed under the MIT License.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated  
documentation files (the "Software"), to deal in the Software without restriction, including without limitation  
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and  
to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE  
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR  
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR  
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## About:

Created by Kinshuk Vasisht,  
  Roll Number: 19  
  M.Sc. Computer Science

## Bibliography:

> - Cryptography & Network Security: Principles and Practice, Sixth Edition by William Stallings:
>   [Chapter 6 - Data Encryption Standard](https://academic.csuohio.edu/yuc/security/Chapter_06_Data_Encription_Standard.pdf)
> - https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm (for testing examples)
> - https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7 (for PKCS#7 padding strategy)
> - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
> - https://docs.python.org/3/library/secrets.html (for generating IVs and nonces)