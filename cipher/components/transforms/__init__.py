"""

    transforms
    ~~~~~~~~~~

    This module provides transformation components as ciphers.
    Common transformations such as swapping of halves and XOR-ing
    with a key are provided, alongside complex transformations
    which combine effects of ciphers.

    - Sub-Modules:
        - common: Common transformations: Swapper, XorKey
        - pipeline: Pipelining and combining transformations: Pipeline, HorizontalPipeline

    Author: Kinshuk Vasisht
    Dated : 10/03/2022

"""

from . import common, pipeline

__version__ = "1.0"
__all__     = [ 'common', 'pipeline' ]