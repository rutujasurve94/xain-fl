from typing import Tuple

from absl import flags

from ..types import FederatedDataset
from . import storage

FLAGS = flags.FLAGS

DATASET_NAME = "fashion_mnist_10s_500_1k_bias"
DATASET_SPLIT_HASHES = {
    "00": [
        "55650bb943986a61135370032cfc82bd8fa0f4b5",
        "ad9b6d293a27a7e8e33dbc0cb52787b3a97c1198",
    ],
    "01": [
        "27980b92a8e37becbd2a3b2d08cc4d7d210097a6",
        "bf6d70d5d05c172ce8c0c7ddb7f5eadd7064e3d1",
    ],
    "02": [
        "3805527efc8100716b2d39c4abf154e75111286d",
        "823f9e3f42e688dd1ec50853210630961bba9499",
    ],
    "03": [
        "421621175e317f789e99d9c47e30ac4f34af64dc",
        "4eac815979f594a0c85b68e451cd62b1309c3a4f",
    ],
    "04": [
        "54d5836edfc5aa3b68836654fdd9ae03d38f1f44",
        "40f727b85eb3f0650f7c1fce79e02a29f5b60f49",
    ],
    "05": [
        "d7eda3da9caeddd746397eba5de92b584f742cf3",
        "d931f8ab70bd49ea6f034e49c5a52cef07e27b4c",
    ],
    "06": [
        "61d13efc85949a5f15dde3258058c6ab3100d409",
        "53cb87265210f900466b2f15fff8a2c284547e06",
    ],
    "07": [
        "42d169567d440e0209c735f840b0fd3d94fa908d",
        "ba333b5c1cdce996de6189ba3ed852ab24f567c1",
    ],
    "08": [
        "bf3b3e81c68693a632ed942343940c3e255dcb84",
        "d8ee333cbe4e57339fe969a3f5ca03b3c381b1e6",
    ],
    "09": [
        "6903140a40b36dd56f9dcbfd7fafd7fba1183d28",
        "3edb87459c11396db2ccdff8b949accd71aff44a",
    ],
    "test": [
        "79e6584f3574e22e97dfe17ddf1b9856b3f2284f",
        "b056ffe622e9a6cfb76862c5ecb120c73d4fd99e",
    ],
    "val": [
        "c008c5dcaf03d23962756f92e6cd09a902f20f8b",
        "e67663f832358b645232f0d448d84e4d6e8c65cd",
    ],
}


def load_splits(
    get_local_datasets_dir=storage.default_get_local_datasets_dir
) -> FederatedDataset:
    return storage.load_splits(
        dataset_name=DATASET_NAME,
        dataset_split_hashes=DATASET_SPLIT_HASHES,
        get_local_datasets_dir=get_local_datasets_dir,
    )


def load_split(
    split_id: str,
    split_hashes: Tuple[str, str],
    get_local_datasets_dir=storage.default_get_local_datasets_dir,
):
    assert split_id in set(DATASET_SPLIT_HASHES.keys())

    x_i, y_i = storage.load_split(
        dataset_name=DATASET_NAME,
        split_id=split_id,
        split_hashes=split_hashes,
        local_datasets_dir=get_local_datasets_dir(),
    )

    return x_i, y_i