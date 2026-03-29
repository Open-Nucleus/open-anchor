// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
export var IOTA_BECH32_HRP = 'iota';
export var IOTA_TESTNET_BECH32_HRP = 'atoi';
export var SHIMMER_BECH32_HRP = 'smr';
export var SHIMMER_TESTNET_BECH32_HRP = 'rms';
/** BIP44 Coin Types for IOTA and Shimmer. */
export var CoinType;
(function (CoinType) {
    /** The IOTA coin. */
    CoinType[CoinType["IOTA"] = 4218] = "IOTA";
    /** The Shimmer coin. */
    CoinType[CoinType["Shimmer"] = 4219] = "Shimmer";
    /** The Ether coin. */
    CoinType[CoinType["Ether"] = 60] = "Ether";
})(CoinType || (CoinType = {}));
//# sourceMappingURL=constants.js.map