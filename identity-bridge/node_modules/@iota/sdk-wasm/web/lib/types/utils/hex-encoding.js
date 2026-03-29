// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
/**
 * Converts `bigint` value to hexadecimal string representation prefixed with "0x".
 */
export function bigIntToHex(value) {
    return '0x' + value.toString(16);
}
/**
 * Converts hex encoded string to `bigint` value.
 */
export function hexToBigInt(value) {
    if (!value.startsWith('0x')) {
        value = '0x' + value;
    }
    return BigInt(value);
}
//# sourceMappingURL=hex-encoding.js.map