// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
/** Convert UTF8 string to an array of bytes */
export var utf8ToBytes = function (utf8) {
    var utf8Encode = new TextEncoder();
    return Array.from(utf8Encode.encode(utf8));
};
/** Convert hex encoded string to UTF8 string */
export var hexToUtf8 = function (hex) {
    return decodeURIComponent(hex.replace(/^0x/, '').replace(/[0-9a-f]{2}/g, '%$&'));
};
/** Convert UTF8 string to hex encoded string */
export var utf8ToHex = function (utf8) {
    return '0x' + Buffer.from(utf8, 'utf8').toString('hex');
};
//# sourceMappingURL=utf8.js.map