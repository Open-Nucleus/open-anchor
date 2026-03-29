// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
/**
 * All of the block payload types.
 */
var PayloadType;
(function (PayloadType) {
    /** A milestone payload. */
    PayloadType[PayloadType["Milestone"] = 7] = "Milestone";
    /** A tagged data payload. */
    PayloadType[PayloadType["TaggedData"] = 5] = "TaggedData";
    /** A transaction payload. */
    PayloadType[PayloadType["Transaction"] = 6] = "Transaction";
    /** A treasury transaction payload. */
    PayloadType[PayloadType["TreasuryTransaction"] = 4] = "TreasuryTransaction";
})(PayloadType || (PayloadType = {}));
/**
 * The base class for block payloads.
 */
var Payload = /** @class */ (function () {
    /**
     * @param type The type of payload.
     */
    function Payload(type) {
        this.type = type;
    }
    /**
     * Get the type of payload.
     */
    Payload.prototype.getType = function () {
        return this.type;
    };
    return Payload;
}());
export { PayloadType, Payload };
//# sourceMappingURL=payload.js.map