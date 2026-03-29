// Copyright 2021-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
/** Return strategy for the storage deposit. */
export var ReturnStrategy;
(function (ReturnStrategy) {
    /** A storage deposit return unlock condition will be added with the required minimum storage deposit. */
    ReturnStrategy["Return"] = "Return";
    /** The recipient address will get the additional amount to reach the minimum storage deposit gifted. */
    ReturnStrategy["Gift"] = "Gift";
})(ReturnStrategy || (ReturnStrategy = {}));
//# sourceMappingURL=output-params.js.map