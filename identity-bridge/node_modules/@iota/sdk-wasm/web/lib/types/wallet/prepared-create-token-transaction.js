// Copyright 2021-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
import { PreparedTransaction } from './prepared-transaction';
/*
 * The class PreparedCreateNativeTokenTransaction represents prepared data for issuing a transaction to create a native token.
 */
var PreparedCreateNativeTokenTransaction = /** @class */ (function (_super) {
    __extends(PreparedCreateNativeTokenTransaction, _super);
    /**
     * @param preparedData Prepared data to create a Native Token.
     * @param account A wallet account.
     */
    function PreparedCreateNativeTokenTransaction(preparedData, account) {
        var _this = _super.call(this, preparedData.transaction, account) || this;
        _this._tokenId = preparedData.tokenId;
        return _this;
    }
    /**
     * The function returns the tokenId as a string.
     *
     * Returns:
     *
     * The token id of the CreateNativeTokenTransaction.
     */
    PreparedCreateNativeTokenTransaction.prototype.tokenId = function () {
        return this._tokenId;
    };
    return PreparedCreateNativeTokenTransaction;
}(PreparedTransaction));
export { PreparedCreateNativeTokenTransaction };
//# sourceMappingURL=prepared-create-token-transaction.js.map