// Copyright 2021-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
/**
 * PreparedTransaction` is a class that represents prepared transaction data, which
 * is useful for offline signing. It contains the prepared transaction data and an
 * `Account` object. It provides methods to retrieve the prepared transaction data, sign
 * the transaction and sign+submit/send the transaction.
 */
var PreparedTransaction = /** @class */ (function () {
    /**
     * @param preparedData Prepared data to sign and submit a transaction.
     * @param account A wallet account.
     */
    function PreparedTransaction(preparedData, account) {
        this._preparedData = preparedData;
        this._account = account;
    }
    /**
     * The function returns the prepared transaction data.
     *
     * Returns:
     *
     * The method `preparedTransactionData()` is returning an object of type
     * `PreparedTransactionData`.
     */
    PreparedTransaction.prototype.preparedTransactionData = function () {
        return this._preparedData;
    };
    /**
     * The `send` function returns a promise that resolves to a `Transaction` object after signing
     * and submitting the transaction. Internally just calls `signAndSubmitTransaction`.
     *
     * Returns:
     *
     * The `send()` method is returning a `Promise` that resolves to a `Transaction` object after it
     * has been signed and submitted.
     */
    PreparedTransaction.prototype.send = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.signAndSubmitTransaction()];
            });
        });
    };
    /**
     * This function signs a prepared transaction essence using the account's private key and returns
     * the signed transaction essence.
     *
     * Returns:
     *
     * A `Promise` that resolves to a `SignedTransactionEssence` object.
     */
    PreparedTransaction.prototype.sign = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this._account.signTransactionEssence(this.preparedTransactionData())];
            });
        });
    };
    /**
     * This function signs and submits a transaction using prepared transaction data.
     *
     * Returns:
     *
     * A Promise that resolves to a Transaction object.
     */
    PreparedTransaction.prototype.signAndSubmitTransaction = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this._account.signAndSubmitTransaction(this.preparedTransactionData())];
            });
        });
    };
    return PreparedTransaction;
}());
export { PreparedTransaction };
//# sourceMappingURL=prepared-transaction.js.map