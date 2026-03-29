// Copyright 2021-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
import { Type } from 'class-transformer';
import { Transaction } from './transaction';
import { PreparedTransactionData } from '../client/prepared-transaction-data';
/** The result of preparing an operation to create a native token. */
var PreparedCreateNativeTokenTransactionData = /** @class */ (function () {
    function PreparedCreateNativeTokenTransactionData() {
    }
    __decorate([
        Type(function () { return PreparedTransactionData; })
    ], PreparedCreateNativeTokenTransactionData.prototype, "transaction");
    return PreparedCreateNativeTokenTransactionData;
}());
export { PreparedCreateNativeTokenTransactionData };
/** The result of an operation to create a native token. */
var CreateNativeTokenTransaction = /** @class */ (function () {
    function CreateNativeTokenTransaction() {
    }
    __decorate([
        Type(function () { return Transaction; })
    ], CreateNativeTokenTransaction.prototype, "transaction");
    return CreateNativeTokenTransaction;
}());
export { CreateNativeTokenTransaction };
//# sourceMappingURL=prepared-create-token-transaction-data.js.map