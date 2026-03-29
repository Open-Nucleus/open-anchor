// Copyright 2021-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
import { Type } from 'class-transformer';
import { TransactionPayload } from '../block/payload/transaction';
import { InputSigningData } from '../client';
/** The signed transaction with inputs data */
var SignedTransactionEssence = /** @class */ (function () {
    function SignedTransactionEssence() {
    }
    __decorate([
        Type(function () { return TransactionPayload; })
    ], SignedTransactionEssence.prototype, "transactionPayload");
    __decorate([
        Type(function () { return InputSigningData; })
    ], SignedTransactionEssence.prototype, "inputsData");
    return SignedTransactionEssence;
}());
export { SignedTransactionEssence };
//# sourceMappingURL=signed-transaction-essence.js.map