// Copyright 2021-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
import { Type } from 'class-transformer';
import { Address, AddressDiscriminator } from '../block/address';
import { Output, OutputDiscriminator } from '../block/output/output';
import { TransactionEssence, TransactionEssenceDiscriminator, } from '../block/payload/transaction/essence';
/**
 * Helper struct for offline signing.
 */
var PreparedTransactionData = /** @class */ (function () {
    function PreparedTransactionData() {
    }
    __decorate([
        Type(function () { return TransactionEssence; }, {
            discriminator: TransactionEssenceDiscriminator
        })
    ], PreparedTransactionData.prototype, "essence");
    return PreparedTransactionData;
}());
export { PreparedTransactionData };
/**
 * Data for transaction inputs for signing and ordering of unlock blocks.
 */
var InputSigningData = /** @class */ (function () {
    function InputSigningData() {
    }
    __decorate([
        Type(function () { return Output; }, {
            discriminator: OutputDiscriminator
        })
    ], InputSigningData.prototype, "output");
    return InputSigningData;
}());
export { InputSigningData };
/**
 * Data for a remainder output, used for Ledger Nano.
 */
var Remainder = /** @class */ (function () {
    function Remainder() {
    }
    __decorate([
        Type(function () { return Output; }, {
            discriminator: OutputDiscriminator
        })
    ], Remainder.prototype, "output");
    __decorate([
        Type(function () { return Address; }, {
            discriminator: AddressDiscriminator
        })
    ], Remainder.prototype, "address");
    return Remainder;
}());
export { Remainder };
//# sourceMappingURL=prepared-transaction-data.js.map