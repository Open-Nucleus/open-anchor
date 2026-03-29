// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
import { Type } from 'class-transformer';
import { Address, AddressDiscriminator } from '../block/address';
import { Output, OutputDiscriminator } from '../block/output';
/** Output to claim */
export var OutputsToClaim;
(function (OutputsToClaim) {
    OutputsToClaim["MicroTransactions"] = "MicroTransactions";
    OutputsToClaim["NativeTokens"] = "NativeTokens";
    OutputsToClaim["Nfts"] = "Nfts";
    OutputsToClaim["Amount"] = "Amount";
    OutputsToClaim["All"] = "All";
})(OutputsToClaim || (OutputsToClaim = {}));
/** An output with metadata */
var OutputData = /** @class */ (function () {
    function OutputData() {
    }
    __decorate([
        Type(function () { return Output; }, {
            discriminator: OutputDiscriminator
        })
    ], OutputData.prototype, "output");
    __decorate([
        Type(function () { return Address; }, {
            discriminator: AddressDiscriminator
        })
    ], OutputData.prototype, "address");
    return OutputData;
}());
export { OutputData };
//# sourceMappingURL=output.js.map