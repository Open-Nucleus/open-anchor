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
import { OutputResponse } from '../models/api';
/** Possible InclusionStates of transactions sent with the wallet */
export var InclusionState;
(function (InclusionState) {
    /** The transaction is pending. */
    InclusionState["Pending"] = "Pending";
    /** The transaction is confirmed. */
    InclusionState["Confirmed"] = "Confirmed";
    /** The transaction is conflicting. */
    InclusionState["Conflicting"] = "Conflicting";
    /** The transaction and its in- and outputs are pruned, so it's unknown if it got confirmed or was conflicting. */
    InclusionState["UnknownPruned"] = "UnknownPruned";
})(InclusionState || (InclusionState = {}));
/** A Transaction with metadata */
var Transaction = /** @class */ (function () {
    function Transaction() {
    }
    __decorate([
        Type(function () { return TransactionPayload; })
    ], Transaction.prototype, "payload");
    __decorate([
        Type(function () { return OutputResponse; })
    ], Transaction.prototype, "inputs");
    return Transaction;
}());
export { Transaction };
//# sourceMappingURL=transaction.js.map