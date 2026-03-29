"use strict";
// Copyright 2021-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transaction = exports.InclusionState = void 0;
const class_transformer_1 = require("class-transformer");
const transaction_1 = require("../block/payload/transaction");
const api_1 = require("../models/api");
/** Possible InclusionStates of transactions sent with the wallet */
var InclusionState;
(function (InclusionState) {
    /** The transaction is pending. */
    InclusionState["Pending"] = "Pending";
    /** The transaction is confirmed. */
    InclusionState["Confirmed"] = "Confirmed";
    /** The transaction is conflicting. */
    InclusionState["Conflicting"] = "Conflicting";
    /** The transaction and its in- and outputs are pruned, so it's unknown if it got confirmed or was conflicting. */
    InclusionState["UnknownPruned"] = "UnknownPruned";
})(InclusionState = exports.InclusionState || (exports.InclusionState = {}));
/** A Transaction with metadata */
class Transaction {
}
__decorate([
    (0, class_transformer_1.Type)(() => transaction_1.TransactionPayload)
], Transaction.prototype, "payload", void 0);
__decorate([
    (0, class_transformer_1.Type)(() => api_1.OutputResponse)
], Transaction.prototype, "inputs", void 0);
exports.Transaction = Transaction;
//# sourceMappingURL=transaction.js.map