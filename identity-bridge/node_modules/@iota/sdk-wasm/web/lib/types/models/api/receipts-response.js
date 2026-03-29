// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
import { Type } from 'class-transformer';
import { ReceiptMilestoneOption } from '../milestone_options';
/**
 * Receipts response details.
 */
var ReceiptsResponse = /** @class */ (function () {
    function ReceiptsResponse() {
    }
    __decorate([
        Type(function () { return MilestoneReceipt; })
    ], ReceiptsResponse.prototype, "receipts");
    return ReceiptsResponse;
}());
export { ReceiptsResponse };
var MilestoneReceipt = /** @class */ (function () {
    function MilestoneReceipt() {
    }
    __decorate([
        Type(function () { return ReceiptMilestoneOption; })
    ], MilestoneReceipt.prototype, "receipt");
    return MilestoneReceipt;
}());
export { MilestoneReceipt };
//# sourceMappingURL=receipts-response.js.map