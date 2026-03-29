// Copyright 2023 IOTA Stiftung
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
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
import { Type } from 'class-transformer';
import { TreasuryTransactionPayload } from '../../block/payload/treasury/treasury';
import { MigratedFunds } from '../migrated-funds';
import { MilestoneOption, MilestoneOptionType } from './milestone-options';
/**
 * A Receipt milestone option.
 */
var ReceiptMilestoneOption = /** @class */ (function (_super) {
    __extends(ReceiptMilestoneOption, _super);
    /**
     * @param migratedAt The milestone index at which the funds were migrated in the legacy network.
     * @param final Whether this Receipt is the final one for a given migrated at index.
     * @param funds The funds which were migrated.
     * @param transaction The Treasury Transaction used to provide the funds.
     */
    function ReceiptMilestoneOption(migratedAt, final, funds, transaction) {
        var _this = _super.call(this, MilestoneOptionType.Receipt) || this;
        _this.migratedAt = migratedAt;
        _this.final = final;
        _this.funds = funds;
        _this.transaction = transaction;
        return _this;
    }
    __decorate([
        Type(function () { return MigratedFunds; })
    ], ReceiptMilestoneOption.prototype, "funds");
    __decorate([
        Type(function () { return TreasuryTransactionPayload; })
    ], ReceiptMilestoneOption.prototype, "transaction");
    return ReceiptMilestoneOption;
}(MilestoneOption));
export { ReceiptMilestoneOption };
//# sourceMappingURL=receipt-milestone-option.js.map