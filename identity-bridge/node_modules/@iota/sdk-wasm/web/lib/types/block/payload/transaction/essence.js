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
import { Input, InputDiscriminator } from '../../input';
import { Output, OutputDiscriminator } from '../../output';
import { Payload, PayloadType } from '../payload';
import { TaggedDataPayload } from '../tagged/tagged';
/**
 * All of the essence types.
 */
var TransactionEssenceType;
(function (TransactionEssenceType) {
    /**
     * A regular transaction essence.
     */
    TransactionEssenceType[TransactionEssenceType["Regular"] = 1] = "Regular";
})(TransactionEssenceType || (TransactionEssenceType = {}));
/**
 * The base class for transaction essences.
 */
var TransactionEssence = /** @class */ (function () {
    /**
     * @param type The type of transaction essence.
     */
    function TransactionEssence(type) {
        this.type = type;
    }
    /**
     * Get the type of essence.
     */
    TransactionEssence.prototype.getType = function () {
        return this.type;
    };
    return TransactionEssence;
}());
/**
 * PayloadDiscriminator for payloads inside of a TransactionEssence.
 */
var PayloadDiscriminator = {
    property: 'type',
    subTypes: [
        { value: TaggedDataPayload, name: PayloadType.TaggedData },
    ]
};
/**
 * RegularTransactionEssence transaction essence.
 */
var RegularTransactionEssence = /** @class */ (function (_super) {
    __extends(RegularTransactionEssence, _super);
    /**
     * @param networkId The ID of the network the transaction was issued to.
     * @param inputsCommitment The hash of all inputs.
     * @param inputs The inputs of the transaction.
     * @param outputs The outputs of the transaction.
     * @param payload An optional Tagged Data payload.
     *
     */
    function RegularTransactionEssence(networkId, inputsCommitment, inputs, outputs, payload) {
        var _this = _super.call(this, TransactionEssenceType.Regular) || this;
        _this.networkId = networkId;
        _this.inputsCommitment = inputsCommitment;
        _this.inputs = inputs;
        _this.outputs = outputs;
        _this.payload = payload;
        return _this;
    }
    __decorate([
        Type(function () { return Input; }, {
            discriminator: InputDiscriminator
        })
    ], RegularTransactionEssence.prototype, "inputs");
    __decorate([
        Type(function () { return Output; }, {
            discriminator: OutputDiscriminator
        })
    ], RegularTransactionEssence.prototype, "outputs");
    __decorate([
        Type(function () { return Payload; }, {
            discriminator: PayloadDiscriminator
        })
    ], RegularTransactionEssence.prototype, "payload");
    return RegularTransactionEssence;
}(TransactionEssence));
var TransactionEssenceDiscriminator = {
    property: 'type',
    subTypes: [
        {
            value: RegularTransactionEssence,
            name: TransactionEssenceType.Regular
        },
    ]
};
export { TransactionEssenceDiscriminator, TransactionEssence, TransactionEssenceType, RegularTransactionEssence, };
//# sourceMappingURL=essence.js.map