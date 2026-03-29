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
/**
 * All of the transaction input types.
 */
var InputType;
(function (InputType) {
    /** A UTXO input. */
    InputType[InputType["UTXO"] = 0] = "UTXO";
    /** The treasury input. */
    InputType[InputType["Treasury"] = 1] = "Treasury";
})(InputType || (InputType = {}));
/**
 * The base class for transaction inputs.
 */
var Input = /** @class */ (function () {
    /**
     * @param type The type of input.
     */
    function Input(type) {
        this.type = type;
    }
    /**
     * Get the type of input.
     */
    Input.prototype.getType = function () {
        return this.type;
    };
    return Input;
}());
/**
 * A Treasury input.
 */
var TreasuryInput = /** @class */ (function (_super) {
    __extends(TreasuryInput, _super);
    /**
     * @param milestoneId The milestone id of the input.
     */
    function TreasuryInput(milestoneId) {
        var _this = _super.call(this, InputType.Treasury) || this;
        _this.milestoneId = milestoneId;
        return _this;
    }
    return TreasuryInput;
}(Input));
/**
 * A UTXO transaction input.
 */
var UTXOInput = /** @class */ (function (_super) {
    __extends(UTXOInput, _super);
    /**
     * @param transactionId The ID of the transaction it is an input of.
     * @param transactionOutputIndex The index of the input within the transaction.
     */
    function UTXOInput(transactionId, transactionOutputIndex) {
        var _this = _super.call(this, InputType.UTXO) || this;
        _this.transactionId = transactionId;
        _this.transactionOutputIndex = transactionOutputIndex;
        return _this;
    }
    /**
     * Create a `UTXOInput` from a given output ID.
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    UTXOInput.fromOutputId = function (outputId) {
        // Implementation injected in lib/index.ts, as it uses bindings.
        return null;
    };
    return UTXOInput;
}(Input));
var InputDiscriminator = {
    property: 'type',
    subTypes: [
        { value: TreasuryInput, name: InputType.Treasury },
        { value: UTXOInput, name: InputType.UTXO },
    ]
};
export { InputDiscriminator, InputType, Input, TreasuryInput, UTXOInput };
//# sourceMappingURL=input.js.map