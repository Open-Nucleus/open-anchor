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
 * An wallet account event.
 */
var Event = /** @class */ (function () {
    /**
     * @param accountIndex The account index.
     * @param event The wallet event.
     */
    function Event(accountIndex, event) {
        this.accountIndex = accountIndex;
        this.event = event;
    }
    return Event;
}());
/**
 * All of the wallet event types.
 */
var WalletEventType;
(function (WalletEventType) {
    /** Consolidation is required. */
    WalletEventType[WalletEventType["ConsolidationRequired"] = 0] = "ConsolidationRequired";
    /** Nano Ledger has generated an address. */
    WalletEventType[WalletEventType["LedgerAddressGeneration"] = 1] = "LedgerAddressGeneration";
    /** A new output was created. */
    WalletEventType[WalletEventType["NewOutput"] = 2] = "NewOutput";
    /** An output was spent. */
    WalletEventType[WalletEventType["SpentOutput"] = 3] = "SpentOutput";
    /** A transaction was included into the ledger. */
    WalletEventType[WalletEventType["TransactionInclusion"] = 4] = "TransactionInclusion";
    /** A progress update while submitting a transaction. */
    WalletEventType[WalletEventType["TransactionProgress"] = 5] = "TransactionProgress";
})(WalletEventType || (WalletEventType = {}));
/**
 * The base class for wallet events.
 */
var WalletEvent = /** @class */ (function () {
    /**
     * @param type The type of wallet event.
     */
    function WalletEvent(type) {
        this.type = type;
    }
    return WalletEvent;
}());
/**
 * A 'consolidation required' wallet event.
 */
var ConsolidationRequiredWalletEvent = /** @class */ (function (_super) {
    __extends(ConsolidationRequiredWalletEvent, _super);
    function ConsolidationRequiredWalletEvent() {
        return _super.call(this, WalletEventType.ConsolidationRequired) || this;
    }
    return ConsolidationRequiredWalletEvent;
}(WalletEvent));
/**
 * A 'ledger address generation' wallet event.
 */
var LedgerAddressGenerationWalletEvent = /** @class */ (function (_super) {
    __extends(LedgerAddressGenerationWalletEvent, _super);
    /**
     * @param address The generated address.
     */
    function LedgerAddressGenerationWalletEvent(address) {
        var _this = _super.call(this, WalletEventType.LedgerAddressGeneration) || this;
        _this.address = address;
        return _this;
    }
    return LedgerAddressGenerationWalletEvent;
}(WalletEvent));
/**
 * A 'new output' wallet event.
 */
var NewOutputWalletEvent = /** @class */ (function (_super) {
    __extends(NewOutputWalletEvent, _super);
    /**
     * @param output The new output.
     * @param transaction The transaction that created the output. Might be pruned and not available.
     * @param transactionInputs The inputs for the transaction that created the output. Might be pruned and not available.
     */
    function NewOutputWalletEvent(output, transaction, transactionInputs) {
        var _this = _super.call(this, WalletEventType.NewOutput) || this;
        _this.output = output;
        _this.transaction = transaction;
        _this.transactionInputs = transactionInputs;
        return _this;
    }
    return NewOutputWalletEvent;
}(WalletEvent));
/**
 * A 'spent output' wallet event.
 */
var SpentOutputWalletEvent = /** @class */ (function (_super) {
    __extends(SpentOutputWalletEvent, _super);
    /**
     * @param output The spent output.
     */
    function SpentOutputWalletEvent(output) {
        var _this = _super.call(this, WalletEventType.SpentOutput) || this;
        _this.output = output;
        return _this;
    }
    return SpentOutputWalletEvent;
}(WalletEvent));
/**
 * A 'transaction inclusion' wallet event.
 */
var TransactionInclusionWalletEvent = /** @class */ (function (_super) {
    __extends(TransactionInclusionWalletEvent, _super);
    /**
     * @param transactionId The transaction ID.
     * @param inclusionState The inclusion state of the transaction.
     */
    function TransactionInclusionWalletEvent(transactionId, inclusionState) {
        var _this = _super.call(this, WalletEventType.TransactionInclusion) || this;
        _this.transactionId = transactionId;
        _this.inclusionState = inclusionState;
        return _this;
    }
    return TransactionInclusionWalletEvent;
}(WalletEvent));
/**
 * All of the transaction progress types.
 */
var TransactionProgressType;
(function (TransactionProgressType) {
    /** Performing input selection. */
    TransactionProgressType[TransactionProgressType["SelectingInputs"] = 0] = "SelectingInputs";
    /** Generating remainder value deposit address. */
    TransactionProgressType[TransactionProgressType["GeneratingRemainderDepositAddress"] = 1] = "GeneratingRemainderDepositAddress";
    /** Prepared transaction. */
    TransactionProgressType[TransactionProgressType["PreparedTransaction"] = 2] = "PreparedTransaction";
    /** Prepared transaction essence hash hex encoded, required for blindsigning with a Ledger Nano. */
    TransactionProgressType[TransactionProgressType["PreparedTransactionEssenceHash"] = 3] = "PreparedTransactionEssenceHash";
    /** Signing the transaction. */
    TransactionProgressType[TransactionProgressType["SigningTransaction"] = 4] = "SigningTransaction";
    /** Performing PoW. */
    TransactionProgressType[TransactionProgressType["PerformingPow"] = 5] = "PerformingPow";
    /** Broadcasting. */
    TransactionProgressType[TransactionProgressType["Broadcasting"] = 6] = "Broadcasting";
})(TransactionProgressType || (TransactionProgressType = {}));
/**
 * A 'transaction progress' wallet event.
 */
var TransactionProgressWalletEvent = /** @class */ (function (_super) {
    __extends(TransactionProgressWalletEvent, _super);
    /**
     * @param progress The progress of the transaction.
     */
    function TransactionProgressWalletEvent(progress) {
        var _this = _super.call(this, WalletEventType.TransactionProgress) || this;
        _this.progress = progress;
        return _this;
    }
    return TransactionProgressWalletEvent;
}(WalletEvent));
/**
 * The base class for transaction progresses.
 */
var TransactionProgress = /** @class */ (function () {
    /**
     * @param type The type of transaction progress.
     */
    function TransactionProgress(type) {
        this.type = type;
    }
    return TransactionProgress;
}());
/**
 * A 'selecting inputs' progress.
 */
var SelectingInputsProgress = /** @class */ (function (_super) {
    __extends(SelectingInputsProgress, _super);
    function SelectingInputsProgress() {
        return _super.call(this, TransactionProgressType.SelectingInputs) || this;
    }
    return SelectingInputsProgress;
}(TransactionProgress));
/**
 * A 'generating remainder deposit address' progress.
 */
var GeneratingRemainderDepositAddressProgress = /** @class */ (function (_super) {
    __extends(GeneratingRemainderDepositAddressProgress, _super);
    /**
     * @param address The generated remainder deposit address.
     */
    function GeneratingRemainderDepositAddressProgress(address) {
        var _this = _super.call(this, TransactionProgressType.GeneratingRemainderDepositAddress) || this;
        _this.address = address;
        return _this;
    }
    return GeneratingRemainderDepositAddressProgress;
}(TransactionProgress));
/**
 * A 'prepared transaction' progress.
 */
var PreparedTransactionProgress = /** @class */ (function (_super) {
    __extends(PreparedTransactionProgress, _super);
    /**
     * @param essence The essence of the prepared transaction.
     * @param inputsData Input signing parameters.
     * @param remainder Remainder output parameters.
     */
    function PreparedTransactionProgress(essence, inputsData, remainder) {
        var _this = _super.call(this, TransactionProgressType.PreparedTransaction) || this;
        _this.essence = essence;
        _this.inputsData = inputsData;
        _this.remainder = remainder;
        return _this;
    }
    return PreparedTransactionProgress;
}(TransactionProgress));
/**
 * A 'prepared transaction essence hash' progress.
 */
var PreparedTransactionEssenceHashProgress = /** @class */ (function (_super) {
    __extends(PreparedTransactionEssenceHashProgress, _super);
    /**
     * @param hash The hash of the transaction essence.
     */
    function PreparedTransactionEssenceHashProgress(hash) {
        var _this = _super.call(this, TransactionProgressType.PreparedTransactionEssenceHash) || this;
        _this.hash = hash;
        return _this;
    }
    return PreparedTransactionEssenceHashProgress;
}(TransactionProgress));
/**
 * A 'signing transaction' progress.
 */
var SigningTransactionProgress = /** @class */ (function (_super) {
    __extends(SigningTransactionProgress, _super);
    function SigningTransactionProgress() {
        return _super.call(this, TransactionProgressType.SigningTransaction) || this;
    }
    return SigningTransactionProgress;
}(TransactionProgress));
/**
 * A 'performing PoW' progress.
 */
var PerformingPowProgress = /** @class */ (function (_super) {
    __extends(PerformingPowProgress, _super);
    function PerformingPowProgress() {
        return _super.call(this, TransactionProgressType.PerformingPow) || this;
    }
    return PerformingPowProgress;
}(TransactionProgress));
/**
 * A 'broadcasting' progress.
 */
var BroadcastingProgress = /** @class */ (function (_super) {
    __extends(BroadcastingProgress, _super);
    function BroadcastingProgress() {
        return _super.call(this, TransactionProgressType.Broadcasting) || this;
    }
    return BroadcastingProgress;
}(TransactionProgress));
export { Event, WalletEventType, WalletEvent, ConsolidationRequiredWalletEvent, LedgerAddressGenerationWalletEvent, NewOutputWalletEvent, SpentOutputWalletEvent, TransactionInclusionWalletEvent, TransactionProgressWalletEvent, TransactionProgress, SelectingInputsProgress, GeneratingRemainderDepositAddressProgress, PreparedTransactionProgress, PreparedTransactionEssenceHashProgress, SigningTransactionProgress, PerformingPowProgress, BroadcastingProgress, TransactionProgressType, };
//# sourceMappingURL=event.js.map