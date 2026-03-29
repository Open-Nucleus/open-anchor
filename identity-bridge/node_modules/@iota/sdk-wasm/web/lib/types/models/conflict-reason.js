// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var _a;
/**
 * Reason for block conflicts.
 */
export var ConflictReason;
(function (ConflictReason) {
    /**
     * The block has no conflict.
     */
    ConflictReason[ConflictReason["none"] = 0] = "none";
    /**
     * The referenced UTXO was already spent.
     */
    ConflictReason[ConflictReason["inputUTXOAlreadySpent"] = 1] = "inputUTXOAlreadySpent";
    /**
     * The referenced UTXO was already spent while confirming this milestone.
     */
    ConflictReason[ConflictReason["inputUTXOAlreadySpentInThisMilestone"] = 2] = "inputUTXOAlreadySpentInThisMilestone";
    /**
     * The referenced UTXO cannot be found.
     */
    ConflictReason[ConflictReason["inputUTXONotFound"] = 3] = "inputUTXONotFound";
    /**
     * The sum of the inputs and output values does not match.
     */
    ConflictReason[ConflictReason["inputOutputSumMismatch"] = 4] = "inputOutputSumMismatch";
    /**
     * The unlock signature is invalid.
     */
    ConflictReason[ConflictReason["invalidSignature"] = 5] = "invalidSignature";
    /**
     * The configured timelock is not yet expired.
     */
    ConflictReason[ConflictReason["invalidTimelock"] = 6] = "invalidTimelock";
    /**
     * The native tokens are invalid.
     */
    ConflictReason[ConflictReason["invalidNativeTokens"] = 7] = "invalidNativeTokens";
    /**
     * The return amount in a transaction is not fulfilled by the output side.
     */
    ConflictReason[ConflictReason["returnAmountMismatch"] = 8] = "returnAmountMismatch";
    /**
     * The input unlock is invalid.
     */
    ConflictReason[ConflictReason["invalidInputUnlock"] = 9] = "invalidInputUnlock";
    /**
     * The inputs commitment is invalid.
     */
    ConflictReason[ConflictReason["invalidInputsCommitment"] = 10] = "invalidInputsCommitment";
    /**
     * The output contains a Sender with an ident (address) which is not unlocked.
     */
    ConflictReason[ConflictReason["invalidSender"] = 11] = "invalidSender";
    /**
     * The chain state transition is invalid.
     */
    ConflictReason[ConflictReason["invalidChainState"] = 12] = "invalidChainState";
    /**
     * The semantic validation failed.
     */
    ConflictReason[ConflictReason["semanticValidationFailed"] = 255] = "semanticValidationFailed";
})(ConflictReason || (ConflictReason = {}));
/**
 * Conflict reason strings.
 */
export var CONFLICT_REASON_STRINGS = (_a = {},
    _a[ConflictReason.none] = 'The block has no conflict',
    _a[ConflictReason.inputUTXOAlreadySpent] = 'The referenced UTXO was already spent',
    _a[ConflictReason.inputUTXOAlreadySpentInThisMilestone] = 'The referenced UTXO was already spent while confirming this milestone',
    _a[ConflictReason.inputUTXONotFound] = 'The referenced UTXO cannot be found',
    _a[ConflictReason.inputOutputSumMismatch] = 'The sum of the inputs and output values does not match',
    _a[ConflictReason.invalidSignature] = 'The unlock block signature is invalid',
    _a[ConflictReason.invalidTimelock] = 'The configured timelock is not yet expired',
    _a[ConflictReason.invalidNativeTokens] = 'The native tokens are invalid',
    _a[ConflictReason.returnAmountMismatch] = 'The return amount in a transaction is not fulfilled by the output side',
    _a[ConflictReason.invalidInputUnlock] = 'The input unlock is invalid',
    _a[ConflictReason.invalidInputsCommitment] = 'The inputs commitment is invalid',
    _a[ConflictReason.invalidSender] = ' The output contains a Sender with an ident (address) which is not unlocked',
    _a[ConflictReason.invalidChainState] = 'The chain state transition is invalid',
    _a[ConflictReason.semanticValidationFailed] = 'The semantic validation failed',
    _a);
//# sourceMappingURL=conflict-reason.js.map