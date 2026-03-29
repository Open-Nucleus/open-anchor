// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
// Needed for class-transformer json deserialisation
import 'reflect-metadata';
import { callUtilsMethod } from './bindings';
import { UTXOInput } from './types';
import { bigIntToHex } from './utils';
// Allow bigint to be serialized as hex string.
//
// Note:
// Serializing `bigint` to a different format, e.g. to decimal number string
// must be done manually.
BigInt.prototype.toJSON = function () {
    return bigIntToHex(this);
};
// Assign the util method on UTXOInput here,
// to prevent loading bindings (callUtilsMethod) when importing UTXOInput just for typing.
Object.assign(UTXOInput, {
    /**
     * Creates a `UTXOInput` from an output id.
     */
    fromOutputId: function (outputId) {
        var input = callUtilsMethod({
            name: 'outputIdToUtxoInput',
            data: {
                outputId: outputId
            }
        });
        return new UTXOInput(input.transactionId, input.transactionOutputIndex);
    }
});
export * from './client';
export * from './secret_manager';
export * from './types';
export * from './utils';
export * from './wallet';
export * from './logger';
// @ts-ignore
import { init } from '../wasm/iota_sdk_wasm';
export default init;
//# sourceMappingURL=index.js.map