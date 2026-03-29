// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
import { plainToInstance } from 'class-transformer';
import { MilestonePayload } from './milestone';
import { PayloadType } from './payload';
import { TaggedDataPayload } from './tagged';
import { TransactionPayload } from './transaction';
import { TreasuryTransactionPayload } from './treasury';
export * from './milestone';
export * from './tagged';
export * from './transaction';
export * from './payload';
export var PayloadDiscriminator = {
    property: 'type',
    subTypes: [
        { value: MilestonePayload, name: PayloadType.Milestone },
        { value: TaggedDataPayload, name: PayloadType.TaggedData },
        { value: TransactionPayload, name: PayloadType.Transaction },
        {
            value: TreasuryTransactionPayload,
            name: PayloadType.TreasuryTransaction
        },
    ]
};
export function parsePayload(data) {
    if (data.type == PayloadType.Milestone) {
        return plainToInstance(MilestonePayload, data);
    }
    else if (data.type == PayloadType.TaggedData) {
        return plainToInstance(TaggedDataPayload, data);
    }
    else if (data.type == PayloadType.Transaction) {
        return plainToInstance(TransactionPayload, data);
    }
    else if (data.type == PayloadType.TreasuryTransaction) {
        return plainToInstance(TreasuryTransactionPayload, data);
    }
    throw new Error('Invalid JSON');
}
//# sourceMappingURL=index.js.map