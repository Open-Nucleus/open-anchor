import { ReceiptMilestoneOption } from '../milestone_options';
/**
 * Receipts response details.
 */
export declare class ReceiptsResponse {
    /**
     * The receipts.
     */
    receipts: MilestoneReceipt[];
}
export declare class MilestoneReceipt {
    /**
     * The milestone index.
     */
    milestoneIndex: number;
    /**
     * The receipt.
     */
    receipt: ReceiptMilestoneOption;
}
