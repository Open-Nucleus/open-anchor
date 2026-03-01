/// Move smart contract for Merkle root anchoring on IOTA Rebased.
/// Deploy this module on-chain, then reference its package ID in Config.AnchorPackageID.
module open_anchor::anchoring {
    use iota::object::{Self, UID};
    use iota::transfer;
    use iota::tx_context::{Self, TxContext};
    use iota::event;
    use iota::clock::{Self, Clock};

    /// Immutable on-chain anchor record.
    public struct MerkleAnchor has key, store {
        id: UID,
        merkle_root: vector<u8>,
        submitter: address,
        timestamp_ms: u64,
        leaf_count: u64,
    }

    /// Event emitted on every anchor.
    public struct AnchorCreated has copy, drop {
        anchor_id: address,
        merkle_root: vector<u8>,
        submitter: address,
        timestamp_ms: u64,
        leaf_count: u64,
    }

    const E_INVALID_ROOT_LENGTH: u64 = 1;

    /// Anchor a Merkle root on-chain (creates immutable object + event).
    public entry fun anchor_root(
        merkle_root: vector<u8>,
        leaf_count: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(vector::length(&merkle_root) == 32, E_INVALID_ROOT_LENGTH);
        let ts = clock::timestamp_ms(clock);
        let anchor = MerkleAnchor {
            id: object::new(ctx),
            merkle_root: copy merkle_root,
            submitter: tx_context::sender(ctx),
            timestamp_ms: ts,
            leaf_count,
        };
        let addr = object::id_to_address(&object::id(&anchor));
        event::emit(AnchorCreated {
            anchor_id: addr,
            merkle_root,
            submitter: tx_context::sender(ctx),
            timestamp_ms: ts,
            leaf_count,
        });
        transfer::public_freeze_object(anchor);
    }
}
