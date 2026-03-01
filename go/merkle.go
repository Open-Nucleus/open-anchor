package anchor

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// MerkleLeaf represents a single leaf in the Merkle tree.
type MerkleLeaf struct {
	Path string `json:"path"`
	Hash []byte `json:"hash"`
}

// MerkleTree computes and stores a binary hash tree.
type MerkleTree struct {
	root         []byte
	leaves       []MerkleLeaf
	nodes        [][]byte // flat array of all nodes for proof generation
	depth        int
	levelOffsets []int
	levelSizes   []int
}

// MerkleProof contains the sibling hashes needed to reconstruct the root.
type MerkleProof struct {
	LeafHash []byte      `json:"leafHash"`
	Siblings []ProofStep `json:"siblings"`
}

// ProofStep is a single sibling hash in a Merkle proof.
type ProofStep struct {
	Hash     []byte `json:"hash"`
	Position string `json:"position"` // "left" or "right"
}

// NewMerkleTree builds a binary Merkle tree from a set of leaves.
// Returns an error if no leaves are provided.
func NewMerkleTree(leaves []MerkleLeaf) (*MerkleTree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("merkle tree requires at least one leaf")
	}

	t := &MerkleTree{leaves: leaves}
	t.build()
	return t, nil
}

// GetRoot returns the 32-byte Merkle root.
func (t *MerkleTree) GetRoot() []byte {
	return t.root
}

// build constructs the tree bottom-up, storing all nodes in a flat slice.
// For a level with an odd number of nodes, the last node is duplicated.
func (t *MerkleTree) build() {
	// Start with leaf hashes.
	level := make([][]byte, len(t.leaves))
	for i, leaf := range t.leaves {
		level[i] = hashLeaf(leaf.Hash)
	}

	// Store all levels for proof generation: levels[0] = leaf hashes, etc.
	var allLevels [][]byte
	allLevels = append(allLevels, level...)

	levelOffsets := []int{0}
	levelSizes := []int{len(level)}

	for len(level) > 1 {
		// Duplicate last node if odd count.
		if len(level)%2 != 0 {
			level = append(level, level[len(level)-1])
		}

		var nextLevel [][]byte
		for i := 0; i < len(level); i += 2 {
			parent := hashPair(level[i], level[i+1])
			nextLevel = append(nextLevel, parent)
		}

		levelOffsets = append(levelOffsets, len(allLevels))
		levelSizes = append(levelSizes, len(nextLevel))
		allLevels = append(allLevels, nextLevel...)
		level = nextLevel
	}

	t.root = level[0]
	t.nodes = allLevels
	t.depth = len(levelOffsets)

	// Store offsets and sizes in the tree for proof generation.
	t.levelOffsets = levelOffsets
	t.levelSizes = levelSizes
}

// levelOffsets and levelSizes are stored for proof generation.
// levelOffsets[i] is the starting index of level i in t.nodes.
// levelSizes[i] is the number of nodes at level i.

// GenerateProof returns the inclusion proof for a specific leaf by index.
func (t *MerkleTree) GenerateProof(leafIndex int) (MerkleProof, error) {
	if leafIndex < 0 || leafIndex >= len(t.leaves) {
		return MerkleProof{}, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, len(t.leaves))
	}

	proof := MerkleProof{
		LeafHash: hashLeaf(t.leaves[leafIndex].Hash),
	}

	idx := leafIndex

	for level := 0; level < t.depth-1; level++ {
		levelSize := t.levelSizes[level]
		offset := t.levelOffsets[level]

		// Handle odd-sized levels: the last node is conceptually duplicated.
		effectiveSize := levelSize
		if effectiveSize%2 != 0 {
			effectiveSize++
		}

		var siblingIdx int
		var position string
		if idx%2 == 0 {
			siblingIdx = idx + 1
			position = "right"
		} else {
			siblingIdx = idx - 1
			position = "left"
		}

		// If sibling index is beyond the actual nodes, it's a duplicate of the last node.
		var siblingHash []byte
		if siblingIdx >= levelSize {
			siblingHash = t.nodes[offset+levelSize-1]
		} else {
			siblingHash = t.nodes[offset+siblingIdx]
		}

		proof.Siblings = append(proof.Siblings, ProofStep{
			Hash:     siblingHash,
			Position: position,
		})

		idx = idx / 2
	}

	return proof, nil
}

// VerifyProof checks that a leaf is included in a tree with the given root.
func VerifyProof(leaf MerkleLeaf, proof MerkleProof, root []byte) bool {
	current := hashLeaf(leaf.Hash)

	for _, step := range proof.Siblings {
		if step.Position == "left" {
			current = hashPair(step.Hash, current)
		} else {
			current = hashPair(current, step.Hash)
		}
	}

	return equal(current, root)
}

func hashLeaf(data []byte) []byte {
	// Prefix with 0x00 to distinguish leaves from internal nodes.
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

func hashPair(left, right []byte) []byte {
	// Prefix with 0x01 to distinguish internal nodes from leaves.
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
