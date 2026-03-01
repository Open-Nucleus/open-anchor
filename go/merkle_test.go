package anchor

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func makeLeaf(path string, data []byte) MerkleLeaf {
	h := sha256.Sum256(data)
	return MerkleLeaf{Path: path, Hash: h[:]}
}

func TestNewMerkleTree_SingleLeaf(t *testing.T) {
	leaf := makeLeaf("file.txt", []byte("hello"))
	tree, err := NewMerkleTree([]MerkleLeaf{leaf})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	root := tree.GetRoot()
	if len(root) != 32 {
		t.Fatalf("root length = %d, want 32", len(root))
	}
}

func TestNewMerkleTree_TwoLeaves(t *testing.T) {
	leaves := []MerkleLeaf{
		makeLeaf("a.txt", []byte("aaa")),
		makeLeaf("b.txt", []byte("bbb")),
	}
	tree, err := NewMerkleTree(leaves)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	root := tree.GetRoot()
	if len(root) != 32 {
		t.Fatalf("root length = %d, want 32", len(root))
	}
}

func TestNewMerkleTree_OddLeaves(t *testing.T) {
	leaves := []MerkleLeaf{
		makeLeaf("a.txt", []byte("aaa")),
		makeLeaf("b.txt", []byte("bbb")),
		makeLeaf("c.txt", []byte("ccc")),
	}
	tree, err := NewMerkleTree(leaves)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	root := tree.GetRoot()
	if len(root) != 32 {
		t.Fatalf("root length = %d, want 32", len(root))
	}
}

func TestNewMerkleTree_Empty(t *testing.T) {
	_, err := NewMerkleTree([]MerkleLeaf{})
	if err == nil {
		t.Fatal("expected error for empty leaves, got nil")
	}
}

func TestGenerateAndVerifyProof(t *testing.T) {
	// Build a 7-leaf tree and verify proofs for all leaves.
	leaves := make([]MerkleLeaf, 7)
	for i := range leaves {
		leaves[i] = makeLeaf(fmt.Sprintf("file%d.txt", i), []byte(fmt.Sprintf("data%d", i)))
	}

	tree, err := NewMerkleTree(leaves)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	root := tree.GetRoot()

	for i, leaf := range leaves {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("GenerateProof(%d): %v", i, err)
		}

		if !VerifyProof(leaf, proof, root) {
			t.Errorf("VerifyProof failed for leaf %d", i)
		}
	}
}

func TestVerifyProof_WrongRoot(t *testing.T) {
	leaves := []MerkleLeaf{
		makeLeaf("a.txt", []byte("aaa")),
		makeLeaf("b.txt", []byte("bbb")),
	}

	tree, _ := NewMerkleTree(leaves)
	proof, _ := tree.GenerateProof(0)

	fakeRoot := make([]byte, 32)
	if VerifyProof(leaves[0], proof, fakeRoot) {
		t.Error("VerifyProof should fail with wrong root")
	}
}

func TestVerifyProof_WrongLeaf(t *testing.T) {
	leaves := []MerkleLeaf{
		makeLeaf("a.txt", []byte("aaa")),
		makeLeaf("b.txt", []byte("bbb")),
	}

	tree, _ := NewMerkleTree(leaves)
	root := tree.GetRoot()
	proof, _ := tree.GenerateProof(0)

	wrongLeaf := makeLeaf("c.txt", []byte("ccc"))
	if VerifyProof(wrongLeaf, proof, root) {
		t.Error("VerifyProof should fail with wrong leaf")
	}
}

func TestDeterministicRoot(t *testing.T) {
	leaves := []MerkleLeaf{
		makeLeaf("a.txt", []byte("aaa")),
		makeLeaf("b.txt", []byte("bbb")),
		makeLeaf("c.txt", []byte("ccc")),
	}

	tree1, _ := NewMerkleTree(leaves)
	tree2, _ := NewMerkleTree(leaves)

	if !bytes.Equal(tree1.GetRoot(), tree2.GetRoot()) {
		t.Error("same leaves should produce the same root")
	}
}

func TestGenerateProof_OutOfRange(t *testing.T) {
	tree, _ := NewMerkleTree([]MerkleLeaf{makeLeaf("a.txt", []byte("a"))})
	_, err := tree.GenerateProof(1)
	if err == nil {
		t.Error("expected error for out-of-range index")
	}
	_, err = tree.GenerateProof(-1)
	if err == nil {
		t.Error("expected error for negative index")
	}
}

func BenchmarkMerkleTree1000(b *testing.B) {
	leaves := make([]MerkleLeaf, 1000)
	for i := range leaves {
		h := sha256.Sum256([]byte(fmt.Sprintf("data%d", i)))
		leaves[i] = MerkleLeaf{Path: fmt.Sprintf("f%d", i), Hash: h[:]}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewMerkleTree(leaves)
	}
}

func BenchmarkMerkleTree10000(b *testing.B) {
	leaves := make([]MerkleLeaf, 10000)
	for i := range leaves {
		h := sha256.Sum256([]byte(fmt.Sprintf("data%d", i)))
		leaves[i] = MerkleLeaf{Path: fmt.Sprintf("f%d", i), Hash: h[:]}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewMerkleTree(leaves)
	}
}
