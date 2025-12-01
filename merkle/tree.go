package merkle

import (
	"fmt"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// Node represents a node in the Merkle tree
type Node struct {
	Data  *lattice.Vector
	Left  *Node
	Right *Node
}

// Tree represents an updatable Merkle tree accumulator
// This is the key component for achieving full dynamicity
type Tree struct {
	Root          *Node
	Leaves        []*Node
	Height        int
	Size          int // Number of leaves (N)
	HashFunction  *HashFunction
	InternalNodes [][]*Node // Cache of internal nodes by level for O(log N) GetProof
}

// NewTree creates a new Merkle tree with N leaves
// Initially all leaves are set to 0 (representing inactive users)
func NewTree(pp *lattice.PublicParameters) *Tree {
	// Calculate height: log2(MaxUsers)
	// For MaxUsers = 4 → height = 2 (levels: leaf, parent, root)
	height := 0
	temp := pp.MaxUsers
	for temp > 1 {
		temp = temp / 2
		height++
	}

	tree := &Tree{
		Height:        height,
		Size:          pp.MaxUsers,
		Leaves:        make([]*Node, pp.MaxUsers),
		HashFunction:  NewHashFunction(pp.A, pp.NK),
		InternalNodes: make([][]*Node, height),
	}

	return tree
}

// BuildTree recursively builds the tree from leaves
// Also caches internal nodes for efficient GetProof (O(log N) instead of O(N))
func (t *Tree) BuildTree(nodes []*Node) *Node {
	return t.buildTreeLevel(nodes, 0)
}

// buildTreeLevel builds a level of the tree and caches internal nodes
func (t *Tree) buildTreeLevel(nodes []*Node, level int) *Node {
	if len(nodes) == 1 {
		t.Root = nodes[0]
		return nodes[0]
	}

	// Cache this level's nodes (excluding leaf level which is already in t.Leaves)
	if level > 0 && level <= len(t.InternalNodes) {
		t.InternalNodes[level-1] = nodes
	}

	var parents []*Node
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]

		right := nodes[i+1]
		parent := &Node{
			Data:  t.HashFunction.Hash(left.Data, right.Data),
			Left:  left,
			Right: right,
		}
		parents = append(parents, parent)
	}

	return t.buildTreeLevel(parents, level+1)
}

// Update updates the value at leaf index i
// This is the core of the updatable Merkle tree
// Complexity: O(log N)
func (t *Tree) Update(index int, value *lattice.Vector) error {
	if index < 0 || index >= t.Size {
		return fmt.Errorf("index out of bounds: %d", index)
	}

	t.ensureTreeInitialized()

	leaf := t.ensureLeafNode(index)
	leaf.Data = value

	currentNode := leaf
	currentIndex := index

	for level := 0; level < t.Height; level++ {
		siblingIndex := currentIndex ^ 1
		var sibling *Node
		if level == 0 {
			sibling = t.ensureLeafNode(siblingIndex)
		} else {
			sibling = t.ensureInternalNode(level-1, siblingIndex)
		}

		parentIndex := currentIndex / 2
		parent := t.ensureInternalNode(level, parentIndex)

		if currentIndex%2 == 0 {
			parent.Data = t.HashFunction.Hash(currentNode.Data, sibling.Data)
			parent.Left = currentNode
			parent.Right = sibling
		} else {
			parent.Data = t.HashFunction.Hash(sibling.Data, currentNode.Data)
			parent.Left = sibling
			parent.Right = currentNode
		}

		currentNode = parent
		currentIndex = parentIndex
	}

	if currentNode != nil {
		t.Root = currentNode
	}

	return nil
}

func (t *Tree) ensureTreeInitialized() {
	if t.Root != nil {
		return
	}

	for i := 0; i < len(t.Leaves); i++ {
		if t.Leaves[i] == nil {
			t.Leaves[i] = &Node{Data: lattice.NewVector(t.HashFunction.NK, t.HashFunction.Q)}
		}
	}

	t.BuildTree(t.Leaves)
}

func (t *Tree) ensureLeafNode(index int) *Node {
	if index < 0 || index >= len(t.Leaves) {
		return &Node{Data: lattice.NewVector(t.HashFunction.NK, t.HashFunction.Q)}
	}

	if t.Leaves[index] == nil {
		t.Leaves[index] = &Node{Data: lattice.NewVector(t.HashFunction.NK, t.HashFunction.Q)}
	}

	return t.Leaves[index]
}

func (t *Tree) ensureInternalNode(level, index int) *Node {
	if level < 0 {
		return &Node{Data: lattice.NewVector(t.HashFunction.NK, t.HashFunction.Q)}
	}

	if level >= len(t.InternalNodes) {
		t.InternalNodes = append(t.InternalNodes, make([]*Node, 1))
	}

	nodes := t.InternalNodes[level]
	if nodes == nil {
		nodes = make([]*Node, t.levelWidth(level))
		t.InternalNodes[level] = nodes
	}

	if index >= len(nodes) {
		newNodes := make([]*Node, index+1)
		copy(newNodes, nodes)
		nodes = newNodes
		t.InternalNodes[level] = nodes
	}

	if nodes[index] == nil {
		nodes[index] = &Node{Data: lattice.NewVector(t.HashFunction.NK, t.HashFunction.Q)}
	}

	return nodes[index]
}

func (t *Tree) levelWidth(level int) int {
	remaining := t.Height - level - 1
	if remaining < 0 {
		remaining = 0
	}
	return 1 << remaining
}

// GetProof returns the Merkle proof (authentication path) for leaf at index
// Returns the sibling hashes at each level from leaf to root
// Optimized: O(log N) using cached internal nodes instead of O(N) rebuilding
func (t *Tree) GetProof(index int) ([]*lattice.Vector, []bool, error) {
	if index < 0 || index >= t.Size {
		return nil, nil, fmt.Errorf("index out of bounds: %d", index)
	}

	var proof []*lattice.Vector
	var directions []bool // true = current is left (sibling is right), false = current is right

	// Start from the leaf
	currentNode := t.Leaves[index]
	if currentNode == nil {
		return nil, nil, fmt.Errorf("leaf at index %d is nil", index)
	}

	currentIndex := index

	for level := 0; level < t.Height; level++ {
		// At each level, find the sibling
		siblingIndex := currentIndex ^ 1 // XOR with 1 flips the last bit
		isLeft := (currentIndex%2 == 0)

		// Get sibling data from cache (O(1) lookup)
		var siblingData *lattice.Vector

		if level == 0 {
			// Leaf level - directly get sibling leaf
			if siblingIndex < len(t.Leaves) && t.Leaves[siblingIndex] != nil {
				siblingData = t.Leaves[siblingIndex].Data
			}
		} else {
			// Internal level - use cached nodes (fix: O(log N) instead of O(N))
			if siblingIndex < len(t.InternalNodes[level-1]) && t.InternalNodes[level-1][siblingIndex] != nil {
				siblingData = t.InternalNodes[level-1][siblingIndex].Data
			}
		}

		if siblingData == nil {
			// If sibling doesn't exist (tree not full), use zero vector
			siblingData = lattice.NewVector(t.HashFunction.NK, t.HashFunction.Q)
		}

		proof = append(proof, siblingData)
		directions = append(directions, isLeft)

		// Move to parent level
		currentIndex = currentIndex / 2
	}

	return proof, directions, nil
}

// buildSubtree builds a subtree from a list of leaves (helper for GetProof)
func (t *Tree) buildSubtree(nodes []*Node) *Node {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	var parents []*Node
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		var right *Node
		if i+1 < len(nodes) {
			right = nodes[i+1]
		}

		if right == nil {
			parents = append(parents, left)
		} else {
			parent := &Node{
				Data:  t.HashFunction.Hash(left.Data, right.Data),
				Left:  left,
				Right: right,
			}
			parents = append(parents, parent)
		}
	}

	return t.buildSubtree(parents)
}

// VerifyProof verifies a Merkle proof
func (t *Tree) VerifyProof(leafValue *lattice.Vector, index int, proof []*lattice.Vector, directions []bool) bool {
	currentHash := leafValue

	for i := 0; i < len(proof); i++ {
		if directions[i] {
			// Current node is left, sibling is right
			currentHash = t.HashFunction.Hash(currentHash, proof[i])
		} else {
			// Current node is right, sibling is left
			currentHash = t.HashFunction.Hash(proof[i], currentHash)
		}
	}

	return currentHash.IsEqual(t.Root.Data)
}

// GetRoot returns the current root hash
func (t *Tree) GetRoot() *lattice.Vector {
	return t.Root.Data
}

// SetActive sets a user as active (joins the group)
// value should be the user's public key pi
func (t *Tree) SetActive(index int, publicKey *lattice.Vector) error {
	return t.Update(index, publicKey)
}

// SetInactive sets a user as inactive (leaves/revoked)
// Sets the leaf value to 0
func (t *Tree) SetInactive(index int) error {
	return t.Update(index, lattice.NewVector(t.HashFunction.NK, t.HashFunction.Q))
}

// Helper functions
