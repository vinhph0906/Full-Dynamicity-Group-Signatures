package nizk

// Debug controls optional debug prints across the NIZK package.
var Debug = false

// StrictPExtStructure toggles strict checking of p* structure in VALID.
// When true, checks p* equals [p || (1−p)[:-1]] after permutation (not recommended
// unless permutations preserve p* block layout). Default false (weight-only).
var StrictPExtStructure = false
