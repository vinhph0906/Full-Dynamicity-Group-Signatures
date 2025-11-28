package storage

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
	"github.com/vinhphamhuu/lattice-group-signature/nizk"
	"github.com/vinhphamhuu/lattice-group-signature/scheme"
)

const (
	DefaultDataDir = ".lattice-gs"
)

// Storage handles persistent storage of keys and data
type Storage struct {
	DataDir string
}

// NewStorage creates a new storage instance
func NewStorage(dataDir string) (*Storage, error) {
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home dir: %v", err)
		}
		dataDir = filepath.Join(home, DefaultDataDir)
	}

	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data dir: %v", err)
	}

	return &Storage{DataDir: dataDir}, nil
}

// File path helpers
func (s *Storage) ppPath() string        { return filepath.Join(s.DataDir, "public_params.json") }
func (s *Storage) gmKeyPath() string     { return filepath.Join(s.DataDir, "gm_keys.json") }
func (s *Storage) tmKeyPath() string     { return filepath.Join(s.DataDir, "tm_keys.json") }
func (s *Storage) groupInfoPath() string { return filepath.Join(s.DataDir, "group_info.json") }
func (s *Storage) registryPath() string  { return filepath.Join(s.DataDir, "registry.json") }
func (s *Storage) userKeyPath(uid int) string {
	return filepath.Join(s.DataDir, fmt.Sprintf("user_%d_keys.json", uid))
}
func (s *Storage) signaturePath(sigID string) string {
	return filepath.Join(s.DataDir, fmt.Sprintf("sig_%s.json", sigID))
}

// SavePublicParameters saves public parameters
func (s *Storage) SavePublicParameters(pp *lattice.PublicParameters) error {
	return s.SaveJSON(s.ppPath(), pp)
}

// LoadPublicParameters loads public parameters
func (s *Storage) LoadPublicParameters() (*lattice.PublicParameters, error) {
	var pp lattice.PublicParameters
	err := s.LoadJSON(s.ppPath(), &pp)
	return &pp, err
}

// SaveGMKeys saves Group Manager keys
func (s *Storage) SaveGMKeys(mpk *scheme.ManagerPublicKey, msk *scheme.ManagerSecretKey) error {
	data := map[string]interface{}{
		"mpk": mpk,
		"msk": msk,
	}
	return s.SaveJSON(s.gmKeyPath(), data)
}

// LoadGMKeys loads Group Manager keys
func (s *Storage) LoadGMKeys() (*scheme.ManagerPublicKey, *scheme.ManagerSecretKey, error) {
	var data map[string]json.RawMessage
	if err := s.LoadJSON(s.gmKeyPath(), &data); err != nil {
		return nil, nil, err
	}

	var mpk scheme.ManagerPublicKey
	var msk scheme.ManagerSecretKey

	if err := json.Unmarshal(data["mpk"], &mpk); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(data["msk"], &msk); err != nil {
		return nil, nil, err
	}

	return &mpk, &msk, nil
}

// SaveTMKeys saves Tracing Manager keys
func (s *Storage) SaveTMKeys(tpk *scheme.TracingPublicKey, tsk *scheme.TracingSecretKey) error {
	data := map[string]interface{}{
		"tpk": tpk,
		"tsk": tsk,
	}
	return s.SaveJSON(s.tmKeyPath(), data)
}

// LoadTMKeys loads Tracing Manager keys
func (s *Storage) LoadTMKeys() (*scheme.TracingPublicKey, *scheme.TracingSecretKey, error) {
	var data map[string]json.RawMessage
	if err := s.LoadJSON(s.tmKeyPath(), &data); err != nil {
		return nil, nil, err
	}

	var tpk scheme.TracingPublicKey
	var tsk scheme.TracingSecretKey

	if err := json.Unmarshal(data["tpk"], &tpk); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(data["tsk"], &tsk); err != nil {
		return nil, nil, err
	}

	return &tpk, &tsk, nil
}

// SaveGroupInfo saves group information
func (s *Storage) SaveGroupInfo(info *scheme.GroupInfo) error {
	return s.SaveJSON(s.groupInfoPath(), info)
}

// LoadGroupInfo loads group information
func (s *Storage) LoadGroupInfo() (*scheme.GroupInfo, error) {
	var info scheme.GroupInfo
	err := s.LoadJSON(s.groupInfoPath(), &info)
	return &info, err
}

// SaveRegistry saves registration table
func (s *Storage) SaveRegistry(reg *scheme.RegistrationTable) error {
	return s.SaveJSON(s.registryPath(), reg)
}

// LoadRegistry loads registration table
func (s *Storage) LoadRegistry() (*scheme.RegistrationTable, error) {
	var reg scheme.RegistrationTable
	err := s.LoadJSON(s.registryPath(), &reg)
	return &reg, err
}

// SaveUserKeys saves user keys
func (s *Storage) SaveUserKeys(uid int, gsk *scheme.GroupSigningKey) error {
	return s.SaveJSON(s.userKeyPath(uid), gsk)
}

// LoadUserKeys loads user keys
func (s *Storage) LoadUserKeys(uid int) (*scheme.GroupSigningKey, error) {
	var gsk scheme.GroupSigningKey
	err := s.LoadJSON(s.userKeyPath(uid), &gsk)
	return &gsk, err
}

// SaveSignature saves a signature
func (s *Storage) SaveSignature(sigID string, sig *scheme.Signature) error {
	// Write a compact, non-indented encoding for signatures
	// Pack lattice vectors into base64 without Q to reduce size
	pp, err := s.LoadPublicParameters()
	if err != nil {
		return fmt.Errorf("failed to load public parameters: %v", err)
	}

	compact, err := packSignatureCompact(sig, pp.Q)
	if err != nil {
		return fmt.Errorf("failed to pack signature: %v", err)
	}

	path := s.signaturePath(sigID)
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	// No indentation for compact output
	if err := enc.Encode(compact); err != nil {
		return fmt.Errorf("failed to encode signature: %v", err)
	}
	return nil
}

// LoadSignature loads a signature
func (s *Storage) LoadSignature(sigID string) (*scheme.Signature, error) {
	// Load raw JSON to check for required fields
	rawData, err := os.ReadFile(s.signaturePath(sigID))
	if err != nil {
		return nil, err
	}

	// Parse as map to check for Epoch field existence
	var rawSig map[string]interface{}
	if err := json.Unmarshal(rawData, &rawSig); err != nil {
		return nil, err
	}

	// Validate required fields exist
	if _, hasEpoch := rawSig["Epoch"]; !hasEpoch {
		return nil, fmt.Errorf("signature missing required Epoch field")
	}

	// Try compact format first
	var compact signatureCompact
	if err := json.Unmarshal(rawData, &compact); err == nil && compact.Epoch != 0 {
		pp, err := s.LoadPublicParameters()
		if err != nil {
			return nil, fmt.Errorf("failed to load public parameters: %v", err)
		}
		sig, err := unpackSignatureCompact(&compact, pp.Q)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack signature: %v", err)
		}
		return sig, nil
	}

	// Fallback: old verbose JSON format
	var sig scheme.Signature
	if err := json.Unmarshal(rawData, &sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

// BuildGroupPublicKey builds GPK from stored components
func (s *Storage) BuildGroupPublicKey() (*scheme.GroupPublicKey, error) {
	pp, err := s.LoadPublicParameters()
	if err != nil {
		return nil, fmt.Errorf("failed to load public parameters: %v", err)
	}

	mpk, _, err := s.LoadGMKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to load GM keys: %v", err)
	}

	tpk, _, err := s.LoadTMKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to load TM keys: %v", err)
	}

	return &scheme.GroupPublicKey{
		PP:  pp,
		MPK: mpk,
		TPK: tpk,
	}, nil
}

// Helper methods
func (s *Storage) SaveJSON(path string, data interface{}) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %v", err)
	}

	return nil
}

func (s *Storage) LoadJSON(path string, data interface{}) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(data); err != nil {
		return fmt.Errorf("failed to decode JSON: %v", err)
	}

	return nil
}

// Exists checks if a file exists
func (s *Storage) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsInitialized checks if the system is initialized
func (s *Storage) IsInitialized() bool {
	return s.Exists(s.ppPath()) && s.Exists(s.gmKeyPath()) && s.Exists(s.tmKeyPath())
}

// Note: legacy MarshalBigInt helper removed; compact signature encoding used instead

// Compact encoding types for signatures only
type compactVector struct {
	N int    `json:"N"`
	B string `json:"B"` // base64 of concatenated entries, fixed byteLen each
}

type compactCommit struct {
	C1 compactVector `json:"C1"`
	C2 compactVector `json:"C2"`
	C3 compactVector `json:"C3"`
}

type compactProof struct {
	// Drop Challenges: verifier recomputes from FS
	Commitments []compactCommit `json:"Commitments"`
	Responses   []compactVector `json:"Responses"`
}

type signatureCompact struct {
	Epoch      int    `json:"Epoch"`
	Message    []byte `json:"Message"`
	Ciphertext struct {
		C1_U compactVector `json:"C1_U"`
		C1_V compactVector `json:"C1_V"`
		C2_U compactVector `json:"C2_U"`
		C2_V compactVector `json:"C2_V"`
	} `json:"Ciphertext"`
	Proof compactProof `json:"Proof"`
}

func packVector(v *lattice.Vector, q int64) (compactVector, error) {
	if v == nil {
		return compactVector{N: 0, B: ""}, nil
	}
	n := v.Size
	byteLen := 8 // int64 is 8 bytes
	buf := make([]byte, n*byteLen)
	off := 0
	for i := 0; i < n; i++ {
		x := v.Data[i] % q
		if x < 0 {
			x += q
		}
		// Convert int64 to bytes (big-endian)
		binary.BigEndian.PutUint64(buf[off:off+byteLen], uint64(x))
		off += byteLen
	}
	return compactVector{N: n, B: base64.StdEncoding.EncodeToString(buf)}, nil
}

// packVectorRaw packs a vector WITHOUT mod q (for permutation indices)
func packVectorRaw(v *lattice.Vector) (compactVector, error) {
	if v == nil {
		return compactVector{N: 0, B: ""}, nil
	}
	n := v.Size
	// Use 8 bytes per element (int64)
	byteLen := 8
	buf := make([]byte, n*byteLen)
	off := 0
	for i := 0; i < n; i++ {
		x := v.Data[i]
		// Convert int64 to bytes (big-endian)
		binary.BigEndian.PutUint64(buf[off:off+byteLen], uint64(x))
		off += byteLen
	}
	return compactVector{N: n, B: base64.StdEncoding.EncodeToString(buf)}, nil
}

// unpackVectorRaw unpacks without mod q
func unpackVectorRaw(cv compactVector, q int64) (*lattice.Vector, error) {
	if cv.N == 0 {
		return lattice.NewVector(0, q), nil
	}
	raw, err := base64.StdEncoding.DecodeString(cv.B)
	if err != nil {
		return nil, err
	}
	byteLen := 8 // int64 is 8 bytes
	if len(raw) != cv.N*byteLen {
		return nil, fmt.Errorf("invalid compact vector length: expected %d, got %d", cv.N*byteLen, len(raw))
	}
	v := lattice.NewVector(cv.N, q)
	off := 0
	for i := 0; i < cv.N; i++ {
		x := int64(binary.BigEndian.Uint64(raw[off : off+byteLen]))
		// NO mod q here - preserve raw values
		v.Data[i] = x
		off += byteLen
	}
	return v, nil
}

func unpackVector(cv compactVector, q int64) (*lattice.Vector, error) {
	if cv.N == 0 {
		return lattice.NewVector(0, q), nil
	}
	raw, err := base64.StdEncoding.DecodeString(cv.B)
	if err != nil {
		return nil, err
	}
	byteLen := 8 // int64 is 8 bytes
	if len(raw) != cv.N*byteLen {
		return nil, fmt.Errorf("invalid compact vector length")
	}
	v := lattice.NewVector(cv.N, q)
	off := 0
	for i := 0; i < cv.N; i++ {
		x := int64(binary.BigEndian.Uint64(raw[off : off+byteLen]))
		v.Data[i] = x % q
		off += byteLen
	}
	return v, nil
}

func packSignatureCompact(sig *scheme.Signature, q int64) (*signatureCompact, error) {
	out := &signatureCompact{Epoch: sig.Epoch, Message: sig.Message}
	// Ciphertext
	var err error
	out.Ciphertext.C1_U, err = packVector(sig.Ciphertext.C1_U, q)
	if err != nil {
		return nil, err
	}
	out.Ciphertext.C1_V, err = packVector(sig.Ciphertext.C1_V, q)
	if err != nil {
		return nil, err
	}
	out.Ciphertext.C2_U, err = packVector(sig.Ciphertext.C2_U, q)
	if err != nil {
		return nil, err
	}
	out.Ciphertext.C2_V, err = packVector(sig.Ciphertext.C2_V, q)
	if err != nil {
		return nil, err
	}

	// Proof (no Challenges)
	if sig.Proof != nil {
		out.Proof.Commitments = make([]compactCommit, len(sig.Proof.Commitments))
		out.Proof.Responses = make([]compactVector, len(sig.Proof.Responses))
		for i, c := range sig.Proof.Commitments {
			if c == nil {
				continue
			}
			out.Proof.Commitments[i].C1, err = packVector(c.C1, q)
			if err != nil {
				return nil, err
			}
			out.Proof.Commitments[i].C2, err = packVector(c.C2, q)
			if err != nil {
				return nil, err
			}
			out.Proof.Commitments[i].C3, err = packVector(c.C3, q)
			if err != nil {
				return nil, err
			}
		}
		for i, r := range sig.Proof.Responses {
			// Use packVectorRaw for responses (they contain permutation indices, not field elements)
			out.Proof.Responses[i], err = packVectorRaw(r)
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func unpackSignatureCompact(sc *signatureCompact, q int64) (*scheme.Signature, error) {
	sig := &scheme.Signature{Epoch: sc.Epoch, Message: sc.Message}
	// Ciphertext
	ct := &scheme.Ciphertext{}
	var err error
	ct.C1_U, err = unpackVector(sc.Ciphertext.C1_U, q)
	if err != nil {
		return nil, err
	}
	ct.C1_V, err = unpackVector(sc.Ciphertext.C1_V, q)
	if err != nil {
		return nil, err
	}
	ct.C2_U, err = unpackVector(sc.Ciphertext.C2_U, q)
	if err != nil {
		return nil, err
	}
	ct.C2_V, err = unpackVector(sc.Ciphertext.C2_V, q)
	if err != nil {
		return nil, err
	}
	sig.Ciphertext = ct

	// Proof (no Challenges stored)
	pr := &nizk.ZKProof{}
	pr.Commitments = make([]*nizk.CommitmentTriple, len(sc.Proof.Commitments))
	pr.Responses = make([]*lattice.Vector, len(sc.Proof.Responses))
	for i, cc := range sc.Proof.Commitments {
		c1, err := unpackVector(cc.C1, q)
		if err != nil {
			return nil, err
		}
		c2, err := unpackVector(cc.C2, q)
		if err != nil {
			return nil, err
		}
		c3, err := unpackVector(cc.C3, q)
		if err != nil {
			return nil, err
		}
		pr.Commitments[i] = &nizk.CommitmentTriple{C1: c1, C2: c2, C3: c3}
	}
	for i, rv := range sc.Proof.Responses {
		// Use unpackVectorRaw for responses (they contain permutation indices)
		pr.Responses[i], err = unpackVectorRaw(rv, q)
		if err != nil {
			return nil, err
		}
	}
	sig.Proof = pr
	return sig, nil
}
