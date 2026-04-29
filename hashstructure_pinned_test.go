package hashstructure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// TestHash_pinned locks in the exact sha256 hex digest produced by Hash for
// every supported Go kind, the time.Time special case, and each option that
// alters output (FormatV1/V2, SlicesAsSets, ZeroNil, IgnoreZeroValue,
// UseStringer, and the hash struct tags).
//
// IMPORTANT: the expected hash values below MUST NOT be changed. Downstream
// consumers (e.g. the ingester duplicate-detection path) persist these hashes
// in long-lived storage; any algorithm change silently invalidates lookups
// against existing records. If a future change makes this test fail, the fix
// belongs in hashstructure (or reverting the offending change), not in
// updating the expected values here.
func TestHash_pinned(t *testing.T) {
	type pointStruct struct {
		X int
		Y int
	}
	type taggedStruct struct {
		Keep   string
		Ignore string `hash:"ignore"`
		Dash   string `hash:"-"`
	}
	type setStruct struct {
		Items []string `hash:"set"`
	}
	type stringerStruct struct {
		When stringerTime `hash:"string"`
	}
	type nestedStruct struct {
		Name  string
		Point pointStruct
		Tags  []string
	}

	fixedTime := time.Date(2024, 1, 2, 3, 4, 5, 6, time.UTC)
	plusTwoZone := time.FixedZone("UTC+2", 2*60*60)
	zonedTime := time.Date(2024, 1, 2, 3, 4, 5, 6, plusTwoZone)

	// MarshalBinary rejects a -1 minute offset because -1 (in minutes)
	// collides with the UTC sentinel; hashstructure must fall back to UTC.
	negOneMinZone := time.FixedZone("", -60)
	negOneMinTime := time.Date(2024, 1, 2, 3, 4, 5, 6, negOneMinZone)
	// MarshalBinary also rejects a sub-minute offset where seconds!=0 and the
	// minute count rounds to -1.
	negNinetySecZone := time.FixedZone("", -90)
	negNinetySecTime := time.Date(2024, 1, 2, 3, 4, 5, 6, negNinetySecZone)

	intPtrVal := 42
	strPtrVal := "ptr"

	tests := []struct {
		name     string
		value    interface{}
		opts     *HashOptions
		format   Format
		expected string
	}{
		{
			name:     "nil",
			value:    nil,
			expected: "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc",
		},
		{
			name:     "string empty",
			value:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "string ascii",
			value:    "hello",
			expected: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:     "string unicode",
			value:    "héllo 世界",
			expected: "41fdd4962650507e535fde55a87df81f9d8a7e12e5663ac3012caaa20432f621",
		},
		{
			name:     "bool true",
			value:    true,
			expected: "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
		},
		{
			name:     "bool false",
			value:    false,
			expected: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		},
		{
			name:     "int zero",
			value:    int(0),
			expected: "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc",
		},
		{
			name:     "int positive",
			value:    int(123456789),
			expected: "03e7fb02cbc33eb45e98ab50b4bcad7fc338e5edfb5eca33ad9eb7d13d4ff106",
		},
		{
			name:     "int negative",
			value:    int(-987654321),
			expected: "4e42568dfa96440a5df9b0f0b6689424d099e4db0bc1a9aedec46f3b756612ce",
		},
		{
			name:     "int8",
			value:    int8(-12),
			expected: "2017ff3461395672aa0aa4f64894fd2f95a4b120e2690e8951656d79adc2eed2",
		},
		{
			name:     "int16",
			value:    int16(-1234),
			expected: "fdd9d82961edf686f5cb6014140fbd228fa2f45aa4e2f57233b14b2fa114d471",
		},
		{
			name:     "int32",
			value:    int32(-1234567),
			expected: "8ad6d84ddaf13d4a2410d4536c947df7e80d440c61489150dfd13add2a676f51",
		},
		{
			name:     "int64",
			value:    int64(-1234567890123),
			expected: "f7444af1c452e81132cbc2ffe3dbf100e0c9423d8923814e894b983c0c4bcc7b",
		},
		{
			name:     "uint",
			value:    uint(123),
			expected: "4f319987a786107dc63b2b70115b3734cb9880b099b70c463c5e1b05521ab764",
		},
		{
			name:     "uint8",
			value:    uint8(255),
			expected: "a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89",
		},
		{
			name:     "uint16",
			value:    uint16(65535),
			expected: "ca2fd00fa001190744c15c317643ab092e7048ce086a243e2be9437c898de1bb",
		},
		{
			name:     "uint32",
			value:    uint32(4294967295),
			expected: "ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e",
		},
		{
			name:     "uint64",
			value:    uint64(18446744073709551615),
			expected: "12a3ae445661ce5dee78d0650d33362dec29c4f82af05e7e57fb595bbbacf0ca",
		},
		{
			name:     "float32",
			value:    float32(3.14159),
			expected: "422dbf129e15e0ce0370016560c39bb9439eb085fa8ffdb2192a7a8b37710cbc",
		},
		{
			name:     "float64",
			value:    float64(2.7182818284590452),
			expected: "b084f39eda8626830f0da93e237409eadcb6558d500c155a438c4dba38d4ba98",
		},
		{
			name:     "complex64",
			value:    complex64(complex(1.5, -2.5)),
			expected: "63962ae680fb4f1041e7917b77a748e82ed8be7b3be0e797c270dd43944e5372",
		},
		{
			name:     "array of int",
			value:    [3]int{1, 2, 3},
			expected: "cd7aec39c5e7aed03d0830c9e6116263625a6a2b52fd2030b1c094f1b62d006b",
		},
		{
			name:     "slice of string",
			value:    []string{"a", "b", "c"},
			expected: "c78843fc45040e6a5b9474708ebefbe58a7c8082e2b87d2edc3cc39625a85556",
		},
		{
			name:     "slice of string reversed",
			value:    []string{"c", "b", "a"},
			expected: "73a8f2c482236ae586476484ec730422c8c7ed3a8d02d413ed9d6a1aa7d49d1c",
		},
		{
			name:     "empty slice",
			value:    []string{},
			expected: "",
		},
		{
			name:     "nil slice",
			value:    []string(nil),
			expected: "",
		},
		{
			name:     "map string to int",
			value:    map[string]int{"a": 1, "b": 2, "c": 3},
			expected: "e9d928a931bbe26b68579d8ea23ac0b0e2af5ef3b8fcf2de3b6e862aaf2e856f",
		},
		{
			name:     "empty map",
			value:    map[string]int{},
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "struct simple",
			value:    pointStruct{X: 7, Y: -3},
			expected: "ca8436440d006ea356ece7e94279fdc9aa62b091da58bb5366600164c36ad60f",
		},
		{
			name:     "struct zero value",
			value:    pointStruct{},
			expected: "abf96e42345442f07aad735d2eef2e873c82aac5fc054218532b2cb05469a173",
		},
		{
			name:     "struct pointer",
			value:    &pointStruct{X: 7, Y: -3},
			expected: "ca8436440d006ea356ece7e94279fdc9aa62b091da58bb5366600164c36ad60f",
		},
		{
			name:     "nested struct",
			value:    nestedStruct{Name: "n", Point: pointStruct{X: 1, Y: 2}, Tags: []string{"t1", "t2"}},
			expected: "3b9a0fd7bbd781ee15739a710b26140c21bdab701f15ec59259c1e4b45231bbc",
		},
		{
			name:     "pointer to int",
			value:    &intPtrVal,
			expected: "ed049108bc18f2c64369e8d0ea42850bdd1a7d1dd340cfde716315579702a76c",
		},
		{
			name:     "pointer to string",
			value:    &strPtrVal,
			expected: "83dbef1f3d2293d865bb05f5ca0839e309e5caf4b98daac8e383d6bb3f8f424b",
		},
		{
			name:     "interface holding string",
			value:    []interface{}{"a", 1, true},
			expected: "19a0172d8eac85c98e8c5a063d138955b84a4057a819ac463cced97d1ad9a6f8",
		},
		{
			name:     "time UTC",
			value:    fixedTime,
			expected: "5f9fd9a97a8bf655d6058a28afe82d411725bd3fd1690320a52349932cdef902",
		},
		{
			name:     "time UTC zero",
			value:    time.Time{},
			expected: "a4b59569bdbd1c86378514858ca37d44908b561451872889aa62fa05324b329f",
		},
		{
			name:     "time fixed zone +2",
			value:    zonedTime,
			expected: "ba55d6c2c884191bcd874672462337448fe225c4cc1a0912d28a98b6b8c982a9",
		},
		{
			// MarshalBinary errors on this offset; library must fall back
			// to UTC. Hash equals the same instant in UTC.
			name:     "time fixed zone -1 minute (MarshalBinary fallback)",
			value:    negOneMinTime,
			expected: "809012599f29245f2a7d617b4332d875af7709926b586e51e8849e3b628d53e0",
		},
		{
			name:     "time fixed zone -1 minute matches UTC equivalent",
			value:    negOneMinTime.UTC(),
			expected: "809012599f29245f2a7d617b4332d875af7709926b586e51e8849e3b628d53e0",
		},
		{
			name:     "time fixed zone -90 seconds (MarshalBinary fallback)",
			value:    negNinetySecTime,
			expected: "20b31e98141d14e1ca1da0bb488c59ce66cc2d663c5bfba1afa4c75d4ac17f3b",
		},
		{
			name:     "time fixed zone -90 seconds matches UTC equivalent",
			value:    negNinetySecTime.UTC(),
			expected: "20b31e98141d14e1ca1da0bb488c59ce66cc2d663c5bfba1afa4c75d4ac17f3b",
		},
		{
			name:     "tag ignore",
			value:    taggedStruct{Keep: "k", Ignore: "should-not-affect", Dash: "also-not"},
			expected: "0f94028412384e1478cd35088549820bd6699110f76f6d53efe761deabb9d2ea",
		},
		{
			name:     "tag set: same elements different order hash equal",
			value:    setStruct{Items: []string{"a", "b", "c"}},
			expected: "4793885fc6f8f253128c2547325fc2f7cbd84ad165d5df7828b996d64c56f89d",
		},
		{
			name:     "tag set: reversed",
			value:    setStruct{Items: []string{"c", "b", "a"}},
			expected: "4793885fc6f8f253128c2547325fc2f7cbd84ad165d5df7828b996d64c56f89d",
		},
		{
			name:     "tag string with stringer",
			value:    stringerStruct{When: stringerTime{T: fixedTime}},
			expected: "cc6e0e13e5f0a96a7eb84fedb13b9d623b37f0d6679e3e348453900e14af5890",
		},
		{
			name:     "option SlicesAsSets",
			value:    []string{"a", "b", "c"},
			opts:     &HashOptions{SlicesAsSets: true},
			expected: "dac9450763729e62aca78b63cbaae8dc1fa837fa018c71aceb81fc8ad828a7e0",
		},
		{
			name:     "option SlicesAsSets reversed",
			value:    []string{"c", "b", "a"},
			opts:     &HashOptions{SlicesAsSets: true},
			expected: "dac9450763729e62aca78b63cbaae8dc1fa837fa018c71aceb81fc8ad828a7e0",
		},
		{
			name:     "option ZeroNil",
			value:    (*int)(nil),
			opts:     &HashOptions{ZeroNil: true},
			expected: "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc",
		},
		{
			name:     "option IgnoreZeroValue",
			value:    pointStruct{X: 0, Y: 5},
			opts:     &HashOptions{IgnoreZeroValue: true},
			expected: "26d45172253953b476cd8ed94ddeb18b61332af2d180a2f6b2236ddf3bb4dfb6",
		},
		{
			name:     "option UseStringer",
			value:    stringerHolder{T: fixedTime},
			opts:     &HashOptions{UseStringer: true},
			expected: "dc86ab5fb51b449d693af137183f20123cd34843790e6cb14fd15eb99c1605ad",
		},
		{
			name:     "FormatV1 string",
			value:    "hello",
			format:   FormatV1,
			expected: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:     "FormatV1 struct",
			value:    pointStruct{X: 7, Y: -3},
			format:   FormatV1,
			expected: "508ce2f1f0e049c93fe87daaea15c4e9293ee7d33b876ab796dae645e24f17a8",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			format := tc.format
			if format == 0 {
				format = FormatV2
			}
			opts := tc.opts
			if opts == nil {
				opts = &HashOptions{}
			}
			opts.Hasher = sha256.New()

			raw, err := Hash(tc.value, format, opts)
			if err != nil {
				t.Fatalf("Hash returned error: %v", err)
			}
			got := hex.EncodeToString(raw)
			if got != tc.expected {
				t.Errorf("hash for %q changed - do not update this expected value, fix the change in hashstructure instead\n  got:      %s\n  expected: %s", tc.name, got, tc.expected)
			}

			// Hashing again must return the same digest.
			opts.Hasher = sha256.New()
			raw2, err := Hash(tc.value, format, opts)
			if err != nil {
				t.Fatalf("Hash returned error on repeat: %v", err)
			}
			got2 := hex.EncodeToString(raw2)
			if got2 != got {
				t.Errorf("hash not deterministic for %q: %s vs %s", tc.name, got, got2)
			}
		})
	}
}

type stringerTime struct {
	T time.Time
}

func (s stringerTime) String() string {
	return fmt.Sprintf("stringerTime(%d)", s.T.UnixNano())
}

type stringerHolder struct {
	T time.Time
}

func (s stringerHolder) String() string {
	return fmt.Sprintf("stringerHolder(%d)", s.T.UnixNano())
}
