package hashstructure

import (
	"crypto/sha256"
	"fmt"
)

func ExampleHash() {
	type ComplexStruct struct {
		Name     string
		Age      uint
		Metadata map[string]interface{}
	}

	v := ComplexStruct{
		Name: "mitchellh",
		Age:  64,
		Metadata: map[string]interface{}{
			"car":      true,
			"location": "California",
			"siblings": []string{"Bob", "John"},
		},
	}

	hasher := sha256.New()
	_, err := Hash(v, FormatV2, &HashOptions{Hasher: hasher})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%d", hasher.Sum(nil))
	// Output:
	// [59 211 209 211 148 28 150 169 196 203 223 172 124 19 44 68 61 179 84 224 195 75 194 37 64 184 169 150 146 17 214 37]
}

func ExampleHash_v1() {
	type ComplexStruct struct {
		Name     string
		Age      uint
		Metadata map[string]interface{}
	}

	v := ComplexStruct{
		Name: "mitchellh",
		Age:  64,
		Metadata: map[string]interface{}{
			"car":      true,
			"location": "California",
			"siblings": []string{"Bob", "John"},
		},
	}

	hash, err := Hash(v, FormatV1, nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%d", hash)
	// Output:
	// [8 54 108 169 168 105 61 236]
}
