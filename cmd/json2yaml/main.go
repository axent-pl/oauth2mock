package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read error: %v\n", err)
		os.Exit(1)
	}

	// Try to unmarshal as an array of docs first, fallback to single
	var arr []any
	if err := json.Unmarshal(data, &arr); err == nil {
		for i, doc := range arr {
			if i > 0 {
				fmt.Println("---")
			}
			if err := yaml.NewEncoder(os.Stdout).Encode(doc); err != nil {
				fmt.Fprintf(os.Stderr, "yaml encode error: %v\n", err)
				os.Exit(1)
			}
		}
		return
	}

	// Not an array → single doc
	var obj any
	if err := json.Unmarshal(data, &obj); err != nil {
		fmt.Fprintf(os.Stderr, "json unmarshal error: %v\n", err)
		os.Exit(1)
	}
	if err := yaml.NewEncoder(os.Stdout).Encode(obj); err != nil {
		fmt.Fprintf(os.Stderr, "yaml encode error: %v\n", err)
		os.Exit(1)
	}
}
