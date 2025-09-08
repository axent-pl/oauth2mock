package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	dec := yaml.NewDecoder(os.Stdin)

	var docs []any
	for {
		var v any
		if err := dec.Decode(&v); err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "yaml decode error: %v\n", err)
			os.Exit(1)
		}
		docs = append(docs, toJSONable(v))
	}

	if len(docs) == 0 {
		// no input; emit JSON null
		fmt.Println("null")
		return
	}

	var out []byte
	var err error
	if len(docs) == 1 {
		out, err = json.Marshal(docs[0])
	} else {
		out, err = json.Marshal(docs)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "json marshal error: %v\n", err)
		os.Exit(1)
	}

	if _, err := os.Stdout.Write(append(out, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "stdout write error: %v\n", err)
		os.Exit(1)
	}
}

func toJSONable(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, vv := range x {
			m[k] = toJSONable(vv)
		}
		return m
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, vv := range x {
			m[fmt.Sprint(k)] = toJSONable(vv)
		}
		return m
	case []any:
		for i := range x {
			x[i] = toJSONable(x[i])
		}
		return x
	default:
		return x
	}
}
