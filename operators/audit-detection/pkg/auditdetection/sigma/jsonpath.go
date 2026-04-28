// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidJSONPath is returned when the lexer rejects a JSONPath
// expression at compile time.
var ErrInvalidJSONPath = errors.New("sigma: invalid JSONPath")

// jsonPathStep is one element of the parsed path.
type jsonPathStep struct {
	// One of:
	//   field:   step.field == "<name>"
	//   wildcard step:    step.wildcard == true (matches every map key
	//                     or array index)
	//   index:   step.index >= 0 (array indexing)
	field    string
	wildcard bool
	index    int
}

// compileJSONPath parses a restricted subset of JSONPath:
//
//	$.a.b.c                 dotted field access
//	$.a[0].b                indexed access
//	$.a[*].b                wildcard array/map walk
//	$.a['x'].b              bracketed-string key (handles dotted keys)
//
// Anything else (filters, slices, recursive descent `..`) is
// rejected. CEL admission policy 6 enforces the same subset at
// apply-time; this is the runtime safety net.
func compileJSONPath(expr string) ([]jsonPathStep, error) {
	if expr == "" || expr[0] != '$' {
		return nil, fmt.Errorf("%w: must start with $", ErrInvalidJSONPath)
	}
	rest := expr[1:]
	var steps []jsonPathStep
	for rest != "" {
		switch rest[0] {
		case '.':
			rest = rest[1:]
			end := indexAny(rest, ".[")
			if end < 0 {
				end = len(rest)
			}
			name := rest[:end]
			if name == "" {
				return nil, fmt.Errorf("%w: empty field after dot", ErrInvalidJSONPath)
			}
			if name == "*" {
				steps = append(steps, jsonPathStep{wildcard: true})
			} else {
				steps = append(steps, jsonPathStep{field: name})
			}
			rest = rest[end:]
		case '[':
			closing := strings.IndexByte(rest, ']')
			if closing < 0 {
				return nil, fmt.Errorf("%w: missing ]", ErrInvalidJSONPath)
			}
			inner := rest[1:closing]
			switch {
			case inner == "*":
				steps = append(steps, jsonPathStep{wildcard: true})
			case len(inner) >= 2 && inner[0] == '\'' && inner[len(inner)-1] == '\'':
				steps = append(steps, jsonPathStep{field: inner[1 : len(inner)-1]})
			default:
				idx, err := strconv.Atoi(inner)
				if err != nil || idx < 0 {
					return nil, fmt.Errorf("%w: bracket %q is neither '*', a quoted key, nor a non-negative index", ErrInvalidJSONPath, inner)
				}
				steps = append(steps, jsonPathStep{index: idx})
			}
			rest = rest[closing+1:]
		default:
			return nil, fmt.Errorf("%w: unexpected %q", ErrInvalidJSONPath, rest[:1])
		}
	}
	return steps, nil
}

// indexAny is strings.IndexAny but inlined to keep compileJSONPath
// allocation-free and readable.
func indexAny(s, chars string) int {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(chars, s[i]) >= 0 {
			return i
		}
	}
	return -1
}

// evalJSONPath walks doc following the compiled steps and returns
// every leaf string value the path resolves to. Non-string leaves
// (numbers, bools, structs) are stringified via fmt.Sprint so the
// glob matcher gets something sensible to compare. nil leaves are
// skipped.
func evalJSONPath(doc map[string]any, steps []jsonPathStep) []string {
	if doc == nil {
		return nil
	}
	current := []any{doc}
	for _, step := range steps {
		next := current[:0]
		for _, node := range current {
			next = stepInto(node, step, next)
		}
		current = next
		if len(current) == 0 {
			return nil
		}
	}
	out := make([]string, 0, len(current))
	for _, leaf := range current {
		if leaf == nil {
			continue
		}
		switch v := leaf.(type) {
		case string:
			out = append(out, v)
		case bool, float64, int, int64, uint64:
			out = append(out, fmt.Sprint(v))
		default:
			out = append(out, fmt.Sprint(v))
		}
	}
	return out
}

// stepInto applies one path step to node and appends every match to
// dst. Both maps (object access via field name or wildcard) and
// arrays (index, wildcard) are supported.
func stepInto(node any, step jsonPathStep, dst []any) []any {
	switch n := node.(type) {
	case map[string]any:
		switch {
		case step.wildcard:
			for _, v := range n {
				dst = append(dst, v)
			}
		case step.field != "":
			if v, ok := n[step.field]; ok {
				dst = append(dst, v)
			}
		}
	case []any:
		switch {
		case step.wildcard:
			dst = append(dst, n...)
		case step.field == "" && step.index >= 0 && step.index < len(n):
			dst = append(dst, n[step.index])
		}
	}
	return dst
}
