// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics_test

import (
	"testing"

	"github.com/ninsun-labs/ugallu/operators/forensics/pkg/forensics"
)

func TestSetupController_RejectsBadOpts(t *testing.T) {
	cases := []struct {
		name string
		opts *forensics.Options
	}{
		{"nil", nil},
		{"missing Emitter", &forensics.Options{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := forensics.SetupController(nil, tc.opts); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}
