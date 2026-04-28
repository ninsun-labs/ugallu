// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package auditdetection_test

import (
	"testing"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection"
)

func TestSetupController_RejectsBadOpts(t *testing.T) {
	cases := []struct {
		name string
		opts *auditdetection.Options
	}{
		{"nil", nil},
		{"missing Emitter", &auditdetection.Options{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := auditdetection.SetupController(nil, tc.opts); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}
