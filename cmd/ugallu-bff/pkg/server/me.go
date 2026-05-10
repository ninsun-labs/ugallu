// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
)

// MeResponse is the payload returned by GET /api/v1/me. It carries
// the OIDC subject + groups plus a small platform header so the SPA
// can identify which BFF version it is talking to.
type MeResponse struct {
	Sub        string   `json:"sub"`
	Email      string   `json:"email,omitempty"`
	Name       string   `json:"name,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	BFFVersion string   `json:"bffVersion"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, ok := SessionFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "no session")
		return
	}
	s.writeJSON(w, http.StatusOK, MeResponse{
		Sub:        sess.Sub,
		Email:      sess.Email,
		Name:       sess.Name,
		Groups:     sess.Groups,
		BFFVersion: s.opts.Version,
	})
}
