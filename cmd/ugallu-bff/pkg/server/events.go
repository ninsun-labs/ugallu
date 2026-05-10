// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// EventListResponse is the shape returned by GET /api/v1/events.
type EventListResponse struct {
	Items      []EventSummary `json:"items"`
	Generation string         `json:"generation"`
	Continue   string         `json:"continue,omitempty"`
}

// EventSummary is the short SE projection used in the list view.
type EventSummary struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               string            `json:"uid"`
	CreationTimestamp string            `json:"creationTimestamp"`
	Type              string            `json:"type"`
	Class             string            `json:"class"`
	Severity          string            `json:"severity"`
	Subject           EventSubject      `json:"subject"`
	Source            EventSource       `json:"source"`
	Phase             string            `json:"phase,omitempty"`
	CorrelationID     string            `json:"correlationID,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

type EventSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	UID       string `json:"uid,omitempty"`
}

// EventSource is a flattened SourceRef + ClusterIdentity for the
// list view. The full SourceRef + ClusterIdentity travel on the
// detail response (the raw SE).
type EventSource struct {
	Kind        string `json:"kind,omitempty"`
	Name        string `json:"name,omitempty"`
	Instance    string `json:"instance,omitempty"`
	ClusterName string `json:"clusterName,omitempty"`
	ClusterID   string `json:"clusterID,omitempty"`
}

const defaultEventLimit = 50
const maxEventLimit = 200

func (s *Server) handleEventsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := defaultEventLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			s.writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be a positive integer")
			return
		}
		if n > maxEventLimit {
			n = maxEventLimit
		}
		limit = n
	}

	listOpts := []client.ListOption{
		client.Limit(int64(limit)),
	}
	if c := q.Get("continue"); c != "" {
		listOpts = append(listOpts, client.Continue(c))
	}
	if ns := q.Get("namespace"); ns != "" {
		listOpts = append(listOpts, client.InNamespace(ns))
	}
	if sel := buildEventSelector(q); sel != nil {
		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: sel})
	}

	var raw securityv1alpha1.SecurityEventList
	if err := s.opts.K8sClient.List(r.Context(), &raw, listOpts...); err != nil {
		s.opts.Logger.Warn("list events", "err", err)
		s.writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}

	resp := EventListResponse{
		Items:      make([]EventSummary, 0, len(raw.Items)),
		Generation: raw.ResourceVersion,
		Continue:   raw.Continue,
	}
	for i := range raw.Items {
		// Apply post-list filters that aren't expressible as label
		// selectors (class, type, severity live on spec, not labels).
		if !matchesSpecFilter(&raw.Items[i], q) {
			continue
		}
		resp.Items = append(resp.Items, summariseEvent(&raw.Items[i]))
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleEventGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		s.writeError(w, http.StatusBadRequest, "missing_name", "event name is required")
		return
	}
	ns := r.URL.Query().Get("namespace")

	var ev securityv1alpha1.SecurityEvent
	err := s.opts.K8sClient.Get(r.Context(), types.NamespacedName{Namespace: ns, Name: name}, &ev)
	if errors.IsNotFound(err) {
		s.writeError(w, http.StatusNotFound, "not_found", "no SecurityEvent named "+name)
		return
	}
	if err != nil {
		s.opts.Logger.Warn("get event", "name", name, "err", err)
		s.writeError(w, http.StatusInternalServerError, "get_failed", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, ev)
}

// buildEventSelector parses the `labelSelector` query param into a
// k8s label selector. Returns nil if the param is absent.
func buildEventSelector(q map[string][]string) labels.Selector {
	v := q["labelSelector"]
	if len(v) == 0 || v[0] == "" {
		return nil
	}
	sel, err := labels.Parse(v[0])
	if err != nil {
		return nil
	}
	return sel
}

func matchesSpecFilter(e *securityv1alpha1.SecurityEvent, q map[string][]string) bool {
	if vs := q["class"]; len(vs) > 0 && vs[0] != "" && string(e.Spec.Class) != vs[0] {
		return false
	}
	if vs := q["type"]; len(vs) > 0 && vs[0] != "" && e.Spec.Type != vs[0] {
		return false
	}
	if vs := q["severity"]; len(vs) > 0 && vs[0] != "" && string(e.Spec.Severity) != vs[0] {
		return false
	}
	if vs := q["subjectKind"]; len(vs) > 0 && vs[0] != "" && string(e.Spec.Subject.Kind) != vs[0] {
		return false
	}
	if vs := q["q"]; len(vs) > 0 && vs[0] != "" {
		needle := strings.ToLower(vs[0])
		// Free-text matches the SE name + the Type + any Signals
		// values (Spec has no description field; signals carry the
		// human-readable bits).
		hay := strings.ToLower(e.Name + " " + e.Spec.Type)
		for _, v := range e.Spec.Signals {
			hay += " " + strings.ToLower(v)
		}
		if !strings.Contains(hay, needle) {
			return false
		}
	}
	return true
}

func summariseEvent(e *securityv1alpha1.SecurityEvent) EventSummary {
	creation := ""
	if !e.CreationTimestamp.IsZero() {
		creation = e.CreationTimestamp.UTC().Format(time.RFC3339)
	}
	return EventSummary{
		Name:              e.Name,
		Namespace:         e.Namespace,
		UID:               string(e.UID),
		CreationTimestamp: creation,
		Type:              e.Spec.Type,
		Class:             string(e.Spec.Class),
		Severity:          string(e.Spec.Severity),
		Subject: EventSubject{
			Kind:      string(e.Spec.Subject.Kind),
			Name:      e.Spec.Subject.Name,
			Namespace: e.Spec.Subject.Namespace,
			UID:       string(e.Spec.Subject.UID),
		},
		Source: EventSource{
			Kind:        e.Spec.Source.Kind,
			Name:        e.Spec.Source.Name,
			Instance:    e.Spec.Source.Instance,
			ClusterName: e.Spec.ClusterIdentity.ClusterName,
			ClusterID:   e.Spec.ClusterIdentity.ClusterID,
		},
		Phase:         string(e.Status.Phase),
		CorrelationID: e.Spec.CorrelationID,
		Labels:        e.Labels,
	}
}
