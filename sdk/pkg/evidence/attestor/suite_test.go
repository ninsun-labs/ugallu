// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

var (
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
	scheme    = runtime.NewScheme()
)

// TestMain bootstraps the envtest control plane before any test runs and
// tears it down after. The KUBEBUILDER_ASSETS env var (set by the
// setup-envtest tool or by the Makefile/Taskfile) points to the
// kube-apiserver + etcd binaries.
func TestMain(m *testing.M) {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))

	// CRDs live four directories up at <repo>/crds/bases relative to this
	// test file: sdk/pkg/evidence/attestor -> ../../../.. -> repo root.
	crdPath := filepath.Join("..", "..", "..", "..", "crds", "bases")

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{crdPath},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	cfg, err = testEnv.Start()
	if err != nil {
		// In CI we require envtest to be set up: a silent skip would hide
		// reconciler regressions. GitHub Actions sets CI=true automatically.
		// In local dev without `task envtest:assets`, degrade gracefully.
		if os.Getenv("CI") == "" && os.Getenv("KUBEBUILDER_ASSETS") == "" {
			println("[envtest] KUBEBUILDER_ASSETS not set and CI is unset; skipping reconciler suite. Run `task envtest:assets` first.")
			os.Exit(0)
		}
		panic(err)
	}

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		_ = testEnv.Stop()
		panic(err)
	}

	code := m.Run()

	_ = testEnv.Stop()
	os.Exit(code)
}

// ctxT returns a fresh background context plus a per-test timeout.
func ctxT() context.Context {
	return context.Background()
}
