// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor_test

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
	envCfg    *rest.Config
	envClient client.Client
	envScheme = runtime.NewScheme()
)

// TestMain bootstraps the envtest control plane. The integration
// tests (TestIntegration_*) skip when KUBEBUILDER_ASSETS is unset
// outside CI, so the unit-only suite still passes locally without
// `task envtest:assets`.
func TestMain(m *testing.M) {
	utilruntime.Must(clientgoscheme.AddToScheme(envScheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(envScheme))

	// Repo root is four levels up from this package
	// (operators/webhook-auditor/pkg/webhookauditor).
	crdPath := filepath.Join("..", "..", "..", "..", "crds", "bases")

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{crdPath},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		if os.Getenv("CI") == "" && os.Getenv("KUBEBUILDER_ASSETS") == "" {
			println("[envtest] KUBEBUILDER_ASSETS not set and CI is unset; integration suite will skip. Run `task envtest:assets` to enable.")
			os.Exit(m.Run())
		}
		panic(err)
	}
	envCfg = cfg

	envClient, err = client.New(envCfg, client.Options{Scheme: envScheme})
	if err != nil {
		_ = testEnv.Stop()
		panic(err)
	}

	code := m.Run()

	_ = testEnv.Stop()
	os.Exit(code)
}

func envCtx() context.Context { return context.Background() }
