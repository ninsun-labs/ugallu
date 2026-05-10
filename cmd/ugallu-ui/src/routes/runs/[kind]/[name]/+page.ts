import type { RunDetailResponse, RunKind } from '$lib/api/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, params, url }) => {
	const ns = url.searchParams.get('namespace') ?? '';
	if (!ns) {
		return {
			detail: null,
			error: 'namespace is required as a query parameter',
			kind: params.kind as RunKind,
			name: params.name,
			namespace: ns
		};
	}
	const res = await fetch(
		`/api/v1/runs/${encodeURIComponent(params.kind)}/${encodeURIComponent(ns)}/${encodeURIComponent(params.name)}`,
		{ credentials: 'include' }
	);
	if (!res.ok) {
		return {
			detail: null,
			error: `HTTP ${res.status}`,
			kind: params.kind as RunKind,
			name: params.name,
			namespace: ns
		};
	}
	const detail = (await res.json()) as RunDetailResponse;
	return { detail, error: null as string | null, kind: params.kind as RunKind, name: params.name, namespace: ns };
};
