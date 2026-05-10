import type { ConfigDetailResponse, ConfigKind } from '$lib/api/types';
import type { PageLoad } from './$types';

// Cluster-scoped configs are routed with `_` as the namespace
// placeholder. The BFF accepts both 2-segment (cluster-scoped) and
// 3-segment (namespaced) URLs; we translate accordingly here.
export const load: PageLoad = async ({ fetch, params }) => {
	const ns = params.namespace === '_' ? '' : params.namespace;
	const path =
		ns === ''
			? `/api/v1/configurations/${encodeURIComponent(params.kind)}/${encodeURIComponent(params.name)}`
			: `/api/v1/configurations/${encodeURIComponent(params.kind)}/${encodeURIComponent(ns)}/${encodeURIComponent(params.name)}`;

	const res = await fetch(path, { credentials: 'include' });
	if (!res.ok) {
		return {
			detail: null,
			error: `HTTP ${res.status}`,
			kind: params.kind as ConfigKind,
			name: params.name,
			namespace: ns
		};
	}
	const detail = (await res.json()) as ConfigDetailResponse;
	return {
		detail,
		error: null as string | null,
		kind: params.kind as ConfigKind,
		name: params.name,
		namespace: ns
	};
};
