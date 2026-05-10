import type { RunListResponse } from '$lib/api/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, url }) => {
	const search = new URLSearchParams();
	const ns = url.searchParams.get('namespace');
	const kind = url.searchParams.get('kind');
	const phase = url.searchParams.get('phase');
	if (ns) search.set('namespace', ns);
	if (kind) search.set('kind', kind);
	if (phase) search.set('phase', phase);

	const res = await fetch(`/api/v1/runs?${search.toString()}`, { credentials: 'include' });
	if (!res.ok) {
		const empty: RunListResponse = { items: [] };
		return { runs: empty, error: `HTTP ${res.status}` as const, kind, phase };
	}
	const runs = (await res.json()) as RunListResponse;
	return { runs, error: null as string | null, kind, phase };
};
