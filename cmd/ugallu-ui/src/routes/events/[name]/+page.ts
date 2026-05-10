import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, params, url }) => {
	const ns = url.searchParams.get('namespace') ?? '';
	const search = ns ? `?namespace=${encodeURIComponent(ns)}` : '';
	const res = await fetch(
		`/api/v1/events/${encodeURIComponent(params.name)}${search}`,
		{ credentials: 'include' }
	);
	if (!res.ok) {
		return { event: null, error: `HTTP ${res.status}`, name: params.name, namespace: ns };
	}
	const event = (await res.json()) as Record<string, unknown>;
	return { event, error: null as string | null, name: params.name, namespace: ns };
};
