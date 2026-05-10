import type { ConfigListResponse } from '$lib/api/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, url }) => {
	const search = new URLSearchParams();
	const kind = url.searchParams.get('kind');
	if (kind) search.set('kind', kind);

	const res = await fetch(`/api/v1/configurations?${search.toString()}`, {
		credentials: 'include'
	});
	if (!res.ok) {
		const empty: ConfigListResponse = { items: [] };
		return { configs: empty, error: `HTTP ${res.status}`, kind };
	}
	const configs = (await res.json()) as ConfigListResponse;
	return { configs, error: null as string | null, kind };
};
