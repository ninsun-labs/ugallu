// Load the SecurityEvent list. Filters come from the URL so the
// view is shareable / bookmarkable. We keep the load function thin
// and let the page component handle the empty / error states.

import type { Class, EventListResponse, EventsListQuery, Severity } from '$lib/api/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, url }) => {
	const query: EventsListQuery = {
		namespace: url.searchParams.get('namespace') ?? undefined,
		class: (url.searchParams.get('class') as Class | null) ?? undefined,
		type: url.searchParams.get('type') ?? undefined,
		severity: (url.searchParams.get('severity') as Severity | null) ?? undefined,
		subjectKind: url.searchParams.get('subjectKind') ?? undefined,
		q: url.searchParams.get('q') ?? undefined,
		limit: Number(url.searchParams.get('limit') ?? 50)
	};
	const search = new URLSearchParams();
	for (const [k, v] of Object.entries(query)) {
		if (v === undefined || v === '' || v === null) continue;
		search.set(k, String(v));
	}
	const res = await fetch(`/api/v1/events?${search.toString()}`, {
		credentials: 'include'
	});
	if (!res.ok) {
		const empty: EventListResponse = { items: [], generation: '' };
		return { events: empty, error: `HTTP ${res.status}`, query };
	}
	const events = (await res.json()) as EventListResponse;
	return { events, error: null as string | null, query };
};
