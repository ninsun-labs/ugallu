// Honeypot view: thin wrapper over /api/v1/configurations
// filtered to HoneypotConfig + per-CR detail to surface the
// decoy inventory.

import type { ConfigDetailResponse, ConfigListResponse } from '$lib/api/types';
import type { PageLoad } from './$types';

interface HoneypotEntry {
	name: string;
	namespace?: string;
	healthy: boolean;
	decoys: Array<{
		kind: string;
		namespace?: string;
		name: string;
	}>;
	deployedDecoys?: Array<{
		kind: string;
		namespace?: string;
		name: string;
		uid?: string;
	}>;
}

export const load: PageLoad = async ({ fetch }) => {
	const listRes = await fetch('/api/v1/configurations?kind=HoneypotConfig', {
		credentials: 'include'
	});
	if (!listRes.ok) {
		return { items: [] as HoneypotEntry[], error: `HTTP ${listRes.status}` };
	}
	const list = (await listRes.json()) as ConfigListResponse;

	const items: HoneypotEntry[] = await Promise.all(
		list.items.map(async (cfg) => {
			const path = cfg.namespace
				? `/api/v1/configurations/${cfg.kind}/${cfg.namespace}/${cfg.name}`
				: `/api/v1/configurations/${cfg.kind}/${cfg.name}`;
			const detailRes = await fetch(path, { credentials: 'include' });
			let decoys: HoneypotEntry['decoys'] = [];
			let deployedDecoys: HoneypotEntry['deployedDecoys'] = [];
			if (detailRes.ok) {
				const detail = (await detailRes.json()) as ConfigDetailResponse;
				const obj = detail.object as Record<string, unknown>;
				const spec = (obj.spec ?? {}) as Record<string, unknown>;
				const status = (obj.status ?? {}) as Record<string, unknown>;
				if (Array.isArray(spec.decoys)) decoys = spec.decoys as never;
				if (Array.isArray(status.deployedDecoys))
					deployedDecoys = status.deployedDecoys as never;
			}
			return {
				name: cfg.name,
				namespace: cfg.namespace,
				healthy: cfg.healthy,
				decoys,
				deployedDecoys
			};
		})
	);

	return { items, error: null as string | null };
};
