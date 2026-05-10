// Root layout load: fetch the authenticated user once and share it
// with every page below. On 401 we redirect through the BFF login
// endpoint, which performs the OIDC + PKCE flow.

import { browser } from '$app/environment';
import { ApiClientError } from '$lib/api/client';
import type { Me } from '$lib/api/types';
import type { LayoutLoad } from './$types';

export const ssr = false; // SPA only - the BFF is the brain.
export const prerender = false;

export const load: LayoutLoad = async ({ fetch, url }) => {
	let me: Me | null = null;
	try {
		const res = await fetch('/api/v1/me', { credentials: 'include' });
		if (res.status === 401) {
			if (browser) {
				const body = (await res.json().catch(() => ({}))) as { loginURL?: string };
				const target =
					body.loginURL ?? `/auth/login?return_to=${encodeURIComponent(url.pathname)}`;
				window.location.assign(target);
			}
			throw new ApiClientError(401, { code: 'unauthenticated', message: 'redirecting to login' });
		}
		if (!res.ok) throw new Error(`/me: HTTP ${res.status}`);
		me = (await res.json()) as Me;
	} catch (err) {
		if (err instanceof ApiClientError && err.status === 401) throw err;
		console.error('layout load failed', err);
	}
	return { me };
};
