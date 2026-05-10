// Typed fetch wrapper for the ugallu BFF.
//
// Cookie carries the session, so every request relies on the
// browser's cookie jar. We use `credentials: 'include'` for the
// rare cross-origin dev case (vite proxy keeps the cookies
// same-origin in normal use).
//
// On 401 the BFF returns a body of shape ApiError with
// `loginURL`; the caller is expected to redirect.

import type {
	ApiError,
	EventListResponse,
	EventSummary,
	EventsListQuery,
	Me
} from './types';

export class ApiClientError extends Error {
	readonly status: number;
	readonly code: string;
	readonly loginURL?: string;
	constructor(status: number, body: ApiError) {
		super(body.message || body.code || `HTTP ${status}`);
		this.status = status;
		this.code = body.code;
		this.loginURL = body.loginURL;
	}
}

async function request<T>(input: RequestInfo, init: RequestInit = {}): Promise<T> {
	const headers = new Headers(init.headers);
	headers.set('Accept', 'application/json');
	const res = await fetch(input, {
		...init,
		headers,
		credentials: 'include'
	});
	if (!res.ok) {
		let body: ApiError = { code: 'unknown', message: res.statusText };
		try {
			body = (await res.json()) as ApiError;
		} catch {
			/* keep the default */
		}
		throw new ApiClientError(res.status, body);
	}
	return (await res.json()) as T;
}

function qs(params: Record<string, string | number | undefined>): string {
	const url = new URLSearchParams();
	for (const [k, v] of Object.entries(params)) {
		if (v === undefined || v === '' || v === null) continue;
		url.set(k, String(v));
	}
	const s = url.toString();
	return s ? `?${s}` : '';
}

export async function getMe(fetchImpl: typeof fetch = fetch): Promise<Me> {
	return request<Me>('/api/v1/me', { method: 'GET' });
}

export async function listEvents(
	query: EventsListQuery = {},
	fetchImpl: typeof fetch = fetch
): Promise<EventListResponse> {
	return request<EventListResponse>(`/api/v1/events${qs(query as never)}`, {
		method: 'GET'
	});
}

export async function getEvent(
	name: string,
	namespace?: string,
	fetchImpl: typeof fetch = fetch
): Promise<EventSummary & { spec?: unknown; status?: unknown }> {
	return request(
		`/api/v1/events/${encodeURIComponent(name)}${qs({ namespace })}`,
		{ method: 'GET' }
	);
}

export function loginRedirect(returnTo: string = window.location.pathname): void {
	window.location.assign(`/auth/login?return_to=${encodeURIComponent(returnTo)}`);
}
