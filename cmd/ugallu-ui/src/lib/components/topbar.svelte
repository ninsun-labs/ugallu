<script lang="ts">
	import { page } from '$app/stores';
	import { Moon, Sun } from 'lucide-svelte';
	import type { Me } from '$lib/api/types';

	export let me: Me | null = null;

	let theme: 'dark' | 'light' = 'dark';

	function toggleTheme(): void {
		theme = theme === 'dark' ? 'light' : 'dark';
		const html = document.documentElement;
		html.classList.toggle('dark', theme === 'dark');
		html.classList.toggle('light', theme === 'light');
		try {
			localStorage.setItem('ugallu-ui-theme', theme);
		} catch {
			/* ignore */
		}
	}

	$: if (typeof window !== 'undefined') {
		try {
			const stored = localStorage.getItem('ugallu-ui-theme');
			if (stored === 'light' || stored === 'dark') theme = stored;
		} catch {
			/* ignore */
		}
	}

	function logout(): void {
		fetch('/auth/logout', { method: 'POST', credentials: 'include' })
			.catch(() => {})
			.finally(() => {
				window.location.assign('/');
			});
	}

	// Breadcrumb derived from the URL. Strips the leading slash and
	// turns nested paths into "Section / sub" entries.
	$: crumbs = breadcrumbsFor($page.url.pathname);

	function breadcrumbsFor(pathname: string): { label: string; href: string }[] {
		const trimmed = pathname.replace(/^\/+|\/+$/g, '');
		if (!trimmed) return [{ label: 'Dashboard', href: '/' }];
		const parts = trimmed.split('/');
		const out: { label: string; href: string }[] = [];
		let acc = '';
		for (const p of parts) {
			acc += '/' + p;
			out.push({ label: humanise(p), href: acc });
		}
		return out;
	}

	function humanise(seg: string): string {
		try {
			const decoded = decodeURIComponent(seg);
			if (/^[A-Z]/.test(decoded)) return decoded; // already PascalCase (kind names)
			return decoded.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
		} catch {
			return seg;
		}
	}
</script>

<header class="border-border bg-background/95 sticky top-0 z-10 flex h-14 items-center justify-between border-b px-6 backdrop-blur">
	<nav aria-label="Breadcrumb" class="min-w-0 truncate">
		<ol class="flex items-center gap-1.5 text-sm">
			{#each crumbs as c, i (c.href)}
				{#if i > 0}
					<li class="text-muted-foreground/60" aria-hidden="true">/</li>
				{/if}
				<li class="min-w-0 truncate">
					{#if i === crumbs.length - 1}
						<span class="text-foreground font-medium">{c.label}</span>
					{:else}
						<a class="text-muted-foreground hover:text-foreground transition-colors" href={c.href}>
							{c.label}
						</a>
					{/if}
				</li>
			{/each}
		</ol>
	</nav>

	<div class="flex items-center gap-3">
		<button
			type="button"
			class="text-foreground/80 hover:text-foreground hover:bg-muted inline-flex h-8 w-8 items-center justify-center rounded-md transition-colors"
			aria-label="Toggle theme"
			on:click={toggleTheme}
		>
			{#if theme === 'dark'}
				<Sun class="h-4 w-4" />
			{:else}
				<Moon class="h-4 w-4" />
			{/if}
		</button>

		{#if me}
			<div class="text-foreground hidden items-center gap-2 text-sm sm:flex">
				<span class="text-muted-foreground">signed in as</span>
				<span class="font-medium">{me.name || me.email || me.sub}</span>
			</div>
			<button
				type="button"
				class="border-border text-foreground/80 hover:text-foreground hover:border-ring rounded-md border px-3 py-1 text-xs transition-colors"
				on:click={logout}
			>
				Sign out
			</button>
		{/if}
	</div>
</header>
