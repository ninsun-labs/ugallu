<script lang="ts">
	import type { PageData } from './$types';

	export let data: PageData;
</script>

<svelte:head>
	<title>Dashboard - ugallu</title>
</svelte:head>

<div class="space-y-6">
	<header>
		<h1 class="text-2xl font-semibold tracking-tight">Dashboard</h1>
		<p class="text-muted-foreground mt-1 text-sm">
			Cluster posture and the last 24h of SecurityEvents at a glance. Detail pages live under
			<code class="bg-muted rounded px-1 py-0.5 text-xs">/events</code>.
		</p>
	</header>

	<section class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
		<article class="border-border bg-card rounded-lg border p-4">
			<p class="text-muted-foreground text-xs uppercase tracking-wide">Operators</p>
			<p class="mt-2 text-3xl font-semibold">11</p>
			<p class="text-muted-foreground mt-1 text-xs">Audit, DNS, tenant-escape, ...</p>
		</article>
		<article class="border-border bg-card rounded-lg border p-4">
			<p class="text-muted-foreground text-xs uppercase tracking-wide">SecurityEvent types</p>
			<p class="mt-2 text-3xl font-semibold">92</p>
			<p class="text-muted-foreground mt-1 text-xs">Closed catalog, admission-enforced</p>
		</article>
		<article class="border-border bg-card rounded-lg border p-4">
			<p class="text-muted-foreground text-xs uppercase tracking-wide">Signed in as</p>
			<p class="mt-2 truncate text-lg font-medium">{data.me?.name || data.me?.email || data.me?.sub || '-'}</p>
			<p class="text-muted-foreground mt-1 truncate text-xs">{data.me?.groups?.join(', ') ?? '-'}</p>
		</article>
		<article class="border-border bg-card rounded-lg border p-4">
			<p class="text-muted-foreground text-xs uppercase tracking-wide">BFF version</p>
			<p class="mt-2 font-mono text-lg">{data.me?.bffVersion ?? '-'}</p>
		</article>
	</section>

	<section class="border-border bg-card rounded-lg border p-6">
		<h2 class="text-lg font-medium">Welcome</h2>
		<p class="text-muted-foreground mt-2 text-sm leading-relaxed">
			This is the v0.1.0-alpha.1 read-only console. Use the left navigation to browse
			SecurityEvents, runs, and configurations. Mutations stay on
			<code class="bg-muted rounded px-1 py-0.5 text-xs">kubectl apply</code> / GitOps for now.
		</p>
	</section>
</div>
