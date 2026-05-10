<script lang="ts">
	import ClassBadge from '$lib/components/class-badge.svelte';
	import SeverityBadge from '$lib/components/severity-badge.svelte';
	import YamlPane from '$lib/components/yaml-pane.svelte';
	import type { Class, Severity } from '$lib/api/types';
	import type { PageData } from './$types';

	export let data: PageData;

	$: spec = (data.event?.spec ?? {}) as Record<string, unknown>;
	$: status = (data.event?.status ?? {}) as Record<string, unknown>;
	$: meta = (data.event?.metadata ?? {}) as Record<string, unknown>;
	$: subject = (spec.subject ?? {}) as Record<string, unknown>;
	$: source = (spec.source ?? {}) as Record<string, unknown>;
	$: cluster = (spec.clusterIdentity ?? {}) as Record<string, unknown>;
</script>

<svelte:head>
	<title>{data.name} - ugallu</title>
</svelte:head>

{#if data.error || !data.event}
	<div class="border-destructive/50 bg-destructive/10 text-destructive rounded-md border p-4 text-sm">
		Failed to load event: {data.error ?? 'unknown'}
	</div>
{:else}
	<div class="space-y-6">
		<header>
			<a href="/events" class="text-muted-foreground hover:text-foreground text-xs">&larr; Events</a>
			<h1 class="mt-1 text-2xl font-semibold tracking-tight">{spec.type ?? data.name}</h1>
			<p class="text-muted-foreground mt-1 font-mono text-xs">{data.name}</p>
		</header>

		<section class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
			<dl class="border-border bg-card rounded-lg border p-4">
				<dt class="text-muted-foreground text-xs uppercase tracking-wide">Class</dt>
				<dd class="mt-2">
					{#if spec.class}<ClassBadge value={spec.class as Class} />{/if}
				</dd>
			</dl>
			<dl class="border-border bg-card rounded-lg border p-4">
				<dt class="text-muted-foreground text-xs uppercase tracking-wide">Severity</dt>
				<dd class="mt-2">
					{#if spec.severity}<SeverityBadge severity={spec.severity as Severity} />{/if}
				</dd>
			</dl>
			<dl class="border-border bg-card rounded-lg border p-4">
				<dt class="text-muted-foreground text-xs uppercase tracking-wide">Phase</dt>
				<dd class="mt-2 text-sm">{status.phase ?? '-'}</dd>
			</dl>
			<dl class="border-border bg-card rounded-lg border p-4">
				<dt class="text-muted-foreground text-xs uppercase tracking-wide">Cluster</dt>
				<dd class="mt-2 truncate text-sm">{cluster.clusterName ?? cluster.clusterID ?? '-'}</dd>
			</dl>
		</section>

		<section class="grid gap-4 lg:grid-cols-2">
			<div class="border-border bg-card rounded-lg border p-4">
				<h2 class="text-muted-foreground text-xs uppercase tracking-wide">Subject</h2>
				<dl class="mt-3 space-y-2 text-sm">
					<div class="flex gap-2">
						<dt class="text-muted-foreground w-24 shrink-0">kind</dt>
						<dd class="font-medium">{subject.kind ?? '-'}</dd>
					</div>
					<div class="flex gap-2">
						<dt class="text-muted-foreground w-24 shrink-0">name</dt>
						<dd>{subject.name ?? '-'}</dd>
					</div>
					{#if subject.namespace}
						<div class="flex gap-2">
							<dt class="text-muted-foreground w-24 shrink-0">namespace</dt>
							<dd>{subject.namespace}</dd>
						</div>
					{/if}
					{#if subject.uid}
						<div class="flex gap-2">
							<dt class="text-muted-foreground w-24 shrink-0">uid</dt>
							<dd class="font-mono text-xs">{subject.uid}</dd>
						</div>
					{/if}
				</dl>
			</div>
			<div class="border-border bg-card rounded-lg border p-4">
				<h2 class="text-muted-foreground text-xs uppercase tracking-wide">Source</h2>
				<dl class="mt-3 space-y-2 text-sm">
					<div class="flex gap-2">
						<dt class="text-muted-foreground w-24 shrink-0">kind</dt>
						<dd>{source.kind ?? '-'}</dd>
					</div>
					<div class="flex gap-2">
						<dt class="text-muted-foreground w-24 shrink-0">name</dt>
						<dd class="font-medium">{source.name ?? '-'}</dd>
					</div>
					{#if source.instance}
						<div class="flex gap-2">
							<dt class="text-muted-foreground w-24 shrink-0">instance</dt>
							<dd>{source.instance}</dd>
						</div>
					{/if}
				</dl>
			</div>
		</section>

		{#if status.attestationBundleRef}
			{@const bundleRef = status.attestationBundleRef as { name?: string }}
			<section class="border-border bg-card rounded-lg border p-4">
				<h2 class="text-muted-foreground text-xs uppercase tracking-wide">Attestation</h2>
				<p class="mt-2 text-sm">
					Sealed by <span class="font-mono">{bundleRef.name ?? '-'}</span>
				</p>
				{#if status.attestationDigest}
					<p class="text-muted-foreground mt-1 break-all font-mono text-xs">
						{status.attestationDigest}
					</p>
				{/if}
			</section>
		{/if}

		{#if Array.isArray(spec.evidence) && spec.evidence.length > 0}
			<section class="border-border bg-card rounded-lg border p-4">
				<h2 class="text-muted-foreground text-xs uppercase tracking-wide">Evidence</h2>
				<ul class="mt-3 space-y-2 text-sm">
					{#each spec.evidence as ev (ev.url ?? ev)}
						<li class="font-mono text-xs">
							<span class="text-muted-foreground">{ev.mediaType}</span>
							<a class="hover:text-primary ml-2 break-all" href={ev.url}>{ev.url}</a>
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		<section>
			<h2 class="text-muted-foreground mb-2 text-xs uppercase tracking-wide">Raw object</h2>
			<YamlPane object={data.event} />
		</section>
	</div>
{/if}
