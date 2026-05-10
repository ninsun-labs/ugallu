<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ChevronRight } from 'lucide-svelte';
	import type { ConfigKind } from '$lib/api/types';
	import type { PageData } from './$types';

	export let data: PageData;

	function onRowKey(e: KeyboardEvent, href: string): void {
		if (e.key === 'Enter' || e.key === ' ') {
			e.preventDefault();
			goto(href);
		}
	}

	const kinds: ConfigKind[] = [
		'AuditDetectionConfig',
		'DNSDetectConfig',
		'ForensicsConfig',
		'HoneypotConfig',
		'WebhookAuditorConfig',
		'TTLConfig',
		'WORMConfig',
		'AttestorConfig',
		'GitOpsResponderConfig'
	];

	function applyFilter(name: string, value: string | undefined): void {
		const url = new URL($page.url);
		if (!value) url.searchParams.delete(name);
		else url.searchParams.set(name, value);
		goto(url, { keepFocus: true, noScroll: true });
	}

	function formatTs(iso?: string): string {
		if (!iso) return '-';
		const d = new Date(iso);
		return Number.isNaN(d.valueOf()) ? iso : d.toLocaleString();
	}

	function detailHref(kind: ConfigKind, namespace: string | undefined, name: string): string {
		const ns = namespace ?? '_';
		return `/configurations/${kind}/${ns}/${name}`;
	}
</script>

<svelte:head>
	<title>Configurations - ugallu</title>
</svelte:head>

<div class="space-y-6">
	<header>
		<h1 class="text-2xl font-semibold tracking-tight">Configurations</h1>
		<p class="text-muted-foreground mt-1 text-sm">
			Read-only view of every <code class="bg-muted rounded px-1 py-0.5 text-xs">*Config</code>
			singleton in the cluster. Mutations stay on
			<code class="bg-muted rounded px-1 py-0.5 text-xs">kubectl apply</code> / GitOps.
		</p>
	</header>

	<section class="border-border bg-card flex flex-wrap items-center gap-3 rounded-lg border p-3">
		<label class="text-muted-foreground text-xs">
			kind
			<select
				class="bg-background border-border focus:ring-ring ml-2 rounded-md border px-2 py-1 text-sm focus:outline-none focus:ring-2"
				value={data.kind ?? ''}
				on:change={(e) => applyFilter('kind', e.currentTarget.value)}
			>
				<option value="">any</option>
				{#each kinds as k}<option value={k}>{k}</option>{/each}
			</select>
		</label>
	</section>

	{#if data.error}
		<div class="border-destructive/50 bg-destructive/10 text-destructive rounded-md border p-4 text-sm">
			Failed to load configurations: {data.error}
		</div>
	{:else if data.configs.items.length === 0}
		<div class="border-border bg-card text-muted-foreground rounded-md border p-12 text-center text-sm">
			No configurations found.
		</div>
	{:else}
		<section class="border-border bg-card overflow-hidden rounded-lg border">
			<table class="w-full text-sm">
				<thead class="border-border bg-muted/40 border-b text-left text-xs uppercase">
					<tr class="text-muted-foreground">
						<th class="px-4 py-2 font-medium">Kind</th>
						<th class="px-4 py-2 font-medium">Name</th>
						<th class="px-4 py-2 font-medium">Namespace</th>
						<th class="px-4 py-2 font-medium">Last load</th>
						<th class="px-4 py-2 font-medium">Generation</th>
						<th class="px-4 py-2 font-medium">Health</th>
						<th class="w-10 px-4 py-2"><span class="sr-only">Open</span></th>
					</tr>
				</thead>
				<tbody class="divide-border divide-y">
					{#each data.configs.items as cfg (`${cfg.kind}/${cfg.namespace ?? '_'}/${cfg.name}`)}
						{@const href = detailHref(cfg.kind, cfg.namespace, cfg.name)}
						<tr
							class="hover:bg-muted/40 focus-within:bg-muted/40 group cursor-pointer transition-colors"
							role="link"
							tabindex="0"
							on:click={() => goto(href)}
							on:keydown={(e) => onRowKey(e, href)}
						>
							<td class="text-muted-foreground px-4 py-2 font-mono text-xs">{cfg.kind}</td>
							<td class="text-foreground group-hover:text-primary px-4 py-2 font-medium transition-colors">
								{cfg.name}
							</td>
							<td class="text-muted-foreground px-4 py-2 text-xs">{cfg.namespace ?? 'cluster-scoped'}</td>
							<td class="text-foreground/70 px-4 py-2 font-mono text-xs">{formatTs(cfg.lastConfigLoadAt)}</td>
							<td class="text-muted-foreground px-4 py-2 text-xs">{cfg.generation ?? '-'}</td>
							<td class="px-4 py-2">
								{#if cfg.healthy}
									<span class="inline-flex items-center rounded-md bg-emerald-500/15 px-2 py-0.5 text-xs font-medium text-emerald-300 ring-1 ring-emerald-400/40">
										healthy
									</span>
								{:else}
									<span class="inline-flex items-center rounded-md bg-destructive/15 text-destructive ring-destructive/40 px-2 py-0.5 text-xs font-medium ring-1">
										degraded
									</span>
								{/if}
							</td>
							<td class="px-4 py-2 text-right">
								<ChevronRight class="text-muted-foreground group-hover:text-primary inline-block h-4 w-4 transition-colors" />
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</section>
	{/if}
</div>
