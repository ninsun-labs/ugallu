<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ChevronRight } from 'lucide-svelte';
	import ClassBadge from '$lib/components/class-badge.svelte';
	import SeverityBadge from '$lib/components/severity-badge.svelte';
	import type { Class, Severity } from '$lib/api/types';
	import type { PageData } from './$types';

	export let data: PageData;

	function rowHref(name: string, namespace?: string): string {
		return `/events/${encodeURIComponent(name)}${namespace ? `?namespace=${encodeURIComponent(namespace)}` : ''}`;
	}

	function onRowKey(e: KeyboardEvent, href: string): void {
		if (e.key === 'Enter' || e.key === ' ') {
			e.preventDefault();
			goto(href);
		}
	}

	const classes: Class[] = ['Detection', 'Audit', 'Forensic', 'Compliance', 'Anomaly', 'PolicyViolation'];
	const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

	function formatTimestamp(iso: string): string {
		if (!iso) return '-';
		const d = new Date(iso);
		if (Number.isNaN(d.valueOf())) return iso;
		return d.toLocaleString();
	}

	function applyFilter(name: string, value: string | undefined): void {
		const url = new URL($page.url);
		if (value === undefined || value === '') {
			url.searchParams.delete(name);
		} else {
			url.searchParams.set(name, value);
		}
		goto(url, { keepFocus: true, noScroll: true, replaceState: false });
	}
</script>

<svelte:head>
	<title>Events - ugallu</title>
</svelte:head>

<div class="space-y-6">
	<header class="flex items-baseline justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight">SecurityEvents</h1>
			<p class="text-muted-foreground mt-1 text-sm">
				{data.events.items.length} event{data.events.items.length === 1 ? '' : 's'}
				{#if data.events.continue}
					(more available)
				{/if}
			</p>
		</div>
	</header>

	<section class="border-border bg-card flex flex-wrap items-center gap-3 rounded-lg border p-3">
		<label class="text-muted-foreground text-xs">
			class
			<select
				class="bg-background border-border focus:ring-ring ml-2 rounded-md border px-2 py-1 text-sm focus:outline-none focus:ring-2"
				value={data.query.class ?? ''}
				on:change={(e) => applyFilter('class', e.currentTarget.value)}
			>
				<option value="">any</option>
				{#each classes as c}<option value={c}>{c}</option>{/each}
			</select>
		</label>
		<label class="text-muted-foreground text-xs">
			severity
			<select
				class="bg-background border-border focus:ring-ring ml-2 rounded-md border px-2 py-1 text-sm focus:outline-none focus:ring-2"
				value={data.query.severity ?? ''}
				on:change={(e) => applyFilter('severity', e.currentTarget.value)}
			>
				<option value="">any</option>
				{#each severities as s}<option value={s}>{s}</option>{/each}
			</select>
		</label>
		<label class="text-muted-foreground text-xs">
			search
			<input
				type="search"
				placeholder="type or signal"
				class="bg-background border-border focus:ring-ring ml-2 w-56 rounded-md border px-2 py-1 text-sm focus:outline-none focus:ring-2"
				value={data.query.q ?? ''}
				on:change={(e) => applyFilter('q', e.currentTarget.value)}
			/>
		</label>
	</section>

	{#if data.error}
		<div class="border-destructive/50 bg-destructive/10 text-destructive rounded-md border p-4 text-sm">
			Failed to load events: {data.error}
		</div>
	{:else if data.events.items.length === 0}
		<div class="border-border bg-card text-muted-foreground rounded-md border p-12 text-center text-sm">
			No SecurityEvents match the current filters.
		</div>
	{:else}
		<section class="border-border bg-card overflow-hidden rounded-lg border">
			<table class="w-full text-sm">
				<thead class="border-border bg-muted/40 border-b text-left text-xs uppercase">
					<tr class="text-muted-foreground">
						<th class="px-4 py-2 font-medium">When</th>
						<th class="px-4 py-2 font-medium">Type</th>
						<th class="px-4 py-2 font-medium">Class</th>
						<th class="px-4 py-2 font-medium">Severity</th>
						<th class="px-4 py-2 font-medium">Subject</th>
						<th class="px-4 py-2 font-medium">Source</th>
						<th class="w-10 px-4 py-2"><span class="sr-only">Open</span></th>
					</tr>
				</thead>
				<tbody class="divide-border divide-y">
					{#each data.events.items as ev (ev.uid)}
						{@const href = rowHref(ev.name, ev.namespace)}
						<tr
							class="hover:bg-muted/40 focus-within:bg-muted/40 group cursor-pointer transition-colors"
							role="link"
							tabindex="0"
							on:click={() => goto(href)}
							on:keydown={(e) => onRowKey(e, href)}
						>
							<td class="text-foreground/70 whitespace-nowrap px-4 py-2 font-mono text-xs">
								{formatTimestamp(ev.creationTimestamp)}
							</td>
							<td class="text-foreground group-hover:text-primary px-4 py-2 font-medium transition-colors">
								{ev.type}
							</td>
							<td class="px-4 py-2"><ClassBadge value={ev.class} /></td>
							<td class="px-4 py-2"><SeverityBadge severity={ev.severity} /></td>
							<td class="px-4 py-2">
								<span class="text-muted-foreground text-xs">{ev.subject.kind}</span>
								<span class="text-foreground ml-1">{ev.subject.name ?? '-'}</span>
								{#if ev.subject.namespace}
									<span class="text-muted-foreground"> / {ev.subject.namespace}</span>
								{/if}
							</td>
							<td class="text-muted-foreground px-4 py-2 text-xs">
								{ev.source.kind}{ev.source.name ? ` / ${ev.source.name}` : ''}
								{#if ev.source.clusterName}
									<span class="text-muted-foreground/80"> @{ev.source.clusterName}</span>
								{/if}
							</td>
							<td class="px-4 py-2 text-right">
								<ChevronRight
									class="text-muted-foreground group-hover:text-primary inline-block h-4 w-4 transition-colors"
								/>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</section>
	{/if}
</div>
