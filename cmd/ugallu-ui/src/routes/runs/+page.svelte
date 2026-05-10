<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { ChevronRight } from 'lucide-svelte';
	import SeverityBadge from '$lib/components/severity-badge.svelte';
	import type { RunKind, RunPhase, Severity } from '$lib/api/types';
	import type { PageData } from './$types';

	export let data: PageData;

	function onRowKey(e: KeyboardEvent, href: string): void {
		if (e.key === 'Enter' || e.key === ' ') {
			e.preventDefault();
			goto(href);
		}
	}

	const kinds: RunKind[] = [
		'BackupVerifyRun',
		'ComplianceScanRun',
		'ConfidentialAttestationRun',
		'SeccompTrainingRun'
	];
	const phases: RunPhase[] = ['Pending', 'Running', 'Succeeded', 'Failed'];

	const phaseStyles: Record<NonNullable<RunPhase>, string> = {
		'': 'bg-muted text-muted-foreground',
		Pending: 'bg-muted text-muted-foreground ring-1 ring-border',
		Running: 'bg-sky-500/15 text-sky-300 ring-1 ring-sky-400/40',
		Succeeded: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-400/40',
		Failed: 'bg-destructive/15 text-destructive ring-1 ring-destructive/40'
	};

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

	function detailHref(kind: RunKind, namespace: string, name: string): string {
		return `/runs/${kind}/${name}?namespace=${encodeURIComponent(namespace)}`;
	}

	function detailLine(details: Record<string, string> | undefined): string {
		if (!details) return '';
		return Object.entries(details)
			.filter(([, v]) => v && v !== '0')
			.map(([k, v]) => `${k}=${v}`)
			.join(' · ');
	}
</script>

<svelte:head>
	<title>Runs - ugallu</title>
</svelte:head>

<div class="space-y-6">
	<header class="flex items-baseline justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight">Runs</h1>
			<p class="text-muted-foreground mt-1 text-sm">
				{data.runs.items.length} run{data.runs.items.length === 1 ? '' : 's'} across the four
				Run kinds (backup-verify, compliance-scan, confidential-attestation, seccomp-gen).
			</p>
		</div>
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
		<label class="text-muted-foreground text-xs">
			phase
			<select
				class="bg-background border-border focus:ring-ring ml-2 rounded-md border px-2 py-1 text-sm focus:outline-none focus:ring-2"
				value={data.phase ?? ''}
				on:change={(e) => applyFilter('phase', e.currentTarget.value)}
			>
				<option value="">any</option>
				{#each phases as p}<option value={p}>{p}</option>{/each}
			</select>
		</label>
	</section>

	{#if data.error}
		<div class="border-destructive/50 bg-destructive/10 text-destructive rounded-md border p-4 text-sm">
			Failed to load runs: {data.error}
		</div>
	{:else if data.runs.items.length === 0}
		<div class="border-border bg-card text-muted-foreground rounded-md border p-12 text-center text-sm">
			No runs match the current filters.
		</div>
	{:else}
		<section class="border-border bg-card overflow-hidden rounded-lg border">
			<table class="w-full text-sm">
				<thead class="border-border bg-muted/40 border-b text-left text-xs uppercase">
					<tr class="text-muted-foreground">
						<th class="px-4 py-2 font-medium">When</th>
						<th class="px-4 py-2 font-medium">Kind</th>
						<th class="px-4 py-2 font-medium">Name</th>
						<th class="px-4 py-2 font-medium">Phase</th>
						<th class="px-4 py-2 font-medium">Severity</th>
						<th class="px-4 py-2 font-medium">Details</th>
						<th class="w-10 px-4 py-2"><span class="sr-only">Open</span></th>
					</tr>
				</thead>
				<tbody class="divide-border divide-y">
					{#each data.runs.items as run (run.uid)}
						{@const href = detailHref(run.kind, run.namespace, run.name)}
						<tr
							class="hover:bg-muted/40 focus-within:bg-muted/40 group cursor-pointer transition-colors"
							role="link"
							tabindex="0"
							on:click={() => goto(href)}
							on:keydown={(e) => onRowKey(e, href)}
						>
							<td class="text-foreground/70 whitespace-nowrap px-4 py-2 font-mono text-xs">
								{formatTs(run.creationTimestamp)}
							</td>
							<td class="text-muted-foreground px-4 py-2 text-xs">{run.kind}</td>
							<td class="px-4 py-2 font-medium">
								<span class="text-foreground group-hover:text-primary transition-colors">
									{run.name}
								</span>
								<div class="text-muted-foreground text-xs">{run.namespace}</div>
							</td>
							<td class="px-4 py-2">
								<span class={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${phaseStyles[(run.phase ?? '') as RunPhase]}`}>
									{run.phase || '-'}
								</span>
							</td>
							<td class="px-4 py-2">
								{#if run.worstSeverity}
									<SeverityBadge severity={run.worstSeverity as Severity} />
								{:else}
									<span class="text-muted-foreground text-xs">-</span>
								{/if}
							</td>
							<td class="text-muted-foreground px-4 py-2 font-mono text-xs">
								{detailLine(run.details)}
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
