<script lang="ts">
	import SeverityBadge from '$lib/components/severity-badge.svelte';
	import YamlPane from '$lib/components/yaml-pane.svelte';
	import type { Severity } from '$lib/api/types';
	import type { PageData } from './$types';

	export let data: PageData;

	$: run = (data.detail?.run ?? {}) as Record<string, unknown>;
	$: result = data.detail?.result as Record<string, unknown> | null | undefined;
	$: spec = (run.spec ?? {}) as Record<string, unknown>;
	$: status = (run.status ?? {}) as Record<string, unknown>;
	$: meta = (run.metadata ?? {}) as Record<string, unknown>;
	$: resultStatus = (result?.status ?? {}) as Record<string, unknown>;

	function formatTs(iso?: string): string {
		if (!iso) return '-';
		const d = new Date(iso);
		return Number.isNaN(d.valueOf()) ? iso : d.toLocaleString();
	}
</script>

<svelte:head>
	<title>{data.name} - {data.kind} - ugallu</title>
</svelte:head>

{#if data.error || !data.detail}
	<div class="border-destructive/50 bg-destructive/10 text-destructive rounded-md border p-4 text-sm">
		Failed to load run: {data.error ?? 'unknown'}
	</div>
{:else}
	<div class="space-y-6">
		<header>
			<a href="/runs" class="text-muted-foreground hover:text-foreground text-xs">&larr; Runs</a>
			<h1 class="mt-1 text-2xl font-semibold tracking-tight">{data.name}</h1>
			<p class="text-muted-foreground mt-1 text-sm">
				<span class="font-mono">{data.kind}</span>
				<span class="mx-2">·</span>
				<span>{data.namespace}</span>
			</p>
		</header>

		<section class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
			<dl class="border-border bg-card rounded-lg border p-4">
				<dt class="text-muted-foreground text-xs uppercase tracking-wide">Phase</dt>
				<dd class="mt-2 text-lg font-medium">{status.phase ?? '-'}</dd>
			</dl>
			<dl class="border-border bg-card rounded-lg border p-4">
				<dt class="text-muted-foreground text-xs uppercase tracking-wide">Started</dt>
				<dd class="mt-2 font-mono text-sm">{formatTs(status.startTime as string | undefined)}</dd>
			</dl>
			<dl class="border-border bg-card rounded-lg border p-4">
				<dt class="text-muted-foreground text-xs uppercase tracking-wide">Completed</dt>
				<dd class="mt-2 font-mono text-sm">{formatTs(status.completionTime as string | undefined)}</dd>
			</dl>
			<dl class="border-border bg-card rounded-lg border p-4">
				<dt class="text-muted-foreground text-xs uppercase tracking-wide">Worst severity</dt>
				<dd class="mt-2">
					{#if resultStatus.worstSeverity}
						<SeverityBadge severity={resultStatus.worstSeverity as Severity} />
					{:else}
						<span class="text-muted-foreground text-sm">-</span>
					{/if}
				</dd>
			</dl>
		</section>

		{#if result && Array.isArray((result.spec as { findings?: unknown[] })?.findings)}
			<section class="border-border bg-card overflow-hidden rounded-lg border">
				<header class="border-border bg-muted/40 border-b px-4 py-2">
					<h2 class="text-muted-foreground text-xs uppercase tracking-wide">Findings</h2>
				</header>
				<table class="w-full text-sm">
					<thead class="border-border bg-muted/30 border-b text-left text-xs uppercase">
						<tr class="text-muted-foreground">
							<th class="px-4 py-2 font-medium">Severity</th>
							<th class="px-4 py-2 font-medium">Code</th>
							<th class="px-4 py-2 font-medium">Detail</th>
						</tr>
					</thead>
					<tbody class="divide-border divide-y">
						{#each (result.spec as { findings: Array<Record<string, unknown>> }).findings as f}
							<tr>
								<td class="px-4 py-2">
									{#if f.severity}<SeverityBadge severity={f.severity as Severity} />{/if}
								</td>
								<td class="px-4 py-2 font-mono text-xs">{f.code ?? '-'}</td>
								<td class="text-muted-foreground px-4 py-2 text-xs">{f.message ?? f.detail ?? ''}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</section>
		{/if}

		<section>
			<h2 class="text-muted-foreground mb-2 text-xs uppercase tracking-wide">Run object</h2>
			<YamlPane object={data.detail.run} />
		</section>

		{#if data.detail.result}
			<section>
				<h2 class="text-muted-foreground mb-2 text-xs uppercase tracking-wide">Result / Profile object</h2>
				<YamlPane object={data.detail.result} />
			</section>
		{/if}
	</div>
{/if}
