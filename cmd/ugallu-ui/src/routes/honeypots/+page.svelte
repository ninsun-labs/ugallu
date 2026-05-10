<script lang="ts">
	import type { PageData } from './$types';

	export let data: PageData;
</script>

<svelte:head>
	<title>Honeypots - ugallu</title>
</svelte:head>

<div class="space-y-6">
	<header>
		<h1 class="text-2xl font-semibold tracking-tight">Honeypots</h1>
		<p class="text-muted-foreground mt-1 text-sm">
			Decoy <code class="bg-muted rounded px-1 py-0.5 text-xs">Secret</code> and
			<code class="bg-muted rounded px-1 py-0.5 text-xs">ServiceAccount</code> objects deployed
			by the
			<a class="hover:text-primary underline-offset-2 hover:underline" href="/configurations?kind=HoneypotConfig">honeypot operator</a>.
			Any access fires a
			<code class="bg-muted rounded px-1 py-0.5 text-xs">HoneypotTriggered</code> SecurityEvent.
		</p>
	</header>

	{#if data.error}
		<div class="border-destructive/50 bg-destructive/10 text-destructive rounded-md border p-4 text-sm">
			Failed to load honeypots: {data.error}
		</div>
	{:else if data.items.length === 0}
		<div class="border-border bg-card text-muted-foreground rounded-md border p-12 text-center text-sm">
			<p>
				No <code class="bg-muted rounded px-1 py-0.5 text-xs">HoneypotConfig</code> CRs
				found. Deploy one with
				<code class="bg-muted rounded px-1 py-0.5 text-xs">kubectl apply</code> -
				see the operator docs for the YAML shape.
			</p>
		</div>
	{:else}
		<section class="space-y-4">
			{#each data.items as h (h.name)}
				<article class="border-border bg-card overflow-hidden rounded-lg border">
					<header class="border-border bg-muted/40 flex items-center justify-between border-b px-4 py-3">
						<div>
							<h2 class="font-medium">{h.name}</h2>
							<p class="text-muted-foreground text-xs">
								{h.namespace ?? 'cluster-scoped'}
								<span class="mx-2">·</span>
								<span>{h.decoys.length} declared</span>
								<span class="mx-1">·</span>
								<span>{h.deployedDecoys?.length ?? 0} deployed</span>
							</p>
						</div>
						{#if h.healthy}
							<span class="inline-flex items-center rounded-md bg-emerald-500/15 px-2 py-0.5 text-xs font-medium text-emerald-300 ring-1 ring-emerald-400/40">
								healthy
							</span>
						{:else}
							<span class="inline-flex items-center rounded-md bg-destructive/15 text-destructive ring-destructive/40 px-2 py-0.5 text-xs font-medium ring-1">
								degraded
							</span>
						{/if}
					</header>

					{#if h.decoys.length === 0}
						<div class="text-muted-foreground p-4 text-xs">No decoys declared.</div>
					{:else}
						<table class="w-full text-sm">
							<thead class="border-border bg-muted/30 border-b text-left text-xs uppercase">
								<tr class="text-muted-foreground">
									<th class="px-4 py-2 font-medium">Kind</th>
									<th class="px-4 py-2 font-medium">Namespace</th>
									<th class="px-4 py-2 font-medium">Name</th>
								</tr>
							</thead>
							<tbody class="divide-border divide-y">
								{#each h.decoys as d}
									<tr>
										<td class="text-muted-foreground px-4 py-2 font-mono text-xs">{d.kind}</td>
										<td class="px-4 py-2 text-xs">{d.namespace ?? '-'}</td>
										<td class="px-4 py-2 font-medium">{d.name}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					{/if}
				</article>
			{/each}
		</section>
	{/if}
</div>
