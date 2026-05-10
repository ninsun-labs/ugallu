<script lang="ts">
	import YamlPane from '$lib/components/yaml-pane.svelte';
	import type { PageData } from './$types';

	export let data: PageData;
</script>

<svelte:head>
	<title>{data.name} - {data.kind} - ugallu</title>
</svelte:head>

{#if data.error || !data.detail}
	<div class="border-destructive/50 bg-destructive/10 text-destructive rounded-md border p-4 text-sm">
		Failed to load configuration: {data.error ?? 'unknown'}
	</div>
{:else}
	<div class="space-y-6">
		<header>
			<a href="/configurations" class="text-muted-foreground hover:text-foreground text-xs">
				&larr; Configurations
			</a>
			<h1 class="mt-1 text-2xl font-semibold tracking-tight">{data.name}</h1>
			<p class="text-muted-foreground mt-1 text-sm">
				<span class="font-mono">{data.kind}</span>
				{#if data.namespace}
					<span class="mx-2">·</span>
					<span>{data.namespace}</span>
				{:else}
					<span class="mx-2">·</span>
					<span class="text-muted-foreground/70">cluster-scoped</span>
				{/if}
			</p>
		</header>

		<section>
			<h2 class="text-muted-foreground mb-2 text-xs uppercase tracking-wide">Object</h2>
			<YamlPane object={data.detail.object} />
		</section>
	</div>
{/if}
