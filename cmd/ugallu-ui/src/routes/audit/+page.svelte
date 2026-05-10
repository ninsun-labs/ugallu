<script lang="ts">
	import { Activity } from 'lucide-svelte';
</script>

<svelte:head>
	<title>Audit - ugallu</title>
</svelte:head>

<div class="space-y-6">
	<header>
		<h1 class="text-2xl font-semibold tracking-tight">Audit</h1>
		<p class="text-muted-foreground mt-1 text-sm">
			Cluster-wide <code class="bg-muted rounded px-1 py-0.5 text-xs">EventResponse</code> log
			and <code class="bg-muted rounded px-1 py-0.5 text-xs">AttestationBundle</code> status.
		</p>
	</header>

	<section class="border-border bg-card flex flex-col items-center gap-3 rounded-lg border p-12 text-center">
		<Activity class="text-muted-foreground h-10 w-10" />
		<p class="text-foreground text-base font-medium">Coming in v0.2.0</p>
		<p class="text-muted-foreground max-w-md text-sm">
			The audit view requires two BFF endpoints that are not yet implemented:
			<code class="bg-muted rounded px-1 py-0.5 text-xs">/api/v1/eventresponses</code>
			(the IR-as-code action chain) and
			<code class="bg-muted rounded px-1 py-0.5 text-xs">/api/v1/attestationbundles</code>
			(the cosign-keyless seal status). For now consume them via
			<code class="bg-muted rounded px-1 py-0.5 text-xs">kubectl get eventresponses</code> and
			<code class="bg-muted rounded px-1 py-0.5 text-xs">kubectl get attestationbundles</code>.
		</p>
	</section>
</div>
