<script lang="ts">
	import '../app.css';
	import Sidebar from '$lib/components/sidebar.svelte';
	import Topbar from '$lib/components/topbar.svelte';
	import type { LayoutData } from './$types';

	export let data: LayoutData;
</script>

<div class="bg-background text-foreground flex min-h-screen">
	<Sidebar />
	<div class="flex min-w-0 flex-1 flex-col">
		<Topbar me={data.me} />
		<main class="flex-1 px-8 py-6">
			<slot />
		</main>
	</div>
</div>
