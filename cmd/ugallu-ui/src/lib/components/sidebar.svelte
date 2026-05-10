<script lang="ts">
	import { page } from '$app/stores';
	import { cn } from '$lib/utils';
	import { Activity, Database, FileText, Home, Layers, ShieldAlert } from 'lucide-svelte';

	type NavItem = { href: string; label: string; icon: typeof Home };
	const items: NavItem[] = [
		{ href: '/', label: 'Dashboard', icon: Home },
		{ href: '/events', label: 'Events', icon: ShieldAlert },
		{ href: '/runs', label: 'Runs', icon: Activity },
		{ href: '/configurations', label: 'Configurations', icon: Layers },
		{ href: '/honeypots', label: 'Honeypots', icon: Database },
		{ href: '/audit', label: 'Audit', icon: FileText }
	];

	function isActive(href: string, current: string): boolean {
		if (href === '/') return current === '/';
		return current === href || current.startsWith(href + '/');
	}
</script>

<aside class="border-sidebar-border bg-sidebar text-sidebar-foreground flex h-screen w-60 flex-col border-r">
	<div class="border-sidebar-border flex h-16 items-center justify-center border-b px-2 py-2">
		<a href="/" class="block h-full w-full" aria-label="ugallu home">
			<!-- Dark theme: bright cyan wordmark on navy sidebar. -->
			<img
				src="/ugallu-wordmark.svg"
				alt="ugallu"
				class="hidden h-full w-full object-contain dark:block"
			/>
			<!-- Light theme: darker teal wordmark on light sidebar. -->
			<img
				src="/ugallu-wordmark-light.svg"
				alt="ugallu"
				class="block h-full w-full object-contain dark:hidden"
			/>
		</a>
	</div>
	<nav class="flex-1 overflow-y-auto px-3 py-4">
		<ul class="space-y-1">
			{#each items as item (item.href)}
				{@const active = isActive(item.href, $page.url.pathname)}
				<li>
					<a
						href={item.href}
						class={cn(
							'flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors',
							active
								? 'bg-sidebar-accent text-sidebar-accent-foreground'
								: 'text-sidebar-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground'
						)}
					>
						<svelte:component this={item.icon} class="h-4 w-4" />
						<span>{item.label}</span>
					</a>
				</li>
			{/each}
		</ul>
	</nav>
	<div class="border-sidebar-border text-muted-foreground border-t p-3 text-xs">
		<p class="font-mono">v0.1.0-alpha.1</p>
	</div>
</aside>
