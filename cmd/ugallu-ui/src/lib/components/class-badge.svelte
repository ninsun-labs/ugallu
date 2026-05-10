<script lang="ts">
	import { cn } from '$lib/utils';
	import type { Class } from '$lib/api/types';

	export let value: Class;

	const styles: Record<Class, string> = {
		Detection: 'bg-primary/15 text-primary ring-1 ring-primary/40',
		Audit: 'bg-muted text-muted-foreground ring-1 ring-border',
		Forensic: 'bg-violet-500/15 text-violet-300 ring-1 ring-violet-400/40',
		Compliance: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-400/40',
		Anomaly: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-400/40',
		PolicyViolation: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-400/40'
	};
</script>

<span
	class={cn(
		'inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium tracking-wide',
		styles[value]
	)}
>
	{value}
</span>
