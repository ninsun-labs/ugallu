<script lang="ts">
	import { cn } from '$lib/utils';
	import type { Severity } from '$lib/api/types';

	export let severity: Severity;

	const styles: Record<Severity, string> = {
		critical: 'bg-destructive/15 text-destructive ring-1 ring-destructive/40',
		high: 'bg-orange-500/15 text-orange-300 ring-1 ring-orange-400/40',
		medium: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-400/40',
		low: 'bg-sky-500/15 text-sky-300 ring-1 ring-sky-400/40',
		info: 'bg-muted text-muted-foreground ring-1 ring-border'
	};
</script>

<span
	class={cn(
		'inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium uppercase tracking-wide',
		styles[severity]
	)}
>
	{severity}
</span>
