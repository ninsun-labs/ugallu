<script lang="ts">
	// A read-only pane that pretty-prints any JSON-serialisable
	// object. Intentionally simple: no syntax highlighting, no
	// folding - just monospace + line breaks. That's enough for the
	// "view the raw CR" use case in v0.1.0-alpha.1.
	export let object: unknown = null;

	$: pretty = JSON.stringify(object, null, 2);
</script>

<pre
	class="border-border bg-muted/30 overflow-x-auto rounded-md border p-4 font-mono text-xs leading-relaxed"
>{pretty}</pre>
