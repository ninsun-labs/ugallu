// SvelteKit config. We build to a static bundle and serve it from
// nginx-distroless side-by-side with the BFF Pod (the chart wires
// nginx to proxy /api -> BFF and serve everything else from the
// SvelteKit build directory).
import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter({
			// Plain static output: nginx will serve `index.html` for
			// every unknown path so client-side routing works.
			pages: 'build',
			assets: 'build',
			fallback: 'index.html',
			strict: true
		}),
		alias: {
			$lib: './src/lib'
		}
	}
};

export default config;
