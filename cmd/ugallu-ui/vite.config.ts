import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// In dev the SPA runs on :5173 and the BFF on :8080. The proxy
// makes `/api/v1/...` calls hit the BFF without CORS / cookie
// headaches; in production nginx does the same proxy server-side.
export default defineConfig({
	plugins: [sveltekit()],
	server: {
		proxy: {
			'/api': {
				target: 'http://localhost:8080',
				changeOrigin: false
			},
			'/auth': {
				target: 'http://localhost:8080',
				changeOrigin: false
			},
			'/healthz': 'http://localhost:8080',
			'/readyz': 'http://localhost:8080'
		}
	}
});
