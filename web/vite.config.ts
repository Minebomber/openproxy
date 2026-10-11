import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': new URL('./src', import.meta.url).pathname } },
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8081',
        changeOrigin: true,
        configure(proxy) {
          // Vite forwards only local development traffic. The Rust API uses token authentication.
          proxy.on('proxyReq', (request) => request.removeHeader('origin'));
        },
      },
    },
  },
  build: { outDir: 'dist' },
});
