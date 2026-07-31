import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/dll-visualizer/',
  server: { watch: { usePolling: true } },
  build: {
    chunkSizeWarningLimit: 2500,
  },
});
