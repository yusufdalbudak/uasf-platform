import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    fs: {
      allow: ['..']
    },
    proxy: {
      '/api': {
        target: 'http://backend:3000',
        changeOrigin: true,
        // UASF assessment scans can run for 60-120s; raise the default so the
        // browser does not see a connection-reset while the backend is still
        // working.
        timeout: 180000,
        proxyTimeout: 180000,
      }
    }
  }
})
