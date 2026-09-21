import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [
    tailwindcss(),
    react(),
  ],
  server: {
    host: '127.0.0.1',
    port: 5173,
    allowedHosts: true,
    proxy: {
      '/health': 'http://127.0.0.1:8000',
      '/analyze': 'http://127.0.0.1:8000',
      '/cases': 'http://127.0.0.1:8000',
      '/monitor': 'http://127.0.0.1:8000',
      '/alerts': 'http://127.0.0.1:8000',
    }
  }
})
