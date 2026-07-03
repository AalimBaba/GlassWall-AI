import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Relative asset paths keep static exports portable across GitHub Pages project URLs.
export default defineConfig({ plugins: [react()], base: './' })
