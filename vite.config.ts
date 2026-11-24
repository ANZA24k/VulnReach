import {defineConfig} from 'vite';
export default defineConfig({build:{rollupOptions:{output:{manualChunks:{genlayer:['genlayer-js','genlayer-js/chains'],react:['react','react-dom']}}}}});
