import { build } from 'esbuild';

build({
	entryPoints: ['./src/index.js'],
	bundle: true,
	minify: true,
	keepNames: true,
	format: 'esm',
	target: 'es2024',
	splitting: false,
	treeShaking: true,
	platform: 'neutral',
	outdir: './dist',
	external: ['cloudflare:workers'],
});
