/**
 * VaultBix ML Web Worker
 * Runs Transformers.js NER inference off the main thread.
 *
 * Messages IN:
 *   { type: 'init', wasmPaths: string }   – preload the model
 *   { type: 'detect', id: string, text: string } – run NER on text
 *
 * Messages OUT:
 *   { type: 'init_done' }
 *   { type: 'init_error', error: string }
 *   { type: 'result', id: string, entities: Array }
 *   { type: 'error', id: string, error: string }
 */

import { pipeline, env } from '@xenova/transformers';

// Force local caching, no local model files (download from Hub)
env.allowLocalModels = false;
env.useBrowserCache = true;

let nerPipeline = null;
let isLoading = false;

async function initPipeline(wasmPaths) {
    if (nerPipeline || isLoading) return;
    isLoading = true;

    try {
        if (wasmPaths) {
            env.backends = env.backends || {};
            env.backends.onnx = env.backends.onnx || {};
            env.backends.onnx.wasm = env.backends.onnx.wasm || {};
            env.backends.onnx.wasm.wasmPaths = wasmPaths;
        }

        nerPipeline = await pipeline(
            'token-classification',
            'Xenova/bert-base-NER',
            { quantized: true }
        );

        self.postMessage({ type: 'init_done' });
    } catch (e) {
        self.postMessage({ type: 'init_error', error: e?.message || String(e) });
    } finally {
        isLoading = false;
    }
}

async function detectEntities(id, text) {
    if (!nerPipeline) {
        self.postMessage({ type: 'result', id, entities: [] });
        return;
    }

    try {
        const results = await nerPipeline(text, { aggregation_strategy: 'simple' });

        const entities = results
            .filter(r => r.score > 0.85)
            .map(r => ({
                entity: r.entity_group,   // PER, ORG, LOC, MISC
                text: r.word,
                score: r.score,
                start: r.start,
                end: r.end
            }));

        self.postMessage({ type: 'result', id, entities });
    } catch (e) {
        self.postMessage({ type: 'error', id, error: e?.message || String(e) });
    }
}

self.onmessage = (e) => {
    const { type, id, text, wasmPaths } = e.data || {};

    switch (type) {
        case 'init':
            initPipeline(wasmPaths);
            break;
        case 'detect':
            detectEntities(id, text);
            break;
        default:
            break;
    }
};
