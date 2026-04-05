/**
 * VaultBix ML Detector
 * Manages a Web Worker running Transformers.js NER and provides
 * a simple async API to the rest of the extension.
 *
 * All ML inference runs off the main thread.  If the worker fails
 * to load (old browser, restricted CSP, etc.) detection degrades
 * gracefully to regex-only.
 */

let worker = null;
let isReady = false;
let pendingRequests = new Map();
let requestCounter = 0;

/**
 * Spin up the ML worker and begin downloading / caching the model.
 * Safe to call multiple times; only the first call has an effect.
 */
export function initML() {
    if (worker) return;

    try {
        const workerUrl = chrome.runtime.getURL('ml-worker.js');
        worker = new Worker(workerUrl);

        worker.onmessage = (e) => {
            const msg = e.data || {};

            switch (msg.type) {
                case 'init_done':
                    isReady = true;
                    break;

                case 'init_error':
                    console.warn('[VaultBix] ML model failed to load, falling back to regex-only:', msg.error);
                    terminateWorker();
                    break;

                case 'result': {
                    const resolve = pendingRequests.get(msg.id);
                    if (resolve) {
                        pendingRequests.delete(msg.id);
                        resolve(msg.entities || []);
                    }
                    break;
                }

                case 'error': {
                    const resolve2 = pendingRequests.get(msg.id);
                    if (resolve2) {
                        pendingRequests.delete(msg.id);
                        resolve2([]);
                    }
                    break;
                }
            }
        };

        worker.onerror = () => {
            console.warn('[VaultBix] ML worker error, falling back to regex-only');
            terminateWorker();
        };

        // Kick off model download / warm-up
        const extensionRoot = chrome.runtime.getURL('/');
        worker.postMessage({ type: 'init', wasmPaths: extensionRoot });

    } catch (e) {
        console.warn('[VaultBix] Could not create ML worker:', e);
        worker = null;
    }
}

function terminateWorker() {
    if (worker) {
        try { worker.terminate(); } catch { /* ignore */ }
        worker = null;
    }
    isReady = false;
    // Resolve any pending requests with empty results
    for (const resolve of pendingRequests.values()) {
        resolve([]);
    }
    pendingRequests.clear();
}

/**
 * Returns true when the ML model is loaded and ready for inference.
 */
export function isMLReady() {
    return isReady;
}

/**
 * Run NER on the given text.  Returns an array of entity objects:
 *   { entity: 'PER'|'ORG'|'LOC'|'MISC', text: string, score: number, start: number, end: number }
 *
 * Returns [] if the model hasn't loaded yet or on any error.
 * Timeout: 10 seconds per request.
 */
export function detectEntitiesML(text) {
    if (!worker || !isReady) return Promise.resolve([]);

    const id = String(++requestCounter);

    return new Promise((resolve) => {
        pendingRequests.set(id, resolve);

        // Safety timeout so we never hang the UI
        const timer = setTimeout(() => {
            if (pendingRequests.has(id)) {
                pendingRequests.delete(id);
                resolve([]);
            }
        }, 10000);

        // Clean up timer on normal resolution
        const originalResolve = pendingRequests.get(id);
        pendingRequests.set(id, (result) => {
            clearTimeout(timer);
            originalResolve(result);
        });

        worker.postMessage({ type: 'detect', id, text });
    });
}
