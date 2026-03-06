/**
 * src/lib/WllamaManager.js
 * Compatibility shim — redirects to ThreataformEngine.
 *
 * All existing imports of `wllamaManager` from this file continue to work.
 * ThreataformEngine provides the same interface (loadFromUrl, loadFromFile,
 * generate, embed, embedQuery, isLoaded) plus new capabilities
 * (ingestFile, fineTune, saveLoRA, loadLoRA, search).
 */

export { threataformEngine as wllamaManager, threataformEngine as default } from './ThreataformEngine.js';
