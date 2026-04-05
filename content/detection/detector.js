/**
 * VaultBix Unified Detector
 * Combines three detection layers:
 *   Layer 1 – Fast regex patterns (synchronous, instant)
 *   Layer 2 – Local ML NER via Transformers.js (async, Web Worker)
 *   Layer 3 – Context-aware financial detection (regex + heuristics)
 *
 * All processing is 100 % local — no network requests for detection.
 */

import { REGEX_PATTERNS, CONTEXTUAL_PATTERNS, RISK_LEVELS, QUICK_CHECK_PATTERNS } from './patterns.js';
import { initML, detectEntitiesML, isMLReady } from './ml-detector.js';

// Start loading the ML model in the background (non-blocking)
initML();

// ── quick pre-filter ───────────────────────────────────────────────────────

/**
 * Fast early-exit check.  Returns false if the text is almost certainly
 * free of sensitive data, saving us from running the full analysis.
 */
export function quickCheck(text) {
    if (!text || text.length < 8) return false;
    return QUICK_CHECK_PATTERNS.some(p => p.test(text));
}

// ── main API ───────────────────────────────────────────────────────────────

/**
 * Run the full hybrid detection pipeline on `text`.
 *
 * Returns:
 *   { findings: Finding[], overallRisk: string|null, summary: object|null }
 *
 * A Finding has:
 *   source, type, name, risk, text, redacted, start, end, confidence?
 */
export async function detectSensitiveData(text, maxLength = 50000) {
    if (!text || typeof text !== 'string') {
        return { findings: [], overallRisk: null, summary: null };
    }

    const scanText = text.length > maxLength ? text.substring(0, maxLength) : text;
    const findings = [];

    // ── Layer 1: regex ─────────────────────────────────────────────────
    runRegexPatterns(scanText, findings);

    // ── Layer 3: contextual financial patterns (runs synchronously) ────
    runContextualPatterns(scanText, findings);

    // ── Layer 2: ML NER (async, non-blocking) ──────────────────────────
    if (isMLReady()) {
        await runMLDetection(scanText, findings);
    }

    // ── deduplicate & sort ─────────────────────────────────────────────
    const deduped = deduplicateFindings(findings);
    deduped.sort((a, b) => a.start - b.start);

    const overallRisk = determineOverallRisk(deduped);
    const summary = generateSummary(deduped);

    return { findings: deduped, overallRisk, summary };
}

// ── Layer 1: regex scan ────────────────────────────────────────────────────

function runRegexPatterns(text, findings) {
    const seenValues = new Set();

    for (const pat of REGEX_PATTERNS) {
        try {
            const re = new RegExp(pat.pattern.source, pat.pattern.flags + (pat.pattern.flags.includes('g') ? '' : 'g'));
            let match;
            while ((match = re.exec(text)) !== null) {
                const value = match[0];
                if (seenValues.has(value)) continue;
                if (pat.validate && !pat.validate(value, text)) continue;
                seenValues.add(value);

                findings.push({
                    source: 'regex',
                    type: pat.category,
                    id: pat.id,
                    name: pat.name,
                    risk: pat.risk,
                    text: value,
                    redacted: redactValue(value, pat),
                    start: match.index,
                    end: match.index + value.length
                });
            }
        } catch { /* skip broken pattern */ }
    }
}

// ── Layer 3: contextual financial detection ────────────────────────────────

function runContextualPatterns(text, findings) {
    for (const pat of CONTEXTUAL_PATTERNS) {
        try {
            // Check if the required context keywords exist in the text at all
            if (!pat.contextRequired.test(text)) continue;

            const re = new RegExp(pat.pattern.source, pat.pattern.flags + (pat.pattern.flags.includes('g') ? '' : 'g'));
            let match;
            while ((match = re.exec(text)) !== null) {
                const value = match[0];
                if (pat.validate && !pat.validate(value, text)) continue;

                // Verify that context keywords appear within the context window
                const windowStart = Math.max(0, match.index - pat.contextWindow);
                const windowEnd = Math.min(text.length, match.index + value.length + pat.contextWindow);
                const window = text.slice(windowStart, windowEnd);
                if (!pat.contextRequired.test(window)) continue;

                findings.push({
                    source: 'contextual',
                    type: pat.category,
                    id: pat.id,
                    name: pat.name,
                    risk: pat.risk,
                    text: value,
                    redacted: '[FINANCIAL]',
                    start: match.index,
                    end: match.index + value.length
                });
            }
        } catch { /* skip */ }
    }
}

// ── Layer 2: ML NER ────────────────────────────────────────────────────────

const NER_CATEGORY_MAP = {
    'PER':  { category: 'PERSON_NAME',   risk: 'HIGH',   name: 'Person Name' },
    'ORG':  { category: 'ORGANIZATION',  risk: 'MEDIUM', name: 'Organization Name' },
    'LOC':  { category: 'LOCATION',      risk: 'LOW',    name: 'Location' },
    'MISC': { category: 'MISC_ENTITY',   risk: 'LOW',    name: 'Miscellaneous Entity' }
};

async function runMLDetection(text, findings) {
    try {
        const entities = await detectEntitiesML(text);
        for (const entity of entities) {
            const mapped = NER_CATEGORY_MAP[entity.entity] || { category: 'UNKNOWN', risk: 'LOW', name: entity.entity };
            findings.push({
                source: 'ml',
                type: mapped.category,
                id: `ner_${entity.entity.toLowerCase()}`,
                name: mapped.name,
                risk: mapped.risk,
                text: entity.text,
                redacted: `[${mapped.name.toUpperCase()}]`,
                start: entity.start,
                end: entity.end,
                confidence: entity.score
            });
        }
    } catch { /* ML failure is non-fatal */ }
}

// ── deduplication ──────────────────────────────────────────────────────────

function deduplicateFindings(findings) {
    // Priority: regex > contextual > ml
    const sourcePriority = { regex: 0, contextual: 1, ml: 2 };
    const sorted = [...findings].sort((a, b) => {
        const pa = sourcePriority[a.source] ?? 9;
        const pb = sourcePriority[b.source] ?? 9;
        if (pa !== pb) return pa - pb;
        return a.start - b.start;
    });

    const result = [];
    const covered = new Set();

    for (const finding of sorted) {
        let dominated = false;
        for (let i = finding.start; i < finding.end; i++) {
            if (covered.has(i)) { dominated = true; break; }
        }
        if (!dominated) {
            result.push(finding);
            for (let i = finding.start; i < finding.end; i++) {
                covered.add(i);
            }
        }
    }

    return result;
}

// ── redaction helpers ──────────────────────────────────────────────────────

function redactValue(value, pattern) {
    if (!value || value.length <= 8) return '[REDACTED]';

    const cat = pattern.category;
    const id = pattern.id;

    if (cat === 'API_KEY' || cat === 'CREDENTIAL' || cat === 'PRIVATE_KEY') {
        const prefixLen = Math.min(6, Math.floor(value.length * 0.15));
        const suffixLen = Math.min(4, Math.floor(value.length * 0.1));
        return `${value.slice(0, prefixLen)}[REDACTED]${value.slice(-suffixLen)}`;
    }

    if (id && id.startsWith('credit_card')) {
        return `[CARD ending ${value.slice(-4)}]`;
    }

    if (id === 'ssn') {
        return `[SSN ending ${value.slice(-4)}]`;
    }

    if (id === 'email') {
        const atIndex = value.indexOf('@');
        if (atIndex > 0) return `${value[0]}***@${value.slice(atIndex + 1)}`;
    }

    return `${value.slice(0, 4)}[REDACTED]${value.slice(-4)}`;
}

/**
 * Redact all findings in the original text by replacing matched
 * spans with their redacted equivalents.
 */
export function redactText(originalText, findings) {
    if (!findings || findings.length === 0) return originalText;
    let redacted = originalText;
    // Process from end to start so indices stay valid
    const sorted = [...findings].sort((a, b) => b.start - a.start);
    for (const f of sorted) {
        redacted = redacted.slice(0, f.start) + f.redacted + redacted.slice(f.end);
    }
    return redacted;
}

// ── risk & summary helpers ─────────────────────────────────────────────────

function determineOverallRisk(findings) {
    if (findings.length === 0) return null;
    if (findings.some(f => f.risk === 'CRITICAL')) return 'CRITICAL';
    if (findings.some(f => f.risk === 'HIGH')) return 'HIGH';
    if (findings.some(f => f.risk === 'MEDIUM')) return 'MEDIUM';
    return 'LOW';
}

function generateSummary(findings) {
    if (findings.length === 0) return null;

    const types = [...new Set(findings.map(f => f.name))];
    const typeStr = types.length <= 3
        ? types.join(', ')
        : `${types.slice(0, 2).join(', ')} (+${types.length - 2} more)`;

    return {
        total: findings.length,
        types,
        message: `${findings.length} sensitive item${findings.length > 1 ? 's' : ''} detected: ${typeStr}`
    };
}

// ── re-exports for convenience ─────────────────────────────────────────────

export { RISK_LEVELS } from './patterns.js';
export { isMLReady } from './ml-detector.js';
