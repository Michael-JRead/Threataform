// src/features/intelligence/panelHelpers.jsx
// Shared helpers for IntelligencePanel tab components.
import React, { useState } from 'react';
import { C, MONO, SANS } from '../../constants/styles.js';

export const SEV_COLOR = { Critical: '#B71C1C', High: '#E53935', Medium: '#F57C00', Low: '#43A047' };
export const STRIDE_COLORS = { spoofing: '#E91E63', tampering: '#FF5722', repudiation: '#9C27B0', infoDisclose: '#F44336', dos: '#FF9800', elevPriv: '#B71C1C' };
export const STRIDE_LABELS = { spoofing: 'Spoofing', tampering: 'Tampering', repudiation: 'Repudiation', infoDisclose: 'Info Disclosure', dos: 'Denial of Service', elevPriv: 'Elevation of Privilege' };
export const COMPLIANCE_LABELS = { hipaa: 'HIPAA', fedramp: 'FedRAMP', soc2: 'SOC 2', pci: 'PCI DSS', gdpr: 'GDPR', cmmc: 'CMMC', iso27001: 'ISO 27001' };

export const catColor = (cat) => ({ 'threat-model': '#E53935', 'compliance': '#0277BD', 'architecture': '#4527A0', 'runbook': '#6A1B9A', 'terraform': '#5C4033' }[cat] || '#78909C');

export function catPill(label, color) {
  return <span style={{ background: color + '22', color, border: '1px solid ' + color + '44', borderRadius: 10, padding: '1px 8px', fontSize: 10, fontWeight: 600 }}>{label}</span>;
}

// ── Inline markdown formatter (bold, code, [DOC-N] refs) ─────────────────
export const inlineFormat = (text, key = 0) => {
  const parts = [];
  const rx = /(\*\*[^*]+\*\*|`[^`]+`|\[DOC-\d+\])/g;
  let last = 0, m;
  while ((m = rx.exec(text)) !== null) {
    if (m.index > last) parts.push(<span key={`t${last}`}>{text.slice(last, m.index)}</span>);
    const tok = m[0];
    if (tok.startsWith('**'))
      parts.push(<strong key={`b${m.index}`} style={{ color: C.text, fontWeight: 700 }}>{tok.slice(2, -2)}</strong>);
    else if (tok.startsWith('`'))
      parts.push(<code key={`c${m.index}`} style={{ ...MONO, fontSize: 11, background: C.bg, padding: '1px 5px', borderRadius: 3, color: C.accent }}>{tok.slice(1, -1)}</code>);
    else
      parts.push(<span key={`d${m.index}`} style={{ color: C.accent, fontWeight: 600 }}>{tok}</span>);
    last = m.index + tok.length;
  }
  if (last < text.length) parts.push(<span key={`e${last}`}>{text.slice(last)}</span>);
  return parts.length ? parts : [text];
};

// ── Render markdown text to JSX ──────────────────────────────────────────
export const renderMarkdown = (text) => {
  if (!text?.trim()) return null;
  const blocks = text.split(/\n\n+/);
  return blocks.map((block, bi) => {
    const trim = block.trim();
    // ATX headings
    const headM = trim.match(/^(#{1,3})\s+(.+)/);
    if (headM) {
      const sz = { 1: 15, 2: 13, 3: 12 }[headM[1].length] || 12;
      return <div key={bi} style={{ fontSize: sz, fontWeight: 700, color: C.text, marginTop: 10, marginBottom: 4 }}>{headM[2]}</div>;
    }
    // Bullet list block
    if (/^[-*•]\s/.test(trim)) {
      const items = trim.split('\n').filter(l => /^[-*•]\s/.test(l.trim())).map(l => l.trim().replace(/^[-*•]\s/, ''));
      return (
        <div key={bi} style={{ marginBottom: 6 }}>
          {items.map((item, ii) => (
            <div key={ii} style={{ display: 'flex', gap: 7, marginBottom: 3, alignItems: 'flex-start' }}>
              <span style={{ color: C.accent, flexShrink: 0, lineHeight: '18px' }}>•</span>
              <span style={{ fontSize: 12, color: C.textSub, lineHeight: 1.65 }}>{inlineFormat(item, ii)}</span>
            </div>
          ))}
        </div>
      );
    }
    // Numbered list
    if (/^\d+\.\s/.test(trim)) {
      const items = trim.split('\n').filter(l => /^\d+\.\s/.test(l.trim())).map(l => l.trim().replace(/^\d+\.\s/, ''));
      return (
        <div key={bi} style={{ marginBottom: 6 }}>
          {items.map((item, ii) => (
            <div key={ii} style={{ display: 'flex', gap: 8, marginBottom: 4, alignItems: 'flex-start' }}>
              <span style={{ color: C.accent, flexShrink: 0, fontWeight: 700, lineHeight: '18px', minWidth: 16 }}>{ii + 1}.</span>
              <span style={{ fontSize: 12, color: C.textSub, lineHeight: 1.65 }}>{inlineFormat(item, ii)}</span>
            </div>
          ))}
        </div>
      );
    }
    // Horizontal rule
    if (/^---+$/.test(trim)) return <div key={bi} style={{ borderTop: `1px solid ${C.border}`, margin: '8px 0' }} />;
    // Regular paragraph
    return <p key={bi} style={{ fontSize: 12, color: C.textSub, lineHeight: 1.7, margin: '4px 0' }}>{inlineFormat(trim, bi)}</p>;
  });
};

// ── Evidence UI helpers ──────────────────────────────────────────────────
export const ConfidenceBadge = ({ ev }) => {
  if (!ev) return null;
  const c = ev.confidence ?? 50;
  const color = c >= 80 ? '#2E7D32' : c >= 55 ? '#F57C00' : '#B71C1C';
  const label = ev.source === 'hcl' ? 'HCL' : ev.source === 'doc' ? 'DOC' : 'INFER';
  const tip = `Method: ${ev.method}\nConfidence: ${c}%\n${ev.snippet ? 'Evidence: ' + ev.snippet.slice(0, 100) : ''}`;
  return (
    <span title={tip} style={{
      display: 'inline-flex', alignItems: 'center', gap: 2,
      background: `${color}18`, border: `1px solid ${color}40`,
      borderRadius: 4, padding: '1px 5px', fontSize: 9,
      color, cursor: 'help', fontWeight: 700, flexShrink: 0
    }}>
      {label} {c}%
    </span>
  );
};

export const EvidenceDrawer = ({ ev, label = 'evidence' }) => {
  const [evOpen, setEvOpen] = useState(false);
  if (!ev?.snippet) return null;
  return (
    <div>
      <span onClick={() => setEvOpen(o => !o)}
        style={{ cursor: 'pointer', fontSize: 9, color: C.textMuted, userSelect: 'none' }}>
        {evOpen ? '▲ hide' : '▼'} {label}
      </span>
      {evOpen && (
        <div style={{
          marginTop: 5, padding: '5px 8px', background: C.bg, borderRadius: 4,
          fontSize: 10, fontFamily: 'monospace', lineHeight: 1.5, maxHeight: 100, overflow: 'auto',
          border: `1px solid ${C.border}`, whiteSpace: 'pre-wrap', wordBreak: 'break-word'
        }}>
          {ev.snippet}
          {ev.location && <div style={{ fontSize: 9, color: C.textMuted, marginTop: 2 }}>↳ {ev.location}</div>}
        </div>
      )}
    </div>
  );
};

// ── Chunk card (document passage display) ───────────────────────────────
export const chunkCard = (chunk, i) => (
  <div key={i} style={{
    background: C.surface, border: `1px solid ${C.border}`,
    borderRadius: 8, padding: '12px 14px', marginBottom: 8,
  }}>
    <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6, flexWrap: 'wrap' }}>
      <span style={{ background: `${C.accent}22`, color: C.accent, border: `1px solid ${C.accent}44`,
        borderRadius: 10, padding: '1px 8px', fontSize: 10, fontWeight: 600 }}>{chunk.source}</span>
      {catPill(chunk.category, catColor(chunk.category))}
      {chunk.confidence != null && (
        <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ fontSize: 9, color: C.textMuted }}>match</span>
          <span style={{ fontSize: 11, fontWeight: 700,
            color: chunk.confidence >= 80 ? '#2E7D32' : chunk.confidence >= 50 ? '#F57C00' : '#E53935' }}>
            {chunk.confidence}%
          </span>
          <div style={{ width: 40, height: 4, background: C.border, borderRadius: 2, overflow: 'hidden' }}>
            <div style={{ width: `${chunk.confidence}%`, height: '100%', borderRadius: 2,
              background: chunk.confidence >= 80 ? '#2E7D32' : chunk.confidence >= 50 ? '#F57C00' : '#E53935' }} />
          </div>
        </span>
      )}
    </div>
    {chunk.compressed && chunk.compressed !== chunk.text && (
      <div style={{ ...MONO, fontSize: 11, color: C.accent, lineHeight: 1.6,
        background: `${C.accent}08`, padding: '5px 8px', borderRadius: 5,
        border: `1px solid ${C.accent}22`, marginBottom: 4, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
        ✦ {chunk.compressed}
      </div>
    )}
    <div style={{ ...MONO, fontSize: 12, color: C.textSub, lineHeight: 1.65,
      background: C.bg, padding: '8px 10px', borderRadius: 6,
      border: `1px solid ${C.border}`, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
      &ldquo;{chunk.text}&rdquo;
    </div>
    {Object.entries(chunk.entities || {}).some(([, s]) => Object.keys(s).length > 0) && (
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 6 }}>
        {Object.entries(chunk.entities.stride || {}).map(([k]) => (
          <span key={k} style={{ background: `${STRIDE_COLORS[k] || '#999'}18`, color: STRIDE_COLORS[k] || '#999',
            border: `1px solid ${STRIDE_COLORS[k] || '#999'}44`, borderRadius: 6, padding: '1px 6px', fontSize: 9, fontWeight: 600 }}>
            STRIDE·{STRIDE_LABELS[k] || k}
          </span>
        ))}
        {Object.entries(chunk.entities.attack || {}).slice(0, 3).map(([k]) => (
          <span key={k} style={{ background: '#E5393514', color: '#E53935', border: '1px solid #E5393530',
            borderRadius: 6, padding: '1px 6px', fontSize: 9, fontWeight: 600 }}>{k}</span>
        ))}
        {Object.entries(chunk.entities.compliance || {}).map(([k]) => (
          <span key={k} style={{ background: '#0277BD18', color: '#0277BD', border: '1px solid #0277BD44',
            borderRadius: 6, padding: '1px 6px', fontSize: 9, fontWeight: 600 }}>{COMPLIANCE_LABELS[k] || k}</span>
        ))}
        {Object.entries(chunk.entities.security || {}).slice(0, 2).map(([k]) => (
          <span key={k} style={{ background: '#2E7D3218', color: '#2E7D32', border: '1px solid #2E7D3244',
            borderRadius: 6, padding: '1px 6px', fontSize: 9, fontWeight: 600 }}>{k}</span>
        ))}
      </div>
    )}
  </div>
);
