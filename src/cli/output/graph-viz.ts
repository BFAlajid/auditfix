/**
 * Dependency-graph visualization outputs: Mermaid, Graphviz DOT, and standalone HTML.
 *
 * The `AuditReport` type does not carry the dependency graph directly, so callers
 * attach the graph (and optional root-deps) to the report object as untyped fields.
 * This module reads those fields defensively — if the graph is missing, the output
 * is a minimal but valid artifact listing only vulnerable packages from the report.
 *
 * Severity color palette (shared across Mermaid fill, DOT fill, and HTML CSS class):
 *   critical → #ff6b6b / stroke #c92a2a
 *   high     → #ffa94d / stroke #d9480f
 *   medium   → #ffd43b / stroke #e67700
 *   low      → #a5d8ff / stroke #1971c2
 *   info     → #a5d8ff / stroke #1971c2
 */
import type { AuditReport, RiskScore } from '../../types/report.js';
import type { DependencyGraph } from '../../types/package.js';

/* ------------------------------------------------------------------ */
/*  Severity palette                                                   */
/* ------------------------------------------------------------------ */

type Severity = RiskScore['label'];

const SEVERITY_FILL: Record<Severity, string> = {
  critical: '#ff6b6b',
  high: '#ffa94d',
  medium: '#ffd43b',
  low: '#a5d8ff',
  info: '#a5d8ff',
};

const SEVERITY_STROKE: Record<Severity, string> = {
  critical: '#c92a2a',
  high: '#d9480f',
  medium: '#e67700',
  low: '#1971c2',
  info: '#1971c2',
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/* ------------------------------------------------------------------ */
/*  Graph-attached report helpers                                      */
/* ------------------------------------------------------------------ */

/**
 * Callers may attach a DependencyGraph and a list of root keys to the report
 * prior to rendering. This extends the public AuditReport contract without
 * forcing a type change on the core report.
 */
type GraphAttached = {
  graph?: DependencyGraph;
  rootKeys?: string[];
};

function getGraph(report: AuditReport): DependencyGraph | undefined {
  const maybe = report as AuditReport & GraphAttached;
  return maybe.graph;
}

function getRootKeys(report: AuditReport): string[] {
  const maybe = report as AuditReport & GraphAttached;
  if (Array.isArray(maybe.rootKeys) && maybe.rootKeys.length > 0) {
    return maybe.rootKeys;
  }
  // Fallback: infer roots as nodes whose depth === 0 (or depth === 1 if no 0 exists)
  const graph = maybe.graph;
  if (!graph) return [];
  const depthZero: string[] = [];
  const depthOne: string[] = [];
  for (const [key, node] of graph) {
    if (node.depth === 0) depthZero.push(key);
    else if (node.depth === 1) depthOne.push(key);
  }
  return depthZero.length > 0 ? depthZero : depthOne;
}

/**
 * Build a Map<nodeKey, highestSeverity> from the vulnerabilities list.
 * Key is the `name@version` string matching DependencyGraph keys.
 */
function buildVulnSeverityMap(report: AuditReport): Map<string, Severity> {
  const map = new Map<string, Severity>();
  for (const v of report.vulnerabilities) {
    const key = `${v.match.package}@${v.match.installedVersion}`;
    const existing = map.get(key);
    if (!existing || SEVERITY_RANK[v.risk.label] > SEVERITY_RANK[existing]) {
      map.set(key, v.risk.label);
    }
  }
  return map;
}

/* ------------------------------------------------------------------ */
/*  ID sanitization                                                    */
/* ------------------------------------------------------------------ */

/**
 * Mermaid and DOT both restrict node IDs. We encode arbitrary package keys
 * deterministically: replace every non-alphanumeric character with `_` and
 * prefix `p_` so the result always starts with a letter.
 */
export function sanitizeId(key: string): string {
  return 'p_' + key.replace(/[^a-zA-Z0-9]/g, '_');
}

/* ------------------------------------------------------------------ */
/*  Truncation: find which nodes to include                            */
/* ------------------------------------------------------------------ */

type IncludeSet = {
  keys: Set<string>;
  truncated: boolean;
  totalCount: number;
};

/**
 * Compute the set of node keys that should appear in the rendered graph.
 *
 * Policy:
 *   1. Always include: vulnerable nodes + all roots.
 *   2. Always include: every ancestor on a path from a root to a vulnerable node.
 *   3. If under `maxNodes`, also include direct dependencies of roots up to 2 levels.
 *   4. If still under `maxNodes`, include other nodes breadth-first from roots
 *      up to `maxDepth` edges away.
 *   5. Never exceed `maxNodes`. If exceeded before step 3/4, truncated=true.
 */
function computeIncludeSet(
  graph: DependencyGraph,
  rootKeys: string[],
  vulnKeys: Set<string>,
  maxNodes: number,
  maxDepth: number,
): IncludeSet {
  const total = graph.size;
  const include = new Set<string>();

  // Step 1: roots + vulnerable nodes
  for (const r of rootKeys) if (graph.has(r)) include.add(r);
  for (const v of vulnKeys) if (graph.has(v)) include.add(v);

  // Step 2: ancestor chains from roots to vulnerable nodes (forward BFS from roots
  // tracking parent, then walk back from each vuln).
  const parent = new Map<string, string>();
  const visited = new Set<string>();
  const queue: string[] = [...rootKeys.filter((r) => graph.has(r))];
  for (const r of queue) visited.add(r);

  while (queue.length > 0) {
    const cur = queue.shift()!;
    const node = graph.get(cur);
    if (!node) continue;
    for (const child of node.dependencies) {
      if (!graph.has(child)) continue;
      if (!visited.has(child)) {
        visited.add(child);
        parent.set(child, cur);
        queue.push(child);
      }
    }
  }

  for (const vk of vulnKeys) {
    let cur: string | undefined = vk;
    while (cur && graph.has(cur)) {
      include.add(cur);
      const p = parent.get(cur);
      if (!p || p === cur) break;
      cur = p;
    }
  }

  if (include.size > maxNodes) {
    // Even required set is too big — keep only vulns + roots and mark truncated.
    const pruned = new Set<string>();
    for (const r of rootKeys) if (graph.has(r)) pruned.add(r);
    for (const v of vulnKeys) if (graph.has(v)) pruned.add(v);
    // Cap pruned if still too large (vulns alone could exceed).
    if (pruned.size > maxNodes) {
      const ordered = [...pruned].slice(0, maxNodes);
      return {
        keys: new Set(ordered),
        truncated: true,
        totalCount: total,
      };
    }
    return { keys: pruned, truncated: true, totalCount: total };
  }

  // Step 3 & 4: breadth-first expansion from roots up to maxDepth, respecting cap.
  const depthMap = new Map<string, number>();
  for (const r of rootKeys) if (graph.has(r)) depthMap.set(r, 0);
  const bfsQueue: string[] = [...rootKeys.filter((r) => graph.has(r))];

  while (bfsQueue.length > 0 && include.size < maxNodes) {
    const cur = bfsQueue.shift()!;
    const curDepth = depthMap.get(cur) ?? 0;
    if (curDepth >= maxDepth) continue;
    const node = graph.get(cur);
    if (!node) continue;
    for (const child of node.dependencies) {
      if (!graph.has(child)) continue;
      if (!depthMap.has(child)) {
        depthMap.set(child, curDepth + 1);
        if (include.size < maxNodes) {
          include.add(child);
          bfsQueue.push(child);
        }
      }
    }
  }

  return {
    keys: include,
    truncated: total > include.size,
    totalCount: total,
  };
}

/* ------------------------------------------------------------------ */
/*  Mermaid                                                            */
/* ------------------------------------------------------------------ */

const MERMAID_MAX_NODES = 500;

export function renderMermaid(
  report: AuditReport,
  options?: { maxDepth?: number; highlightVulnerable?: boolean; direction?: 'LR' | 'TB' },
): string {
  const direction = options?.direction ?? 'LR';
  const maxDepth = options?.maxDepth ?? 4;
  const highlight = options?.highlightVulnerable ?? true;

  const graph = getGraph(report);
  const vulnSeverity = buildVulnSeverityMap(report);

  // No graph attached — render vulnerability-only diagram.
  if (!graph || graph.size === 0) {
    return renderMermaidVulnsOnly(report, direction, highlight, vulnSeverity);
  }

  const rootKeys = getRootKeys(report);
  const vulnKeys = new Set(vulnSeverity.keys());
  const include = computeIncludeSet(graph, rootKeys, vulnKeys, MERMAID_MAX_NODES, maxDepth);

  const lines: string[] = [];
  if (include.truncated) {
    lines.push(
      `%% Truncated: showing ${include.keys.size} of ${include.totalCount} nodes (focused on vulnerable + direct deps)`,
    );
  }
  lines.push(`graph ${direction}`);

  // Nodes
  for (const key of include.keys) {
    const node = graph.get(key);
    const label = node ? `${node.name}@${node.version}` : key;
    lines.push(`    ${sanitizeId(key)}["${escapeMermaidLabel(label)}"]`);
  }

  // Edges
  for (const key of include.keys) {
    const node = graph.get(key);
    if (!node) continue;
    for (const dep of node.dependencies) {
      if (!include.keys.has(dep)) continue;
      lines.push(`    ${sanitizeId(key)} --> ${sanitizeId(dep)}`);
    }
  }

  // Styles
  if (highlight) {
    for (const key of include.keys) {
      const sev = vulnSeverity.get(key);
      if (sev) {
        lines.push(
          `    style ${sanitizeId(key)} fill:${SEVERITY_FILL[sev]},stroke:${SEVERITY_STROKE[sev]}`,
        );
      }
    }
  }

  return lines.join('\n') + '\n';
}

function renderMermaidVulnsOnly(
  report: AuditReport,
  direction: 'LR' | 'TB',
  highlight: boolean,
  vulnSeverity: Map<string, Severity>,
): string {
  const lines: string[] = [`graph ${direction}`];
  if (report.vulnerabilities.length === 0) {
    lines.push(`    empty["No vulnerabilities"]`);
    return lines.join('\n') + '\n';
  }
  for (const [key, sev] of vulnSeverity) {
    const label = escapeMermaidLabel(key);
    lines.push(`    ${sanitizeId(key)}["${label}"]`);
    if (highlight) {
      lines.push(
        `    style ${sanitizeId(key)} fill:${SEVERITY_FILL[sev]},stroke:${SEVERITY_STROKE[sev]}`,
      );
    }
  }
  return lines.join('\n') + '\n';
}

function escapeMermaidLabel(s: string): string {
  // Mermaid labels in quoted form need to escape double quotes; also strip
  // problematic characters that can break the parser inside `"..."` labels.
  return s.replace(/"/g, '#quot;').replace(/[\r\n]/g, ' ');
}

/* ------------------------------------------------------------------ */
/*  DOT (Graphviz)                                                     */
/* ------------------------------------------------------------------ */

const DOT_MAX_NODES = 1000;

export function renderDot(
  report: AuditReport,
  options?: { maxDepth?: number; highlightVulnerable?: boolean },
): string {
  const maxDepth = options?.maxDepth ?? 4;
  const highlight = options?.highlightVulnerable ?? true;

  const graph = getGraph(report);
  const vulnSeverity = buildVulnSeverityMap(report);

  const lines: string[] = [];
  lines.push('digraph DependencyGraph {');
  lines.push('    rankdir=LR;');
  lines.push('    node [shape=box, style=filled, fillcolor="#f8f9fa"];');

  if (!graph || graph.size === 0) {
    // No graph — list vulnerabilities only.
    if (report.vulnerabilities.length === 0) {
      lines.push('    empty [label="No vulnerabilities"];');
    } else {
      for (const [key, sev] of vulnSeverity) {
        lines.push(
          `    ${sanitizeId(key)} [label="${escapeDotLabel(key)}", fillcolor="${SEVERITY_FILL[sev]}", color="${SEVERITY_STROKE[sev]}"];`,
        );
      }
    }
    appendDotLegend(lines);
    lines.push('}');
    return lines.join('\n') + '\n';
  }

  const rootKeys = getRootKeys(report);
  const vulnKeys = new Set(vulnSeverity.keys());
  const include = computeIncludeSet(graph, rootKeys, vulnKeys, DOT_MAX_NODES, maxDepth);

  if (include.truncated) {
    lines.push(
      `    // Truncated: showing ${include.keys.size} of ${include.totalCount} nodes`,
    );
  }

  // Nodes
  for (const key of include.keys) {
    const node = graph.get(key);
    const label = node ? `${node.name}@${node.version}` : key;
    const sev = highlight ? vulnSeverity.get(key) : undefined;
    if (sev) {
      lines.push(
        `    ${sanitizeId(key)} [label="${escapeDotLabel(label)}", fillcolor="${SEVERITY_FILL[sev]}", color="${SEVERITY_STROKE[sev]}"];`,
      );
    } else {
      lines.push(`    ${sanitizeId(key)} [label="${escapeDotLabel(label)}"];`);
    }
  }

  // Edges
  for (const key of include.keys) {
    const node = graph.get(key);
    if (!node) continue;
    for (const dep of node.dependencies) {
      if (!include.keys.has(dep)) continue;
      lines.push(`    ${sanitizeId(key)} -> ${sanitizeId(dep)};`);
    }
  }

  appendDotLegend(lines);
  lines.push('}');
  return lines.join('\n') + '\n';
}

function appendDotLegend(lines: string[]): void {
  lines.push('    subgraph cluster_legend {');
  lines.push('        label="Severity Legend";');
  lines.push('        style=dashed;');
  lines.push(
    `        legend_critical [label="critical", fillcolor="${SEVERITY_FILL.critical}", color="${SEVERITY_STROKE.critical}"];`,
  );
  lines.push(
    `        legend_high [label="high", fillcolor="${SEVERITY_FILL.high}", color="${SEVERITY_STROKE.high}"];`,
  );
  lines.push(
    `        legend_medium [label="medium", fillcolor="${SEVERITY_FILL.medium}", color="${SEVERITY_STROKE.medium}"];`,
  );
  lines.push(
    `        legend_low [label="low/info", fillcolor="${SEVERITY_FILL.low}", color="${SEVERITY_STROKE.low}"];`,
  );
  lines.push('    }');
}

function escapeDotLabel(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[\r\n]/g, ' ');
}

/* ------------------------------------------------------------------ */
/*  Standalone HTML (pure SVG, zero JS, zero CDN)                      */
/* ------------------------------------------------------------------ */

const HTML_MAX_NODES = 2000;
const VERSION = '2.0.0';

export function renderHTML(report: AuditReport, projectName: string): string {
  const graph = getGraph(report);
  const vulnSeverity = buildVulnSeverityMap(report);

  // Severity counts
  const sevCounts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const v of report.vulnerabilities) sevCounts[v.risk.label]++;

  const totalPackages = graph?.size ?? report.metadata.totalPackages;
  const timestamp = new Date().toISOString();

  // Pick nodes to display
  let includeKeys: Set<string> = new Set();
  let truncated = false;
  let totalCount = totalPackages;
  let rootKeys: string[] = [];

  if (graph && graph.size > 0) {
    rootKeys = getRootKeys(report);
    const vulnKeys = new Set(vulnSeverity.keys());
    const include = computeIncludeSet(graph, rootKeys, vulnKeys, HTML_MAX_NODES, 4);
    includeKeys = include.keys;
    truncated = include.truncated;
    totalCount = include.totalCount;
  }

  const svg = graph && graph.size > 0
    ? renderSvgTree(graph, rootKeys, includeKeys, vulnSeverity)
    : renderSvgEmpty(vulnSeverity);

  const body = [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    `<title>${escapeHtml(projectName)} — auditfix dependency graph</title>`,
    '<style>',
    htmlCss(),
    '</style>',
    '</head>',
    '<body>',
    '<header>',
    `<h1>${escapeHtml(projectName)}</h1>`,
    `<p class="meta">Scanned: ${escapeHtml(timestamp)} · Packages: ${totalPackages} · Vulnerabilities: ${report.vulnerabilities.length}</p>`,
    '<p class="meta">',
    `<span class="badge sev-critical">critical ${sevCounts.critical}</span> `,
    `<span class="badge sev-high">high ${sevCounts.high}</span> `,
    `<span class="badge sev-medium">medium ${sevCounts.medium}</span> `,
    `<span class="badge sev-low">low ${sevCounts.low}</span> `,
    `<span class="badge sev-info">info ${sevCounts.info}</span>`,
    '</p>',
    '</header>',
    '<section class="legend">',
    '<h2>Legend</h2>',
    '<ul>',
    '<li><span class="swatch sev-critical"></span> Critical</li>',
    '<li><span class="swatch sev-high"></span> High</li>',
    '<li><span class="swatch sev-medium"></span> Medium</li>',
    '<li><span class="swatch sev-low"></span> Low</li>',
    '<li><span class="swatch sev-info"></span> Info / clean</li>',
    '</ul>',
    '</section>',
    '<main>',
    truncated
      ? `<p class="note">Truncated: showing ${includeKeys.size} of ${totalCount} packages (focused on vulnerable + direct deps).</p>`
      : '',
    svg,
    '</main>',
    '<footer>',
    `<p>Generated by auditfix v${VERSION}</p>`,
    '</footer>',
    '</body>',
    '</html>',
    '',
  ].join('\n');

  return body;
}

function htmlCss(): string {
  return [
    'body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;padding:1.5rem;color:#212529;background:#fff;}',
    'header h1{margin:0 0 .25rem 0;font-size:1.5rem;}',
    '.meta{color:#495057;font-size:.9rem;margin:.25rem 0;}',
    '.badge{display:inline-block;padding:.15rem .5rem;border-radius:.25rem;font-size:.8rem;margin-right:.25rem;}',
    '.legend{margin:1rem 0;}',
    '.legend ul{list-style:none;padding:0;display:flex;flex-wrap:wrap;gap:1rem;}',
    '.swatch{display:inline-block;width:12px;height:12px;margin-right:.25rem;border:1px solid #555;vertical-align:middle;}',
    `.sev-critical,.swatch.sev-critical,.badge.sev-critical{background:${SEVERITY_FILL.critical};}`,
    `.sev-high,.swatch.sev-high,.badge.sev-high{background:${SEVERITY_FILL.high};}`,
    `.sev-medium,.swatch.sev-medium,.badge.sev-medium{background:${SEVERITY_FILL.medium};}`,
    `.sev-low,.swatch.sev-low,.badge.sev-low{background:${SEVERITY_FILL.low};}`,
    `.sev-info,.swatch.sev-info,.badge.sev-info{background:${SEVERITY_FILL.info};}`,
    '.note{background:#fff3bf;border-left:4px solid #f59f00;padding:.5rem .75rem;margin:1rem 0;}',
    'main{overflow:auto;border:1px solid #dee2e6;padding:.5rem;background:#f8f9fa;}',
    'svg{display:block;max-width:100%;height:auto;}',
    'svg .node rect{fill:#fff;stroke:#495057;stroke-width:1;}',
    'svg .node text{font-family:monospace;font-size:10px;fill:#212529;}',
    'svg .edge{stroke:#868e96;stroke-width:1;fill:none;}',
    `svg .node.sev-critical rect{fill:${SEVERITY_FILL.critical};stroke:${SEVERITY_STROKE.critical};stroke-width:2;}`,
    `svg .node.sev-high rect{fill:${SEVERITY_FILL.high};stroke:${SEVERITY_STROKE.high};stroke-width:2;}`,
    `svg .node.sev-medium rect{fill:${SEVERITY_FILL.medium};stroke:${SEVERITY_STROKE.medium};stroke-width:2;}`,
    `svg .node.sev-low rect{fill:${SEVERITY_FILL.low};stroke:${SEVERITY_STROKE.low};stroke-width:2;}`,
    `svg .node.sev-info rect{fill:${SEVERITY_FILL.info};stroke:${SEVERITY_STROKE.info};stroke-width:2;}`,
    'footer{margin-top:1.5rem;color:#868e96;font-size:.8rem;text-align:center;}',
  ].join('\n');
}

/**
 * Render a rooted, top-down SVG tree of the included nodes.
 * Layout is a simple layered BFS: depth = layer, sibling order = insertion.
 * For 2000+ nodes this produces a wide but readable image; callers pan with
 * the overflowing <main> container.
 */
function renderSvgTree(
  graph: DependencyGraph,
  rootKeys: string[],
  includeKeys: Set<string>,
  vulnSeverity: Map<string, Severity>,
): string {
  type Layout = { key: string; x: number; y: number; label: string; sev?: Severity };
  const layouts: Layout[] = [];
  const positions = new Map<string, { x: number; y: number }>();

  const layers: string[][] = [];
  const seen = new Set<string>();
  const rootsInInclude = rootKeys.filter((r) => includeKeys.has(r));
  const initial = rootsInInclude.length > 0 ? rootsInInclude : [...includeKeys].slice(0, 1);
  layers.push(initial);
  for (const k of initial) seen.add(k);

  while (true) {
    const current = layers[layers.length - 1];
    const next: string[] = [];
    for (const key of current) {
      const node = graph.get(key);
      if (!node) continue;
      for (const dep of node.dependencies) {
        if (!includeKeys.has(dep) || seen.has(dep)) continue;
        seen.add(dep);
        next.push(dep);
      }
    }
    if (next.length === 0) break;
    layers.push(next);
  }

  // Any included node not yet placed (e.g. disconnected or unreachable from roots)
  // goes into a final "orphan" layer so every included node renders somewhere.
  const orphans = [...includeKeys].filter((k) => !seen.has(k));
  if (orphans.length > 0) layers.push(orphans);

  const NODE_W = 160;
  const NODE_H = 28;
  const GAP_X = 20;
  const GAP_Y = 60;

  let maxCols = 0;
  for (let li = 0; li < layers.length; li++) {
    const layer = layers[li];
    if (layer.length > maxCols) maxCols = layer.length;
  }
  const width = Math.max(maxCols, 1) * (NODE_W + GAP_X) + GAP_X;
  const height = layers.length * (NODE_H + GAP_Y) + GAP_Y;

  for (let li = 0; li < layers.length; li++) {
    const layer = layers[li];
    const rowWidth = layer.length * (NODE_W + GAP_X);
    const startX = (width - rowWidth) / 2;
    for (let ci = 0; ci < layer.length; ci++) {
      const key = layer[ci];
      const node = graph.get(key);
      const label = node ? `${node.name}@${node.version}` : key;
      const x = startX + ci * (NODE_W + GAP_X);
      const y = li * (NODE_H + GAP_Y) + GAP_Y;
      positions.set(key, { x, y });
      layouts.push({ key, x, y, label, sev: vulnSeverity.get(key) });
    }
  }

  const parts: string[] = [];
  parts.push(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">`,
  );

  // Edges first (so nodes render on top)
  for (const key of includeKeys) {
    const node = graph.get(key);
    if (!node) continue;
    const from = positions.get(key);
    if (!from) continue;
    for (const dep of node.dependencies) {
      if (!includeKeys.has(dep)) continue;
      const to = positions.get(dep);
      if (!to) continue;
      const x1 = from.x + NODE_W / 2;
      const y1 = from.y + NODE_H;
      const x2 = to.x + NODE_W / 2;
      const y2 = to.y;
      parts.push(
        `<path class="edge" d="M${x1} ${y1} C${x1} ${(y1 + y2) / 2} ${x2} ${(y1 + y2) / 2} ${x2} ${y2}"/>`,
      );
    }
  }

  // Nodes
  for (const l of layouts) {
    const cls = l.sev ? `node sev-${l.sev}` : 'node sev-info';
    const truncLabel = l.label.length > 22 ? l.label.slice(0, 21) + '…' : l.label;
    parts.push(
      `<g class="${cls}" transform="translate(${l.x} ${l.y})"><rect width="${NODE_W}" height="${NODE_H}" rx="4"/><text x="8" y="18">${escapeHtml(truncLabel)}</text></g>`,
    );
  }

  parts.push('</svg>');
  return parts.join('\n');
}

function renderSvgEmpty(vulnSeverity: Map<string, Severity>): string {
  const entries = [...vulnSeverity];
  if (entries.length === 0) {
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 60" width="400" height="60"><text x="8" y="35" font-family="monospace" font-size="12" fill="#495057">No packages and no vulnerabilities.</text></svg>';
  }
  const NODE_W = 200;
  const NODE_H = 28;
  const GAP_Y = 10;
  const height = entries.length * (NODE_H + GAP_Y) + GAP_Y;
  const parts: string[] = [];
  parts.push(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${NODE_W + 40} ${height}" width="${NODE_W + 40}" height="${height}">`,
  );
  entries.forEach(([key, sev], i) => {
    const y = GAP_Y + i * (NODE_H + GAP_Y);
    const truncLabel = key.length > 28 ? key.slice(0, 27) + '…' : key;
    parts.push(
      `<g class="node sev-${sev}" transform="translate(20 ${y})"><rect width="${NODE_W}" height="${NODE_H}" rx="4"/><text x="8" y="18">${escapeHtml(truncLabel)}</text></g>`,
    );
  });
  parts.push('</svg>');
  return parts.join('\n');
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
