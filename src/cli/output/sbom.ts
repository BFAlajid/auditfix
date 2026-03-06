/**
 * CycloneDX 1.5 SBOM generation.
 * Produces a minimal but valid CycloneDX JSON SBOM from the dependency graph.
 */
import type { DependencyGraph } from '../../types/package.js';

const CYCLONEDX_SPEC = '1.5';
const CYCLONEDX_FORMAT = 'CycloneDX';

type CdxComponent = {
  type: 'library';
  name: string;
  version: string;
  purl: string;
  scope?: 'required' | 'optional' | 'excluded';
};

type CdxDependency = {
  ref: string;
  dependsOn: string[];
};

/**
 * Generate a CycloneDX 1.5 JSON SBOM from a dependency graph.
 */
export function generateSbom(
  graph: DependencyGraph,
  toolVersion: string,
  projectName?: string,
): string {
  const components: CdxComponent[] = [];
  const dependencies: CdxDependency[] = [];
  const seen = new Set<string>();

  for (const [graphKey, node] of graph) {
    if (seen.has(`${node.name}@${node.version}`)) continue;
    seen.add(`${node.name}@${node.version}`);

    const purl = `pkg:npm/${encodePackageName(node.name)}@${node.version}`;

    components.push({
      type: 'library',
      name: node.name,
      version: node.version,
      purl,
      scope: node.isOptional ? 'optional' : node.isDev ? 'excluded' : 'required',
    });

    dependencies.push({
      ref: purl,
      dependsOn: node.dependencies
        .map((depKey) => {
          const dep = graph.get(depKey);
          if (!dep) return null;
          return `pkg:npm/${encodePackageName(dep.name)}@${dep.version}`;
        })
        .filter((d): d is string => d !== null),
    });
  }

  const sbom = {
    bomFormat: CYCLONEDX_FORMAT,
    specVersion: CYCLONEDX_SPEC,
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'auditfix',
          name: 'auditfix',
          version: toolVersion,
        },
      ],
      ...(projectName ? { component: { type: 'application', name: projectName } } : {}),
    },
    components,
    dependencies,
  };

  return JSON.stringify(sbom, null, 2);
}

function encodePackageName(name: string): string {
  // Scoped packages: @scope/name -> %40scope/name
  if (name.startsWith('@')) {
    return '%40' + name.slice(1);
  }
  return name;
}
