import type { Files, Finding, Severity } from './types';
import { findBlocks, hBool, hList, hNum, hStr, refName, resourcesOf, type Resource } from './hcl';

// Checkov-style policy checks for Terraform (AWS) with inline
// `#checkov:skip=CKV_ID:reason` suppressions.

export interface CheckResult {
  id: string;
  name: string;
  severity: Severity;
  resource: string;
  file: string;
  lines: [number, number];
  status: 'PASSED' | 'FAILED' | 'SKIPPED';
  skipReason?: string;
  guide: string;
}

interface Check {
  id: string;
  name: string;
  severity: Severity;
  types: string[];
  /** true = pass */
  eval: (r: Resource, all: Resource[]) => boolean;
}

const bucketHas = (all: Resource[], type: string, bucket: string, pred: (r: Resource) => boolean) =>
  all.some((x) => x.type === type && refName(x.block.attrs.bucket, 'aws_s3_bucket') === bucket && pred(x));

export function ingressRules(r: Resource): { from: number; to: number; cidrs: string[] }[] {
  return findBlocks(r.block, 'ingress').map((b) => {
    const all = hStr(b.attrs.protocol) === '-1';
    return { from: all ? 0 : (hNum(b.attrs.from_port) ?? 0), to: all ? 65535 : (hNum(b.attrs.to_port) ?? 65535), cidrs: hList(b.attrs.cidr_blocks) };
  });
}

const openTo = (r: Resource, port: number) => ingressRules(r).some((p) => p.cidrs.includes('0.0.0.0/0') && p.from <= port && p.to >= port);

const CHECKS: Check[] = [
  { id: 'CKV_AWS_20', name: 'S3 Bucket has an ACL defined which allows public READ access.', severity: 'HIGH', types: ['aws_s3_bucket_acl', 'aws_s3_bucket'], eval: (r) => !['public-read', 'public-read-write', 'authenticated-read'].includes(hStr(r.block.attrs.acl) ?? '') },
  { id: 'CKV_AWS_57', name: 'S3 Bucket has an ACL defined which allows public WRITE access.', severity: 'CRITICAL', types: ['aws_s3_bucket_acl', 'aws_s3_bucket'], eval: (r) => hStr(r.block.attrs.acl) !== 'public-read-write' },
  {
    id: 'CKV2_AWS_6',
    name: 'Ensure that S3 bucket has a Public Access block',
    severity: 'MEDIUM',
    types: ['aws_s3_bucket'],
    eval: (r, all) => bucketHas(all, 'aws_s3_bucket_public_access_block', r.name, (x) => ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets'].every((k) => hBool(x.block.attrs[k]) === true)),
  },
  {
    id: 'CKV_AWS_145',
    name: 'Ensure that S3 buckets are encrypted with KMS by default',
    severity: 'MEDIUM',
    types: ['aws_s3_bucket'],
    eval: (r, all) => bucketHas(all, 'aws_s3_bucket_server_side_encryption_configuration', r.name, (x) => findBlocks(x.block, 'apply_server_side_encryption_by_default').some((b) => hStr(b.attrs.sse_algorithm) === 'aws:kms')),
  },
  { id: 'CKV_AWS_24', name: 'Ensure no security groups allow ingress from 0.0.0.0:0 to port 22', severity: 'HIGH', types: ['aws_security_group'], eval: (r) => !openTo(r, 22) },
  { id: 'CKV_AWS_25', name: 'Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389', severity: 'HIGH', types: ['aws_security_group'], eval: (r) => !openTo(r, 3389) },
  { id: 'CKV_AWS_17', name: 'Ensure all data stored in RDS is not publicly accessible', severity: 'HIGH', types: ['aws_db_instance'], eval: (r) => hBool(r.block.attrs.publicly_accessible) !== true },
  { id: 'CKV_AWS_16', name: 'Ensure all data stored in the RDS is securely encrypted at rest', severity: 'MEDIUM', types: ['aws_db_instance'], eval: (r) => hBool(r.block.attrs.storage_encrypted) === true },
  { id: 'CKV_AWS_133', name: 'Ensure that RDS instances has backup policy', severity: 'LOW', types: ['aws_db_instance'], eval: (r) => (hNum(r.block.attrs.backup_retention_period) ?? 0) > 0 },
];

function skipsOf(r: Resource): Record<string, string> {
  const out: Record<string, string> = {};
  const collect = (comments: string[]) => {
    for (const c of comments) {
      const m = /checkov:skip=([A-Z0-9_]+)(?::(.*))?/.exec(c);
      if (m) out[m[1]] = (m[2] ?? '').trim();
    }
  };
  collect(r.block.comments);
  r.block.blocks.forEach((b) => collect(b.comments));
  return out;
}

export interface CheckovRun {
  results: CheckResult[];
  parseErrors: string[];
  resourceCount: number;
}

export function checkov(files: Files, dir = '', skipChecks: string[] = []): CheckovRun {
  const prefix = dir.replace(/^\.\/?/, '').replace(/\/$/, '');
  const scoped = Object.fromEntries(Object.entries(files).filter(([p]) => !prefix || p.startsWith(prefix + '/') || p === prefix));
  const { resources, diags } = resourcesOf(scoped);
  const results: CheckResult[] = [];
  for (const r of resources) {
    const skips = skipsOf(r);
    for (const c of CHECKS) {
      if (!c.types.includes(r.type) || skipChecks.includes(c.id)) continue;
      if ((c.id === 'CKV_AWS_20' || c.id === 'CKV_AWS_57') && r.type === 'aws_s3_bucket' && !r.block.attrs.acl) continue;
      const base = { id: c.id, name: c.name, severity: c.severity, resource: `${r.type}.${r.name}`, file: '/' + r.file, lines: [r.block.startLine, r.block.endLine] as [number, number], guide: `https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/${c.id.toLowerCase()}` };
      if (c.id in skips) results.push({ ...base, status: 'SKIPPED', skipReason: skips[c.id] || 'No comment provided' });
      else results.push({ ...base, status: c.eval(r, resources) ? 'PASSED' : 'FAILED' });
    }
  }
  return { results, parseErrors: diags.map((d) => `${d.file}:${d.diag.line}: ${d.diag.summary}`), resourceCount: resources.length };
}

export function checkToFinding(c: CheckResult): Finding {
  return { tool: 'checkov', ruleId: c.id, severity: c.severity, title: c.name, file: c.file.slice(1), line: c.lines[0], detail: `Resource ${c.resource} (lines ${c.lines[0]}-${c.lines[1]})`, remediation: c.guide };
}
