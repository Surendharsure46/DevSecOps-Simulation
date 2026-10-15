import type { Files, LabState } from '../../engine/types';
import type { LabDef } from '../../engine/lab';
import { revOf } from '../../engine/shell';
import { checkov, ingressRules } from '../../engine/iac';
import { findBlocks, hBool, hStr, refName, resourcesOf, type Resource } from '../../engine/hcl';
import { baseFiles, TEAM } from '../shopflow';
import { headFiles, isPushed } from './common';

const MAIN_TF = `terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

# Customer invoices (PDF) - contains personal data
resource "aws_s3_bucket" "invoices" {
  bucket = "shopflow-invoices-prod"
}

resource "aws_s3_bucket_acl" "invoices" {
  bucket = aws_s3_bucket.invoices.id
  acl    = "public-read"
}

# Static website assets (logos, product photos) loaded by browsers
resource "aws_s3_bucket" "assets" {
  bucket = "shopflow-public-assets"
}

resource "aws_s3_bucket_acl" "assets" {
  bucket = aws_s3_bucket.assets.id
  acl    = "public-read"
}

resource "aws_security_group" "app" {
  name        = "shopflow-app"
  description = "ShopFlow API servers"

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH for ops"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "orders" {
  identifier                  = "shopflow-orders"
  engine                      = "postgres"
  engine_version              = "16.4"
  instance_class              = "db.t4g.medium"
  allocated_storage           = 50
  username                    = "shopflow"
  manage_master_user_password = true
  publicly_accessible         = true
  storage_encrypted           = false
  backup_retention_period     = 0
  skip_final_snapshot         = true
}
`;

const CORP_CIDR = '10.20.0.0/16';

function model(files: Files) {
  const tf = Object.fromEntries(Object.entries(files).filter(([p]) => p.startsWith('infra/') && p.endsWith('.tf')));
  const { resources, diags } = resourcesOf(tf);
  const find = (type: string, name: string) => resources.find((r) => r.type === type && r.name === name);
  const forBucket = (type: string, bucket: string) => resources.filter((r) => r.type === type && refName(r.block.attrs.bucket, 'aws_s3_bucket') === bucket);
  return { resources, diags, find, forBucket };
}

function checksFor(s: LabState, match: (resource: string) => boolean) {
  return checkov(s.files, 'infra').results.filter((r) => match(r.resource));
}

const isKms = (r: Resource) => findBlocks(r.block, 'apply_server_side_encryption_by_default').some((b) => hStr(b.attrs.sse_algorithm) === 'aws:kms');

/** Business requirement: the assets bucket must stay anonymously readable. */
function assetsStillPublic(files: Files): boolean {
  const m = model(files);
  if (!m.find('aws_s3_bucket', 'assets')) return false;
  const acl = m.forBucket('aws_s3_bucket_acl', 'assets')[0];
  if (hStr(acl?.block.attrs.acl) !== 'public-read') return false;
  const pab = m.forBucket('aws_s3_bucket_public_access_block', 'assets')[0];
  if (pab && (hBool(pab.block.attrs.block_public_acls) === true || hBool(pab.block.attrs.ignore_public_acls) === true)) return false;
  return !m.forBucket('aws_s3_bucket_server_side_encryption_configuration', 'assets').some(isKms);
}

export const iacLab: LabDef = {
  id: 'iac-terraform',
  level: 3,
  title: 'Terraform misconfigurations',
  track: 'Infrastructure as Code',
  minutes: 40,
  summary: 'Validate and scan Terraform with Checkov, fix public storage, open SSH and an exposed database — while keeping legitimate public assets working with documented exceptions.',
  story:
    'Before the new production account goes live, cloud security reviews infra/main.tf. Fix the real risks, but be careful: marketing needs the website assets bucket to stay public, and ops still needs SSH from the corporate VPN (10.20.0.0/16).',
  ticket: 'CLOUD-77 — Checkov must pass for infra/. Invoices private and KMS-encrypted, SSH only from 10.20.0.0/16, DB private/encrypted/backed up. Public assets bucket stays public with documented skips.',
  skills: ['Terraform', 'Policy-as-code scanning', 'Least-privilege networking', 'Risk exceptions'],
  tools: ['terraform init/validate/plan', 'checkov'],
  concepts: [
    { term: 'Shift left', text: 'Catching a public bucket in a pull request costs minutes; catching it in production can cost a breach notification.' },
    { term: 'Exceptions', text: 'Some findings are intended (a public website bucket). Suppress them inline with #checkov:skip=ID:reason so the decision is reviewed and auditable.' },
    { term: 'Functional constraints', text: 'Security changes must keep the business working: HTTPS stays open, the assets bucket stays readable.' },
  ],
  openFile: 'infra/main.tf',
  seed: () => ({
    history: [
      { message: 'Initial ShopFlow API', author: TEAM.priya, daysAgo: 100, files: baseFiles() },
      { message: 'Add production infrastructure', author: TEAM.dana, daysAgo: 4, files: baseFiles({ 'infra/main.tf': MAIN_TF }) },
    ],
  }),
  tests: [],
  objectives: [
    {
      id: 'validate',
      title: 'Initialise and validate the Terraform configuration',
      guide: 'Terraform needs `init` before it can validate. Run both from the repo root using `-chdir=infra` (or the defaults).',
      command: 'terraform init && terraform validate',
      hints: ['terraform plan shows every resource that would be created.'],
      check: (s) => s.flags.tfValidRev !== undefined,
    },
    {
      id: 'scan',
      title: 'Scan the infrastructure code with Checkov',
      guide: 'Run Checkov on the infra directory. Each failed check names the resource and line range.',
      command: 'checkov -d infra',
      hints: ['--compact hides the code snippets.'],
      check: (s) => !!s.scans.checkov,
    },
    {
      id: 'invoices',
      title: 'Invoices bucket: private, public access blocked, KMS-encrypted',
      guide:
        'Remove the public ACL (use "private" or drop the ACL resource), add an `aws_s3_bucket_public_access_block` with all four settings `true`, and an `aws_s3_bucket_server_side_encryption_configuration` using `aws:kms`. Skipping invoice checks is not allowed.',
      hints: ['resource "aws_s3_bucket_public_access_block" "invoices" { bucket = aws_s3_bucket.invoices.id ... }', 'rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }'],
      check: (s) => {
        const r = checksFor(s, (x) => x.endsWith('.invoices') && x.startsWith('aws_s3'));
        return !!model(s.files).find('aws_s3_bucket', 'invoices') && r.length > 0 && r.every((x) => x.status === 'PASSED');
      },
    },
    {
      id: 'ssh',
      title: 'SSH only from the corporate VPN; HTTPS still public',
      guide: `Change the SSH rule's CIDR to ${CORP_CIDR}. Do not remove the HTTPS rule — customers need it.`,
      hints: [`cidr_blocks = ["${CORP_CIDR}"]`],
      check: (s) => {
        const sg = model(s.files).find('aws_security_group', 'app');
        if (!sg) return false;
        const rules = ingressRules(sg);
        const ssh = rules.filter((r) => r.from <= 22 && r.to >= 22);
        const https = rules.some((r) => r.from <= 443 && r.to >= 443 && r.cidrs.includes('0.0.0.0/0'));
        return https && ssh.length > 0 && ssh.every((r) => !r.cidrs.includes('0.0.0.0/0')) && ssh.some((r) => r.cidrs.includes(CORP_CIDR));
      },
    },
    {
      id: 'database',
      title: 'Database: private, encrypted at rest, backups kept',
      guide: 'Set `publicly_accessible = false`, `storage_encrypted = true` and a `backup_retention_period` of at least 7 days.',
      hints: ['Encryption at rest cannot be skipped — personal data lives here.'],
      check: (s) => {
        const r = checksFor(s, (x) => x === 'aws_db_instance.orders');
        const db = model(s.files).find('aws_db_instance', 'orders');
        return !!db && Number(db.block.attrs.backup_retention_period?.raw ?? 0) >= 7 && r.length > 0 && r.every((x) => x.status === 'PASSED');
      },
    },
    {
      id: 'exceptions',
      title: 'Assets bucket stays public, with justified Checkov skips',
      guide:
        'The assets bucket must remain anonymously readable (no KMS — anonymous users cannot decrypt). Add `#checkov:skip=<ID>:<reason>` comments inside the relevant resources for each failing check, with a real reason.',
      hints: ['#checkov:skip=CKV_AWS_20:Public website assets, approved MKT-12', 'Skips go inside the resource block they apply to.'],
      check: (s) => {
        if (!assetsStillPublic(s.files)) return false;
        const r = checksFor(s, (x) => x.endsWith('.assets'));
        return r.length > 0 && r.every((x) => x.status === 'PASSED' || (x.status === 'SKIPPED' && (x.skipReason ?? '').length >= 10 && x.skipReason !== 'No comment provided'));
      },
    },
    {
      id: 'clean',
      title: 'Checkov passes and Terraform validates on the final code',
      guide: 'Re-run `terraform validate` and `checkov -d infra` after your last edit. Both must pass on the same version.',
      command: 'terraform validate && checkov -d infra',
      hints: ['A syntax error makes Checkov skip the file — validate first.'],
      check: (s) => s.flags.tfValidRev === revOf(s) && s.scans.checkov?.rev === revOf(s) && s.scans.checkov.findings.length === 0 && model(s.files).diags.length === 0,
    },
    {
      id: 'ship',
      title: 'Commit and push the infrastructure changes',
      guide: 'Push so the change can go through review and the deploy pipeline.',
      command: 'git commit -am "Harden production infrastructure" && git push',
      hints: ['git diff --staged before committing.'],
      check: (s) => isPushed(s) && headFiles(s)['infra/main.tf'] === s.files['infra/main.tf'] && checkov(headFiles(s), 'infra').results.every((r) => r.status !== 'FAILED'),
    },
  ],
};
