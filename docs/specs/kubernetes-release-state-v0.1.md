# Kubernetes Release-State Receipt v0.1

Status: draft

## Purpose

The Kubernetes release-state receipt records provider or customer Kubernetes
exports for a TrustAI BYOC/self-hosted installation. It complements the local
Helm chart validation receipt: Helm validation proves the chart source contains
the expected API Deployment, Service, Secret wiring, PVC, and NetworkPolicy;
this receipt proves that a named Kubernetes environment has an externally
recorded release, namespace, workload, NetworkPolicy, and audit-log export by
hash.

The receipt is offline-verifiable. It stores references and hashes, not raw
cluster credentials or secret values.

## Schema

`trustai.kubernetes-release-state/0.1`

## Required Bindings

The receipt binds:

- deployment manifest ID/hash and verification result
- Helm chart validation receipt ID/hash and check summary
- release provider, cluster reference, namespace, release name, revision, and
  status
- provider/customer release export reference and `sha256:` hash
- API Deployment, Service, NetworkPolicy, Secret, and ServiceAccount references
- desired and ready replica counts from the recorded export
- admitted NetworkPolicy state plus pod selector, ingress, and egress rule
  summary hashes
- Kubernetes/provider audit-log reference and root hash
- issued/expires freshness window for the recorded export
- source files used by the local verifier implementation

## Verification Rules

Verifiers must:

- recompute `receipt_id` from the canonical body
- verify at least one receipt signature
- replay source file hashes against the current worktree
- replay the deployment manifest when supplied
- replay the Helm chart validation receipt when supplied
- require the release export reference and hash
- require Deployment, Service, NetworkPolicy, Secret, and ServiceAccount refs
- require ready replicas to meet or exceed desired replicas
- require admitted NetworkPolicy state
- require `sha256:` hashes for NetworkPolicy selector/rule summaries and the
  audit-log root
- require an issued/expires freshness window

## Evidence Chain Entry

`deployment.kubernetes_release_state.recorded`

The chain payload records the receipt ID/hash, mode, environment, release,
workload, NetworkPolicy, deployment manifest binding, Helm validation binding,
check summary, and pass/fail state.