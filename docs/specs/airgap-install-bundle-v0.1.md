# TrustAI Air-Gap Install Bundle v0.1

Status: draft

## Purpose

The air-gap install bundle is a signed offline BYOC/self-hosted package
manifest. It binds the deployment manifest, Helm chart validation receipt,
deployment image integrity receipt, and Kubernetes release-state receipt into
one portable artifact for auditors, customer platform teams, and external
reviewers.

The bundle proves that the install package is deterministic and replayable from
local source artifacts. It does not prove a customer has imported or operated
the package in a live air-gapped environment without fresh customer/provider
installation evidence.

## Schema

`trustai.airgap-install-bundle/0.1`

## Required Inputs

- signed deployment manifest
- signed Helm chart validation receipt
- signed deployment image integrity receipt with image digest, SBOM,
  provenance, and signature bindings
- signed Kubernetes release-state receipt with release, workload,
  NetworkPolicy, and audit-log references

## Verification Rules

Verifiers must:

- recompute `bundle_id` from the canonical body
- verify at least one bundle signature
- replay all source-file hashes from the local worktree
- replay every required input receipt when supplied
- require the deployment manifest to verify
- require the Helm chart validation receipt to verify and pass
- require the image integrity receipt to verify and pass
- require the image signature subject to verify
- require the image reference to be pinned by a `sha256:` digest
- require the Kubernetes release-state receipt to verify and pass
- require the recorded release to be deployed with ready replicas at or above
  desired replicas
- require NetworkPolicy admission evidence to be present in the release-state
  receipt
- reject any bundle whose replayed input bindings, source file hashes, checks,
  summary, or limitations differ from the signed bundle body

## Evidence Chain Entry

`deployment.airgap_install_bundle.attested`

The chain payload records the bundle ID/hash, mode, environment, bundle and
producer refs, bound receipt summaries, install package metadata, source file
count, check summary, and pass/fail state.
