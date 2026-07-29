package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	proofPackSpecVersion = "trustai.proof-pack/0.1"

	roadmapEvidenceBundleSchema          = "trustai.roadmap-evidence-bundle/0.1"
	roadmapEvidenceReportSchema          = "trustai.roadmap-evidence-report/0.1"
	chainSpecVersion                     = "trustai.evidence-chain/0.1"
	externalEvidenceCollectionRunSchema  = "trustai.external-evidence-collection-run/0.1"
	externalEvidenceSourceMapSchema      = "trustai.external-evidence-source-map/0.1"
	externalEvidenceSourceSnapshotSchema = "trustai.external-evidence-source-snapshot/0.1"
	externalEvidenceIntakeSchema         = "trustai.external-evidence-intake/0.1"

	defaultSigningKey = "trustai-local-dev-key-change-me"
	defaultTSAKey     = "trustai-local-tsa-key-change-me"

	contractEntryType                      = "verification_contract.registered"
	evalEntryType                          = "eval.completed"
	gateEntryType                          = "promotion_gate.decided"
	approvalEntryType                      = "human_approval.granted"
	runtimeEntryType                       = "runtime.attested"
	policyDecisionEntryType                = "policy.decision"
	policyPackSpecVersion                  = "trustai.policy-pack/0.1"
	roadmapAuditEntryType                  = "trustai.roadmap_audit.attested"
	externalEvidenceEntryType              = "trustai.external_evidence_manifest.attested"
	externalEvidenceCollectionRunEntryType = "trustai.external_evidence_collection_run.attested"

	leafPrefix = "trustai-merkle-leaf-v1\x00"
	nodePrefix = "trustai-merkle-node-v1\x00"
	emptyRoot  = "trustai-empty-merkle-tree-v1"
)

type result struct {
	OK       bool
	Errors   []string
	Warnings []string
	Decision string
}

type roadmapOptions struct {
	requireExternal        bool
	requireComplete        bool
	requireFresh           bool
	requireSourceArtifacts bool
}

type roadmapChainResult struct {
	OK                                      bool
	Errors                                  []string
	Warnings                                []string
	AuditEntryCount                         int
	ExternalEvidenceEntryCount              int
	ExternalEvidenceCollectionRunEntryCount int
	CompleteExternalEvidenceEntryCount      int
	FreshExternalEvidenceEntryCount         int
}

func main() {
	key := flag.String("key", getenvDefault("TRUSTAI_SIGNING_KEY", defaultSigningKey), "local HMAC signing key")
	tsaKey := flag.String("tsa-key", getenvDefault("TRUSTAI_TSA_KEY", defaultTSAKey), "local TSA HMAC key")
	requireExternal := flag.Bool("require-external", false, "fail roadmap evidence bundles without external evidence entries")
	requireComplete := flag.Bool("require-complete", false, "fail roadmap evidence bundles with incomplete external evidence")
	requireFresh := flag.Bool("require-fresh", false, "fail roadmap evidence bundles with stale or missing freshness metadata")
	requireSourceArtifacts := flag.Bool("require-source-artifacts", false, "fail roadmap evidence bundles unless required embedded source artifacts are present")
	jsonOut := flag.Bool("json", false, "emit machine-readable verification result")
	quiet := flag.Bool("quiet", false, "suppress success details")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: trustai-verify [--key KEY] [--tsa-key KEY] [--require-external] [--require-complete] [--require-fresh] [--require-source-artifacts] [--json] <proof-pack-or-roadmap-evidence-bundle.json>")
		os.Exit(2)
	}
	artifact, err := loadJSON(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load artifact: %v\n", err)
		os.Exit(2)
	}

	artifactKind := "proof pack"
	var res result
	if getString(artifact, "spec_version") == proofPackSpecVersion {
		res = verifyProofPack(artifact, *key, *tsaKey)
	} else if getString(artifact, "schema") == roadmapEvidenceBundleSchema {
		artifactKind = "roadmap evidence bundle"
		opts := roadmapOptions{
			requireExternal:        *requireExternal || *requireComplete,
			requireComplete:        *requireComplete,
			requireFresh:           *requireFresh,
			requireSourceArtifacts: *requireSourceArtifacts,
		}
		res = verifyRoadmapEvidenceBundle(artifact, *key, *tsaKey, opts)
	} else {
		res = result{OK: false, Errors: []string{fmt.Sprintf("unsupported artifact schema/spec_version: schema=%v spec_version=%v", artifact["schema"], artifact["spec_version"])}}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else if res.OK {
		if !*quiet {
			fmt.Printf("verified %s: %s\n", artifactKind, flag.Arg(0))
			if res.Decision != "" {
				fmt.Printf("decision: %s\n", res.Decision)
			}
			for _, warning := range res.Warnings {
				fmt.Printf("warning: %s\n", warning)
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s verification failed: %s\n", artifactKind, flag.Arg(0))
		for _, err := range res.Errors {
			fmt.Fprintf(os.Stderr, "- %s\n", err)
		}
	}
	if !res.OK {
		os.Exit(1)
	}
}

func verifyRoadmapEvidenceBundle(bundle map[string]any, key, tsaKey string, opts roadmapOptions) result {
	errors := []string{}
	warnings := []string{}

	if getString(bundle, "schema") != roadmapEvidenceBundleSchema {
		errors = append(errors, fmt.Sprintf("unsupported roadmap evidence bundle schema: %v", bundle["schema"]))
	}
	if getString(bundle, "bundle_id") != contentHash(withoutKeys(bundle, "bundle_id")) {
		errors = append(errors, "bundle_id does not match canonical bundle body")
	}
	if !canonicalEqual(bundle["verification_options"], roadmapVerificationOptions(opts)) {
		errors = append(errors, "verification_options do not match verifier options")
	}

	tenantID, tree, entries, chainErrors := loadRoadmapBundleChain(bundle["chain"])
	errors = append(errors, chainErrors...)
	chainResult := verifyRoadmapEvidenceChain(tenantID, tree, entries, key, tsaKey, opts)

	report := getMap(bundle, "report")
	if report == nil {
		errors = append(errors, "bundle report must be an object")
		report = map[string]any{}
	}
	reportErrors, reportWarnings := verifyRoadmapEvidenceReport(report, tenantID, entries, chainResult, opts)
	for _, err := range reportErrors {
		errors = append(errors, "report: "+err)
	}
	warnings = append(warnings, reportWarnings...)

	sourceArtifacts, sourceArtifactsOK := roadmapSourceArtifacts(bundle)
	if !sourceArtifactsOK {
		errors = append(errors, "bundle source_artifacts must be a list")
	}
	verifyRoadmapBundleSourceArtifacts(entries, sourceArtifacts, &errors, &warnings, opts.requireSourceArtifacts)

	if !canonicalEqual(bundle["summary"], roadmapEvidenceBundleSummary(entries, report, sourceArtifacts)) {
		errors = append(errors, "bundle summary does not match bundled chain and report")
	}

	return result{OK: len(errors) == 0, Errors: errors, Warnings: warnings}
}

func roadmapVerificationOptions(opts roadmapOptions) map[string]any {
	return map[string]any{
		"require_external": opts.requireExternal || opts.requireComplete,
		"require_complete": opts.requireComplete,
		"require_fresh":    opts.requireFresh,
	}
}

func loadRoadmapBundleChain(raw any) (string, map[string]any, []map[string]any, []string) {
	errors := []string{}
	document, ok := raw.(map[string]any)
	if !ok {
		return "", nil, []map[string]any{}, []string{"bundle chain must be an object"}
	}
	if getString(document, "spec_version") != chainSpecVersion {
		errors = append(errors, fmt.Sprintf("unsupported bundled chain spec version: %v", document["spec_version"]))
	}
	tenantID := getString(document, "tenant_id")
	if tenantID == "" {
		errors = append(errors, "bundled chain tenant_id is required")
		tenantID = "bundle"
	}
	tree := getMap(document, "tree")
	if tree == nil {
		errors = append(errors, "bundled chain tree must be an object")
	}
	rawEntries, ok := document["entries"].([]any)
	if !ok {
		errors = append(errors, "bundled chain entries must be a list")
		rawEntries = []any{}
	}
	entries := make([]map[string]any, 0, len(rawEntries))
	for _, rawEntry := range rawEntries {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			errors = append(errors, "bundled chain entry must be an object")
			continue
		}
		entries = append(entries, entry)
	}
	errors = append(errors, verifyPackedChainTree(tree, rawEntries, "bundled chain")...)
	if tree != nil && !canonicalEqual(tree, chainTree(entries)) {
		errors = append(errors, "bundled chain tree does not match entries")
	}
	return tenantID, tree, entries, errors
}

func verifyRoadmapEvidenceReport(report map[string]any, tenantID string, entries []map[string]any, chainResult roadmapChainResult, opts roadmapOptions) ([]string, []string) {
	errors := []string{}
	warnings := []string{}
	if getString(report, "schema") != roadmapEvidenceReportSchema {
		errors = append(errors, fmt.Sprintf("unsupported roadmap evidence report schema: %v", report["schema"]))
	}
	if getString(report, "report_id") != contentHash(withoutKeys(report, "report_id")) {
		errors = append(errors, "report_id does not match canonical report body")
	}
	if !canonicalEqual(report["verification_options"], roadmapVerificationOptions(opts)) {
		errors = append(errors, "verification_options do not match verifier options")
	}
	if !canonicalEqual(report["chain"], roadmapEvidenceChainRecord(tenantID, entries)) {
		errors = append(errors, "chain summary does not match supplied evidence chain")
	}
	if !canonicalEqual(report["summary"], roadmapEvidenceSummary(entries, chainResult)) {
		errors = append(errors, "report summary does not match supplied evidence chain")
	}
	if !canonicalEqual(report["verification"], roadmapEvidenceVerificationRecord(chainResult)) {
		errors = append(errors, "report verification block does not match supplied evidence chain")
	}
	if !canonicalEqual(report["roadmap_audit_entries"], roadmapAuditEntryRecords(entries)) {
		errors = append(errors, "roadmap audit entries do not match supplied evidence chain")
	}
	if !canonicalEqual(report["external_evidence_entries"], externalEvidenceEntryRecords(entries)) {
		errors = append(errors, "external evidence entries do not match supplied evidence chain")
	}
	if !canonicalEqual(report["external_evidence_collection_run_entries"], externalEvidenceCollectionRunEntryRecords(entries)) {
		errors = append(errors, "external evidence collection run entries do not match supplied evidence chain")
	}
	warnings = append(warnings, chainResult.Warnings...)
	if !chainResult.OK {
		for _, err := range chainResult.Errors {
			errors = append(errors, "roadmap evidence chain: "+err)
		}
	}
	return errors, warnings
}
func verifyRoadmapEvidenceChain(tenantID string, tree map[string]any, entries []map[string]any, key, tsaKey string, opts roadmapOptions) roadmapChainResult {
	errors := []string{}
	warnings := []string{}
	auditEntries := []map[string]any{}
	externalEntries := []map[string]any{}
	collectionRunEntries := []map[string]any{}
	auditBySource := map[string]map[string]any{}

	var expectedPrevious any
	for expectedIndex, entry := range entries {
		if !sameNumber(entry["index"], expectedIndex) {
			errors = append(errors, fmt.Sprintf("chain: entry index mismatch at position %d", expectedIndex))
		}
		if !canonicalEqual(entry["previous_entry_id"], expectedPrevious) {
			errors = append(errors, fmt.Sprintf("chain: entry %d previous pointer mismatch", expectedIndex))
		}
		for _, err := range verifyEntry(entry, key, tsaKey) {
			errors = append(errors, "chain: "+err)
		}
		expectedPrevious = entry["entry_id"]

		payload := getMap(entry, "payload")
		if payload == nil {
			errors = append(errors, fmt.Sprintf("entry %v payload must be an object", entry["index"]))
			continue
		}
		switch getString(entry, "entry_type") {
		case roadmapAuditEntryType:
			auditEntries = append(auditEntries, entry)
			auditID := getString(payload, "audit_id")
			auditHash := getString(payload, "audit_hash")
			if auditID == "" {
				errors = append(errors, fmt.Sprintf("roadmap audit entry %v missing audit_id", entry["index"]))
			}
			if auditHash == "" {
				errors = append(errors, fmt.Sprintf("roadmap audit entry %v missing audit_hash", entry["index"]))
			}
			if auditID != "" && auditHash != "" {
				auditBySource[sourceAuditKey(auditID, auditHash)] = entry
			}
		case externalEvidenceEntryType:
			externalEntries = append(externalEntries, entry)
		case externalEvidenceCollectionRunEntryType:
			collectionRunEntries = append(collectionRunEntries, entry)
		}
	}

	if len(auditEntries) == 0 {
		errors = append(errors, "roadmap evidence chain has no roadmap audit entry")
	}
	if opts.requireExternal && len(externalEntries) == 0 {
		errors = append(errors, "roadmap evidence chain has no external evidence entry")
	}

	completeExternalCount := 0
	freshExternalCount := 0
	for _, entry := range externalEntries {
		payload := getMap(entry, "payload")
		source := getMap(payload, "source_roadmap_audit")
		if source == nil {
			errors = append(errors, fmt.Sprintf("external evidence entry %v missing source_roadmap_audit", entry["index"]))
			continue
		}
		auditEntry := auditBySource[sourceAuditKey(getString(source, "audit_id"), getString(source, "audit_hash"))]
		if auditEntry == nil {
			errors = append(errors, fmt.Sprintf("external evidence entry %v source roadmap audit is not chained", entry["index"]))
			continue
		}
		if numberInt(auditEntry["index"]) >= numberInt(entry["index"]) {
			errors = append(errors, fmt.Sprintf("external evidence entry %v does not follow its source roadmap audit entry", entry["index"]))
		}
		proof := getMap(payload, "source_roadmap_audit_inclusion_proof")
		if proof == nil {
			errors = append(errors, fmt.Sprintf("external evidence entry %v missing source roadmap audit inclusion proof", entry["index"]))
		} else {
			verifySourceRoadmapAuditInclusionProof(entries, auditEntry, entry, proof, &errors, "external evidence entry")
		}
		verifyExternalEvidenceEntrySummary(entry, &errors, &warnings, opts)
		if getString(payload, "status") == "complete" && numberInt(payload["missing_requirement_count"]) == 0 && numberInt(payload["missing_authority_kind_count"]) == 0 {
			completeExternalCount++
		}
		if getBool(payload, "require_fresh") && numberInt(payload["stale_evidence_count"]) == 0 && numberInt(payload["missing_freshness_count"]) == 0 {
			freshExternalCount++
		}
	}

	for _, entry := range collectionRunEntries {
		payload := getMap(entry, "payload")
		source := getMap(payload, "source_roadmap_audit")
		if source == nil {
			errors = append(errors, fmt.Sprintf("external evidence collection run entry %v missing source_roadmap_audit", entry["index"]))
			continue
		}
		auditEntry := auditBySource[sourceAuditKey(getString(source, "audit_id"), getString(source, "audit_hash"))]
		if auditEntry == nil {
			errors = append(errors, fmt.Sprintf("external evidence collection run entry %v source roadmap audit is not chained", entry["index"]))
			continue
		}
		if numberInt(auditEntry["index"]) >= numberInt(entry["index"]) {
			errors = append(errors, fmt.Sprintf("external evidence collection run entry %v does not follow its source roadmap audit entry", entry["index"]))
		}
		proof := getMap(payload, "source_roadmap_audit_inclusion_proof")
		if proof == nil {
			errors = append(errors, fmt.Sprintf("external evidence collection run entry %v missing source roadmap audit inclusion proof", entry["index"]))
		} else {
			verifySourceRoadmapAuditInclusionProof(entries, auditEntry, entry, proof, &errors, "external evidence collection run entry")
		}
		verifyExternalEvidenceCollectionRunEntrySummary(entry, &errors)
	}

	if tree == nil {
		errors = append(errors, "declared chain tree missing")
	} else if !canonicalEqual(tree, chainTree(entries)) {
		errors = append(errors, "declared chain tree root mismatch")
	}

	return roadmapChainResult{
		OK:                                      len(errors) == 0,
		Errors:                                  errors,
		Warnings:                                warnings,
		AuditEntryCount:                         len(auditEntries),
		ExternalEvidenceEntryCount:              len(externalEntries),
		ExternalEvidenceCollectionRunEntryCount: len(collectionRunEntries),
		CompleteExternalEvidenceEntryCount:      completeExternalCount,
		FreshExternalEvidenceEntryCount:         freshExternalCount,
	}
}

func verifySourceRoadmapAuditInclusionProof(entries []map[string]any, auditEntry, externalEntry, proof map[string]any, errors *[]string, label string) {
	if getString(proof, "entry_id") != getString(auditEntry, "entry_id") {
		*errors = append(*errors, fmt.Sprintf("%s %v source audit proof entry_id mismatch", label, externalEntry["index"]))
	}
	if !sameNumber(proof["index"], auditEntry["index"]) {
		*errors = append(*errors, fmt.Sprintf("%s %v source audit proof index mismatch", label, externalEntry["index"]))
	}
	treeSize, ok := intValue(proof["tree_size"])
	if !ok {
		*errors = append(*errors, fmt.Sprintf("%s %v source audit proof tree_size invalid", label, externalEntry["index"]))
		return
	}
	auditIndex := numberInt(auditEntry["index"])
	externalIndex := numberInt(externalEntry["index"])
	if treeSize <= auditIndex {
		*errors = append(*errors, fmt.Sprintf("%s %v source audit proof tree_size excludes audit entry", label, externalEntry["index"]))
		return
	}
	if treeSize > externalIndex {
		*errors = append(*errors, fmt.Sprintf("%s %v source audit proof was not recorded before append", label, externalEntry["index"]))
		return
	}
	if treeSize > int64(len(entries)) {
		*errors = append(*errors, fmt.Sprintf("%s %v source audit proof tree_size exceeds bundled chain", label, externalEntry["index"]))
		return
	}
	prefixIDs := []string{}
	for i := int64(0); i < treeSize; i++ {
		prefixIDs = append(prefixIDs, getString(entries[i], "entry_id"))
	}
	if getString(proof, "tree_root") != merkleRoot(prefixIDs) {
		*errors = append(*errors, fmt.Sprintf("%s %v source audit proof tree_root mismatch", label, externalEntry["index"]))
	}
	auditPath, ok := proof["audit_path"].([]any)
	if !ok {
		*errors = append(*errors, fmt.Sprintf("%s %v source audit proof audit_path invalid", label, externalEntry["index"]))
		return
	}
	if !verifyInclusion(getString(auditEntry, "entry_id"), auditPath, getString(proof, "tree_root")) {
		*errors = append(*errors, fmt.Sprintf("%s %v source audit proof inclusion failed", label, externalEntry["index"]))
	}
}
func verifyExternalEvidenceEntrySummary(entry map[string]any, errors, warnings *[]string, opts roadmapOptions) {
	payload := getMap(entry, "payload")
	required, requiredOK := intValue(payload["required_requirement_count"])
	covered, coveredOK := intValue(payload["covered_requirement_count"])
	missing, missingOK := intValue(payload["missing_requirement_count"])
	if requiredOK && coveredOK && missingOK && covered+missing != required {
		*errors = append(*errors, fmt.Sprintf("external evidence entry %v coverage counts do not add up", entry["index"]))
	}
	missingAuthority, missingAuthorityOK := intValue(payload["missing_authority_kind_count"])
	coveredAuthority, coveredAuthorityOK := intValue(payload["covered_authority_kind_count"])
	requiredAuthority, requiredAuthorityOK := intValue(payload["required_authority_kind_count"])
	hasAuthorityCounts := missingAuthorityOK && coveredAuthorityOK && requiredAuthorityOK
	if hasAuthorityCounts && coveredAuthority+missingAuthority != requiredAuthority {
		*errors = append(*errors, fmt.Sprintf("external evidence entry %v authority-kind coverage counts do not add up", entry["index"]))
	}
	status := getString(payload, "status")
	if status == "complete" && missing != 0 {
		*errors = append(*errors, fmt.Sprintf("external evidence entry %v is complete but has missing requirements", entry["index"]))
	}
	if status == "complete" && !hasAuthorityCounts {
		*errors = append(*errors, fmt.Sprintf("external evidence entry %v is complete but missing authority-kind coverage metadata", entry["index"]))
	}
	if status == "complete" && hasAuthorityCounts && missingAuthority != 0 {
		*errors = append(*errors, fmt.Sprintf("external evidence entry %v is complete but has missing authority kinds", entry["index"]))
	}
	if status != "complete" {
		message := fmt.Sprintf("external evidence entry %v is partial", entry["index"])
		if opts.requireComplete {
			*errors = append(*errors, message)
		} else {
			*warnings = append(*warnings, message)
		}
	}
	stale := numberInt(payload["stale_evidence_count"])
	missingFreshness := numberInt(payload["missing_freshness_count"])
	if opts.requireFresh {
		if !getBool(payload, "require_fresh") {
			*errors = append(*errors, fmt.Sprintf("external evidence entry %v was not appended with freshness required", entry["index"]))
		}
		if stale != 0 {
			*errors = append(*errors, fmt.Sprintf("external evidence entry %v has stale evidence", entry["index"]))
		}
		if missingFreshness != 0 {
			*errors = append(*errors, fmt.Sprintf("external evidence entry %v has evidence without freshness metadata", entry["index"]))
		}
	} else if stale != 0 {
		*warnings = append(*warnings, fmt.Sprintf("external evidence entry %v has stale evidence", entry["index"]))
	} else if missingFreshness != 0 {
		*warnings = append(*warnings, fmt.Sprintf("external evidence entry %v has evidence without freshness metadata", entry["index"]))
	}
}

func verifyExternalEvidenceCollectionRunEntrySummary(entry map[string]any, errors *[]string) {
	payload := getMap(entry, "payload")
	if payload == nil {
		*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v payload must be an object", entry["index"]))
		return
	}
	for _, field := range []string{"run_id", "run_hash", "source_map_hash"} {
		if getString(payload, field) == "" {
			*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v missing %s", entry["index"], field))
		}
	}
	sourceMap := getMap(payload, "source_map")
	if sourceMap == nil {
		*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v source_map must be an object", entry["index"]))
	} else if getString(sourceMap, "source_map_hash") != getString(payload, "source_map_hash") {
		*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v source_map hash mismatch", entry["index"]))
	}
	collectedTasks, collectedTasksOK := stringList(payload["collected_tasks"])
	snapshotIDs, snapshotIDsOK := stringList(payload["snapshot_ids"])
	intakeIDs, intakeIDsOK := stringList(payload["intake_ids"])
	if !collectedTasksOK {
		*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v collected_tasks must be a list of strings", entry["index"]))
		collectedTasks = []string{}
	}
	if !snapshotIDsOK {
		*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v snapshot_ids must be a list of strings", entry["index"]))
		snapshotIDs = []string{}
	}
	if !intakeIDsOK {
		*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v intake_ids must be a list of strings", entry["index"]))
		intakeIDs = []string{}
	}
	collectedCount, collectedOK := intValue(payload["collected_count"])
	if collectedOK {
		if int64(len(collectedTasks)) != collectedCount {
			*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v collected_count does not match collected_tasks", entry["index"]))
		}
		if int64(len(snapshotIDs)) != collectedCount {
			*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v collected_count does not match snapshot_ids", entry["index"]))
		}
		if int64(len(intakeIDs)) != collectedCount {
			*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v collected_count does not match intake_ids", entry["index"]))
		}
	} else {
		*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v collected_count must be an integer", entry["index"]))
	}
	taskCount, taskOK := intValue(payload["task_count"])
	if taskOK {
		if int64(len(uniqueStrings(collectedTasks))) != taskCount {
			*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v task_count does not match unique collected tasks", entry["index"]))
		}
	} else {
		*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v task_count must be an integer", entry["index"]))
	}
	if !getBool(payload, "require_source_snapshot_artifacts") {
		*errors = append(*errors, fmt.Sprintf("external evidence collection run entry %v was not appended with source snapshot artifact verification", entry["index"]))
	}
}

type bundleSourceRefs struct {
	manifestEvidence               map[string]string
	embeddedExternalFiles          map[string]bool
	collectionSourceMapHashes      map[string]bool
	collectionSnapshotRefs         map[string]string
	collectionIntakeRefs           map[string]string
	embeddedRoadmapAuditHashes     map[string]bool
	embeddedExternalManifestHashes map[string]bool
	embeddedCollectionRunHashes    map[string]bool
	embeddedSourceMapHashes        map[string]bool
	embeddedSnapshotRefs           map[string]bool
	embeddedIntakeRefs             map[string]bool
}

func newBundleSourceRefs() bundleSourceRefs {
	return bundleSourceRefs{
		manifestEvidence:               map[string]string{},
		embeddedExternalFiles:          map[string]bool{},
		collectionSourceMapHashes:      map[string]bool{},
		collectionSnapshotRefs:         map[string]string{},
		collectionIntakeRefs:           map[string]string{},
		embeddedRoadmapAuditHashes:     map[string]bool{},
		embeddedExternalManifestHashes: map[string]bool{},
		embeddedCollectionRunHashes:    map[string]bool{},
		embeddedSourceMapHashes:        map[string]bool{},
		embeddedSnapshotRefs:           map[string]bool{},
		embeddedIntakeRefs:             map[string]bool{},
	}
}

func verifyRoadmapBundleSourceArtifacts(entries []map[string]any, sourceArtifacts []any, errors, warnings *[]string, requireSourceArtifacts bool) {
	if requireSourceArtifacts && len(sourceArtifacts) == 0 {
		*errors = append(*errors, "bundle source_artifacts are required")
	}
	refs := newBundleSourceRefs()
	for _, rawArtifact := range sourceArtifacts {
		artifact, ok := rawArtifact.(map[string]any)
		if !ok {
			*errors = append(*errors, "bundle source artifact must be an object")
			continue
		}
		inspectBundleSourceArtifact(artifact, entries, &refs, errors, warnings)
	}
	verifyRequiredBundleSourceArtifacts(entries, refs, errors, requireSourceArtifacts)
	appendMissingRefs(refs.manifestEvidence, refs.embeddedExternalFiles, "external evidence file referenced by embedded manifest is not embedded", errors, warnings, requireSourceArtifacts)
	appendMissingHashRefs(refs.collectionSourceMapHashes, refs.embeddedSourceMapHashes, "external evidence source map referenced by embedded collection run is not embedded", errors, warnings, requireSourceArtifacts)
	appendMissingRefs(refs.collectionSnapshotRefs, refs.embeddedSnapshotRefs, "external evidence source snapshot referenced by embedded collection run is not embedded", errors, warnings, requireSourceArtifacts)
	appendMissingRefs(refs.collectionIntakeRefs, refs.embeddedIntakeRefs, "external evidence intake referenced by embedded collection run is not embedded", errors, warnings, requireSourceArtifacts)
}

func inspectBundleSourceArtifact(artifact map[string]any, entries []map[string]any, refs *bundleSourceRefs, errors, warnings *[]string) {
	body := withoutKeys(artifact, "artifact_id")
	if getString(artifact, "artifact_id") != contentHash(body) {
		*errors = append(*errors, fmt.Sprintf("bundle source artifact id mismatch: %v", artifact["path"]))
	}
	kind := getString(artifact, "kind")
	if !isBundleSourceArtifactKind(kind) {
		*errors = append(*errors, fmt.Sprintf("unsupported bundle source artifact kind: %v", artifact["kind"]))
	}
	pathValue := getString(artifact, "path")
	normalizedPath := normalizePath(pathValue)
	if pathValue == "" {
		*errors = append(*errors, "bundle source artifact path is required")
	} else if !isSafeRelativePath(pathValue) {
		*errors = append(*errors, fmt.Sprintf("bundle source artifact path must be repository-relative: %s", pathValue))
	}
	data, err := base64.StdEncoding.DecodeString(getString(artifact, "content_b64"))
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("bundle source artifact content_b64 invalid: %v", artifact["path"]))
		return
	}
	actualSHA := "sha256:" + sha256HexBytes(data)
	if getString(artifact, "sha256") != actualSHA {
		*errors = append(*errors, fmt.Sprintf("bundle source artifact hash mismatch: %v", artifact["path"]))
	}

	switch kind {
	case "external-evidence-file":
		refs.embeddedExternalFiles[setKey(normalizedPath, actualSHA)] = true
	case "external-evidence-manifest":
		manifest := jsonSourceArtifact(artifact, data, errors)
		if manifest == nil {
			return
		}
		for _, rawEvidence := range getSlice(manifest, "evidence") {
			evidence, ok := rawEvidence.(map[string]any)
			if ok && getString(evidence, "path") != "" && getString(evidence, "sha256") != "" {
				refPath := normalizePath(getString(evidence, "path"))
				refs.manifestEvidence[setKey(refPath, getString(evidence, "sha256"))] = refPath
			}
		}
		manifestHash := contentHash(manifest)
		refs.embeddedExternalManifestHashes[manifestHash] = true
		if !chainHasExternalManifest(entries, manifestHash) {
			*errors = append(*errors, fmt.Sprintf("external evidence manifest artifact is not committed to bundled chain: %s", pathValue))
		}
	case "external-evidence-collection-run":
		collectionRun := jsonSourceArtifact(artifact, data, errors)
		if collectionRun == nil {
			return
		}
		verifyBundleCollectionRunArtifact(collectionRun, normalizedPath, entries, errors)
		refs.embeddedCollectionRunHashes[contentHash(collectionRun)] = true
		sourceMap := getMap(collectionRun, "source_map")
		if sourceMap != nil && getString(sourceMap, "source_map_hash") != "" {
			refs.collectionSourceMapHashes[getString(sourceMap, "source_map_hash")] = true
		}
		for _, rawItem := range getSlice(collectionRun, "collected") {
			item, ok := rawItem.(map[string]any)
			if !ok {
				continue
			}
			snapshotPath := getString(item, "snapshot_artifact_path")
			if snapshotPath == "" {
				snapshotPath = getString(item, "snapshot_path")
			}
			if snapshotPath != "" && getString(item, "snapshot_id") != "" {
				normalized := normalizePath(snapshotPath)
				refs.collectionSnapshotRefs[setKey(normalized, getString(item, "snapshot_id"))] = normalized
			}
			if getString(item, "intake_path") != "" && getString(item, "intake_id") != "" {
				normalized := normalizePath(getString(item, "intake_path"))
				refs.collectionIntakeRefs[setKey(normalized, getString(item, "intake_id"))] = normalized
			}
		}
	case "external-evidence-source-map":
		sourceMap := jsonSourceArtifact(artifact, data, errors)
		if sourceMap == nil {
			return
		}
		if getString(sourceMap, "schema") != externalEvidenceSourceMapSchema {
			*errors = append(*errors, fmt.Sprintf("unsupported external evidence source map artifact schema: %s: %v", pathValue, sourceMap["schema"]))
		}
		if getString(sourceMap, "source_map_id") != contentHash(withoutKeys(sourceMap, "source_map_id")) {
			*errors = append(*errors, fmt.Sprintf("external evidence source map artifact id mismatch: %s", pathValue))
		}
		refs.embeddedSourceMapHashes[contentHash(sourceMap)] = true
	case "external-evidence-source-snapshot":
		snapshot := jsonSourceArtifact(artifact, data, errors)
		if snapshot == nil {
			return
		}
		snapshotErrors, snapshotWarnings := verifyExternalEvidenceSourceSnapshot(snapshot)
		for _, warning := range snapshotWarnings {
			*warnings = append(*warnings, fmt.Sprintf("bundle source snapshot artifact %s: %s", pathValue, warning))
		}
		for _, err := range snapshotErrors {
			*errors = append(*errors, fmt.Sprintf("bundle source snapshot artifact %s: %s", pathValue, err))
		}
		if getString(snapshot, "snapshot_id") != "" {
			refs.embeddedSnapshotRefs[setKey(normalizedPath, getString(snapshot, "snapshot_id"))] = true
		}
	case "external-evidence-intake":
		intake := jsonSourceArtifact(artifact, data, errors)
		if intake == nil {
			return
		}
		if getString(intake, "schema") != externalEvidenceIntakeSchema {
			*errors = append(*errors, fmt.Sprintf("unsupported external evidence intake artifact schema: %s: %v", pathValue, intake["schema"]))
		}
		if getString(intake, "intake_id") != contentHash(withoutKeys(intake, "intake_id")) {
			*errors = append(*errors, fmt.Sprintf("external evidence intake artifact id mismatch: %s", pathValue))
		}
		if getString(intake, "intake_id") != "" {
			refs.embeddedIntakeRefs[setKey(normalizedPath, getString(intake, "intake_id"))] = true
		}
	case "roadmap-audit":
		audit := jsonSourceArtifact(artifact, data, errors)
		if audit == nil {
			return
		}
		auditHash := contentHash(audit)
		refs.embeddedRoadmapAuditHashes[auditHash] = true
		if !chainHasRoadmapAudit(entries, auditHash) {
			*errors = append(*errors, fmt.Sprintf("roadmap audit artifact is not committed to bundled chain: %s", pathValue))
		}
	}
}
func roadmapSourceArtifacts(bundle map[string]any) ([]any, bool) {
	raw, exists := bundle["source_artifacts"]
	if !exists || raw == nil {
		return []any{}, true
	}
	items, ok := raw.([]any)
	if !ok {
		return []any{}, false
	}
	return items, true
}

func verifyRequiredBundleSourceArtifacts(entries []map[string]any, refs bundleSourceRefs, errors *[]string, requireSourceArtifacts bool) {
	if !requireSourceArtifacts {
		return
	}
	for _, entry := range entries {
		payload := getMap(entry, "payload")
		if payload == nil {
			continue
		}
		switch getString(entry, "entry_type") {
		case roadmapAuditEntryType:
			auditHash := getString(payload, "audit_hash")
			if auditHash != "" && !refs.embeddedRoadmapAuditHashes[auditHash] {
				*errors = append(*errors, fmt.Sprintf("roadmap audit chain entry %v is missing an embedded source artifact", entry["index"]))
			}
		case externalEvidenceEntryType:
			manifestHash := getString(payload, "manifest_hash")
			if manifestHash != "" && !refs.embeddedExternalManifestHashes[manifestHash] {
				*errors = append(*errors, fmt.Sprintf("external evidence chain entry %v is missing an embedded manifest source artifact", entry["index"]))
			}
		case externalEvidenceCollectionRunEntryType:
			runHash := getString(payload, "run_hash")
			if runHash != "" && !refs.embeddedCollectionRunHashes[runHash] {
				*errors = append(*errors, fmt.Sprintf("external evidence collection run chain entry %v is missing an embedded collection-run source artifact", entry["index"]))
			}
			sourceMapHash := getString(payload, "source_map_hash")
			if sourceMapHash != "" && !refs.embeddedSourceMapHashes[sourceMapHash] {
				*errors = append(*errors, fmt.Sprintf("external evidence collection run chain entry %v is missing an embedded source-map source artifact", entry["index"]))
			}
		}
	}
}

func verifyBundleCollectionRunArtifact(collectionRun map[string]any, path string, entries []map[string]any, errors *[]string) {
	if getString(collectionRun, "schema") != externalEvidenceCollectionRunSchema {
		*errors = append(*errors, fmt.Sprintf("unsupported external evidence collection run artifact schema: %s: %v", path, collectionRun["schema"]))
	}
	if getString(collectionRun, "run_id") != contentHash(withoutKeys(collectionRun, "run_id")) {
		*errors = append(*errors, fmt.Sprintf("external evidence collection run artifact id mismatch: %s", path))
	}
	runHash := contentHash(collectionRun)
	if !chainHasExternalCollectionRun(entries, runHash) {
		*errors = append(*errors, fmt.Sprintf("external evidence collection run artifact is not committed to bundled chain: %s", path))
	}
}

func verifyExternalEvidenceSourceSnapshot(snapshot map[string]any) ([]string, []string) {
	errors := []string{}
	warnings := []string{}
	if getString(snapshot, "schema") != externalEvidenceSourceSnapshotSchema {
		errors = append(errors, fmt.Sprintf("unsupported external evidence source snapshot schema: %v", snapshot["schema"]))
	}
	if getString(snapshot, "snapshot_id") != contentHash(withoutKeys(snapshot, "snapshot_id")) {
		errors = append(errors, "snapshot_id does not match canonical source snapshot body")
	}
	if getString(snapshot, "source_uri") == "" {
		errors = append(errors, "external evidence source snapshot source_uri is required")
	}
	if getString(snapshot, "retrieval_method") == "" {
		errors = append(errors, "external evidence source snapshot retrieval_method is required")
	}
	if statusCode, ok := intValue(snapshot["status_code"]); snapshot["status_code"] != nil && (!ok || statusCode < 100 || statusCode > 599) {
		errors = append(errors, "external evidence source snapshot status_code must be an HTTP status code")
	}
	if _, ok := snapshot["response_headers"].(map[string]any); !ok {
		errors = append(errors, "external evidence source snapshot response_headers must be an object")
	}
	bodyBase64 := getString(snapshot, "body_base64")
	if bodyBase64 == "" {
		errors = append(errors, "external evidence source snapshot body_base64 is required")
	} else {
		bodyBytes, err := base64.StdEncoding.DecodeString(bodyBase64)
		if err != nil {
			errors = append(errors, "external evidence source snapshot body_base64 invalid: "+err.Error())
		} else if len(bodyBytes) == 0 {
			errors = append(errors, "external evidence source snapshot body is empty")
		} else {
			expectedHash := "sha256:" + sha256HexBytes(bodyBytes)
			if getString(snapshot, "body_sha256") != expectedHash {
				errors = append(errors, "external evidence source snapshot body_sha256 mismatch")
			}
			if size, ok := intValue(snapshot["body_size_bytes"]); !ok || size != int64(len(bodyBytes)) {
				errors = append(errors, "external evidence source snapshot body_size_bytes mismatch")
			}
		}
	}
	missingFreshness := []string{}
	if getString(snapshot, "issued_at") == "" {
		missingFreshness = append(missingFreshness, "issued_at")
	}
	if getString(snapshot, "expires_at") == "" {
		missingFreshness = append(missingFreshness, "expires_at")
	}
	if len(missingFreshness) > 0 {
		warnings = append(warnings, "external evidence source snapshot freshness metadata missing: "+strings.Join(missingFreshness, ", "))
	}
	return errors, warnings
}

func jsonSourceArtifact(artifact map[string]any, data []byte, errors *[]string) map[string]any {
	parsed, err := decodeJSONMap(data)
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("bundle source artifact JSON invalid: %v: %v", artifact["path"], err))
		return nil
	}
	return parsed
}

func decodeJSONMap(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var parsed map[string]any
	if err := dec.Decode(&parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}
func chainTree(entries []map[string]any) map[string]any {
	entryIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		entryIDs = append(entryIDs, getString(entry, "entry_id"))
	}
	return map[string]any{"size": len(entryIDs), "root": merkleRoot(entryIDs)}
}

func roadmapEvidenceChainRecord(tenantID string, entries []map[string]any) map[string]any {
	return map[string]any{"tenant_id": tenantID, "entry_count": len(entries), "tree": chainTree(entries)}
}

func roadmapEvidenceSummary(entries []map[string]any, chainResult roadmapChainResult) map[string]any {
	return map[string]any{
		"semantic_ok":                                  chainResult.OK,
		"chain_entry_count":                            len(entries),
		"roadmap_audit_entry_count":                    chainResult.AuditEntryCount,
		"external_evidence_entry_count":                chainResult.ExternalEvidenceEntryCount,
		"external_evidence_collection_run_entry_count": chainResult.ExternalEvidenceCollectionRunEntryCount,
		"complete_external_evidence_entry_count":       chainResult.CompleteExternalEvidenceEntryCount,
		"fresh_external_evidence_entry_count":          chainResult.FreshExternalEvidenceEntryCount,
		"has_external_evidence":                        chainResult.ExternalEvidenceEntryCount > 0,
		"has_external_evidence_collection_runs":        chainResult.ExternalEvidenceCollectionRunEntryCount > 0,
		"has_complete_external_evidence":               chainResult.CompleteExternalEvidenceEntryCount > 0,
		"has_fresh_external_evidence":                  chainResult.FreshExternalEvidenceEntryCount > 0,
	}
}

func roadmapEvidenceVerificationRecord(chainResult roadmapChainResult) map[string]any {
	return map[string]any{
		"ok":                            chainResult.OK,
		"errors":                        chainResult.Errors,
		"warnings":                      chainResult.Warnings,
		"audit_entry_count":             chainResult.AuditEntryCount,
		"external_evidence_entry_count": chainResult.ExternalEvidenceEntryCount,
		"external_evidence_collection_run_entry_count": chainResult.ExternalEvidenceCollectionRunEntryCount,
		"complete_external_evidence_entry_count":       chainResult.CompleteExternalEvidenceEntryCount,
		"fresh_external_evidence_entry_count":          chainResult.FreshExternalEvidenceEntryCount,
	}
}

func roadmapEvidenceBundleSummary(entries []map[string]any, report map[string]any, sourceArtifacts []any) map[string]any {
	reportSummary := getMap(report, "summary")
	if reportSummary == nil {
		reportSummary = map[string]any{}
	}
	return map[string]any{
		"report_id":                     report["report_id"],
		"report_hash":                   contentHash(report),
		"chain_tree":                    chainTree(entries),
		"chain_entry_count":             len(entries),
		"roadmap_audit_entry_count":     reportSummary["roadmap_audit_entry_count"],
		"external_evidence_entry_count": reportSummary["external_evidence_entry_count"],
		"external_evidence_collection_run_entry_count": reportSummary["external_evidence_collection_run_entry_count"],
		"complete_external_evidence_entry_count":       reportSummary["complete_external_evidence_entry_count"],
		"fresh_external_evidence_entry_count":          reportSummary["fresh_external_evidence_entry_count"],
		"source_artifact_count":                        len(sourceArtifacts),
		"semantic_ok":                                  reportSummary["semantic_ok"],
	}
}

func roadmapAuditEntryRecords(entries []map[string]any) []any {
	records := []any{}
	for _, entry := range entries {
		if getString(entry, "entry_type") != roadmapAuditEntryType {
			continue
		}
		payload := getMap(entry, "payload")
		if payload == nil {
			payload = map[string]any{}
		}
		records = append(records, map[string]any{
			"index":                        entry["index"],
			"entry_id":                     entry["entry_id"],
			"timestamp":                    entry["timestamp"],
			"audit_id":                     payload["audit_id"],
			"audit_hash":                   payload["audit_hash"],
			"completion_position":          payload["completion_position"],
			"requirement_count":            payload["requirement_count"],
			"implemented_local_count":      payload["implemented_local_count"],
			"reference_attested_count":     payload["reference_attested_count"],
			"missing_local_evidence_count": payload["missing_local_evidence_count"],
			"deferred_external_count":      payload["deferred_external_count"],
		})
	}
	return records
}
func externalEvidenceEntryRecords(entries []map[string]any) []any {
	records := []any{}
	for _, entry := range entries {
		if getString(entry, "entry_type") != externalEvidenceEntryType {
			continue
		}
		payload := getMap(entry, "payload")
		if payload == nil {
			payload = map[string]any{}
		}
		records = append(records, map[string]any{
			"index":                                entry["index"],
			"entry_id":                             entry["entry_id"],
			"timestamp":                            entry["timestamp"],
			"manifest_id":                          payload["manifest_id"],
			"manifest_hash":                        payload["manifest_hash"],
			"manifest_ref":                         payload["manifest_ref"],
			"source_roadmap_audit":                 payload["source_roadmap_audit"],
			"source_roadmap_audit_inclusion_proof": roadmapProofRecord(payload["source_roadmap_audit_inclusion_proof"]),
			"status":                               payload["status"],
			"require_complete":                     payload["require_complete"],
			"require_fresh":                        payload["require_fresh"],
			"require_live_source_uris":             payload["require_live_source_uris"],
			"require_source_snapshot_artifacts":    payload["require_source_snapshot_artifacts"],
			"require_fresh_source_snapshot_artifacts": payload["require_fresh_source_snapshot_artifacts"],
			"freshness_checked_at":                    payload["freshness_checked_at"],
			"required_requirement_count":              payload["required_requirement_count"],
			"covered_requirement_count":               payload["covered_requirement_count"],
			"missing_requirement_count":               payload["missing_requirement_count"],
			"required_authority_kind_count":           payload["required_authority_kind_count"],
			"covered_authority_kind_count":            payload["covered_authority_kind_count"],
			"missing_authority_kind_count":            payload["missing_authority_kind_count"],
			"evidence_count":                          payload["evidence_count"],
			"issued_at_count":                         payload["issued_at_count"],
			"expires_at_count":                        payload["expires_at_count"],
			"freshness_window_count":                  payload["freshness_window_count"],
			"fresh_evidence_count":                    payload["fresh_evidence_count"],
			"stale_evidence_count":                    payload["stale_evidence_count"],
			"missing_freshness_count":                 payload["missing_freshness_count"],
			"covered_requirement_ids":                 defaultList(payload["covered_requirement_ids"]),
			"missing_requirement_ids":                 defaultList(payload["missing_requirement_ids"]),
			"covered_authority_kinds_by_requirement":  defaultMap(payload["covered_authority_kinds_by_requirement"]),
			"missing_authority_kinds_by_requirement":  defaultMap(payload["missing_authority_kinds_by_requirement"]),
		})
	}
	return records
}

func externalEvidenceCollectionRunEntryRecords(entries []map[string]any) []any {
	records := []any{}
	for _, entry := range entries {
		if getString(entry, "entry_type") != externalEvidenceCollectionRunEntryType {
			continue
		}
		payload := getMap(entry, "payload")
		if payload == nil {
			payload = map[string]any{}
		}
		records = append(records, map[string]any{
			"index":                                entry["index"],
			"entry_id":                             entry["entry_id"],
			"timestamp":                            entry["timestamp"],
			"run_id":                               payload["run_id"],
			"run_hash":                             payload["run_hash"],
			"source_map":                           payload["source_map"],
			"source_map_hash":                      payload["source_map_hash"],
			"source_plan":                          payload["source_plan"],
			"source_manifest":                      payload["source_manifest"],
			"source_roadmap_audit":                 payload["source_roadmap_audit"],
			"source_roadmap_audit_inclusion_proof": roadmapProofRecord(payload["source_roadmap_audit_inclusion_proof"]),
			"require_fresh":                        payload["require_fresh"],
			"require_live_source_uris":             payload["require_live_source_uris"],
			"require_source_snapshot_artifacts":    payload["require_source_snapshot_artifacts"],
			"require_fresh_source_snapshot_artifacts": payload["require_fresh_source_snapshot_artifacts"],
			"freshness_checked_at":                    payload["freshness_checked_at"],
			"collected_count":                         payload["collected_count"],
			"task_count":                              payload["task_count"],
			"collected_tasks":                         defaultList(payload["collected_tasks"]),
			"snapshot_ids":                            defaultList(payload["snapshot_ids"]),
			"intake_ids":                              defaultList(payload["intake_ids"]),
		})
	}
	return records
}

func roadmapProofRecord(raw any) any {
	proof, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	return map[string]any{
		"entry_id":  proof["entry_id"],
		"index":     proof["index"],
		"tree_size": proof["tree_size"],
		"tree_root": proof["tree_root"],
	}
}

func defaultList(value any) any {
	if value == nil {
		return []any{}
	}
	return value
}

func defaultMap(value any) any {
	if value == nil {
		return map[string]any{}
	}
	return value
}
func chainHasRoadmapAudit(entries []map[string]any, auditHash string) bool {
	for _, entry := range entries {
		payload := getMap(entry, "payload")
		if getString(entry, "entry_type") == roadmapAuditEntryType && payload != nil && getString(payload, "audit_hash") == auditHash {
			return true
		}
	}
	return false
}

func chainHasExternalManifest(entries []map[string]any, manifestHash string) bool {
	for _, entry := range entries {
		payload := getMap(entry, "payload")
		if getString(entry, "entry_type") == externalEvidenceEntryType && payload != nil && getString(payload, "manifest_hash") == manifestHash {
			return true
		}
	}
	return false
}

func chainHasExternalCollectionRun(entries []map[string]any, runHash string) bool {
	for _, entry := range entries {
		payload := getMap(entry, "payload")
		if getString(entry, "entry_type") == externalEvidenceCollectionRunEntryType && payload != nil && getString(payload, "run_hash") == runHash {
			return true
		}
	}
	return false
}

func appendMissingRefs(left map[string]string, right map[string]bool, message string, errors, warnings *[]string, require bool) {
	keys := make([]string, 0, len(left))
	for key := range left {
		if !right[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		line := fmt.Sprintf("%s: %s", message, left[key])
		if require {
			*errors = append(*errors, line)
		} else {
			*warnings = append(*warnings, line)
		}
	}
}

func appendMissingHashRefs(left, right map[string]bool, message string, errors, warnings *[]string, require bool) {
	keys := make([]string, 0, len(left))
	for key := range left {
		if !right[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		line := fmt.Sprintf("%s: %s", message, key)
		if require {
			*errors = append(*errors, line)
		} else {
			*warnings = append(*warnings, line)
		}
	}
}

func isBundleSourceArtifactKind(kind string) bool {
	switch kind {
	case "roadmap-audit", "external-evidence-manifest", "external-evidence-collection-run", "external-evidence-source-map", "external-evidence-source-snapshot", "external-evidence-intake", "external-evidence-file", "other":
		return true
	}
	return false
}

func isSafeRelativePath(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") {
		return false
	}
	if len(path) >= 2 && path[1] == ':' {
		return false
	}
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return false
		}
	}
	return true
}

func normalizePath(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func sourceAuditKey(auditID, auditHash string) string {
	return auditID + "\x00" + auditHash
}

func setKey(left, right string) string {
	return left + "\x00" + right
}

func sha256HexBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func stringList(value any) ([]string, bool) {
	raw, ok := value.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
}

func uniqueStrings(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func verifyProofPack(pack map[string]any, key, tsaKey string) result {
	var errors []string
	var warnings []string

	if getString(pack, "spec_version") != proofPackSpecVersion {
		errors = append(errors, fmt.Sprintf("unsupported proof pack spec_version: %v", pack["spec_version"]))
	}
	issuedAt := getString(pack, "issued_at")
	if issuedAt == "" {
		errors = append(errors, "proof pack issued_at missing")
	} else if mustParseTime(issuedAt).IsZero() {
		errors = append(errors, "proof pack issued_at invalid")
	}

	packBody := withoutKeys(pack, "pack_id", "signatures")
	expectedPackID := contentHash(packBody)
	if getString(pack, "pack_id") != expectedPackID {
		errors = append(errors, "pack_id does not match canonical pack body")
	}
	signatures := getSlice(pack, "signatures")
	if len(signatures) == 0 {
		errors = append(errors, "proof pack missing signature")
	} else if sig, ok := signatures[0].(map[string]any); !ok || !verifyValue(map[string]any{"pack_id": pack["pack_id"], "pack": packBody}, sig, key) {
		errors = append(errors, "proof pack signature invalid")
	}

	chain := getMap(pack, "chain")
	if chain == nil {
		errors = append(errors, "proof pack chain must be an object")
		chain = map[string]any{}
	}
	tree := getMap(chain, "tree")
	root := getString(tree, "root")
	entries := getSlice(chain, "entries")
	proofs := getMap(chain, "inclusion_proofs")
	errors = append(errors, verifyPackedChainTree(tree, entries, "chain")...)
	if proofs == nil {
		errors = append(errors, "chain inclusion_proofs must be an object")
		proofs = map[string]any{}
	}
	entryByType := map[string]map[string]any{}
	var approvalEntries []map[string]any
	var runtimeEntries []map[string]any
	var policyEntries []map[string]any

	if root == "" {
		errors = append(errors, "chain tree root missing")
	}
	if len(entries) == 0 {
		errors = append(errors, "proof pack must include selected chain entries")
	} else {
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				errors = append(errors, "proof pack chain entry must be an object")
				continue
			}
			errors = append(errors, verifyEntry(entry, key, tsaKey)...)
			core := entryCore(entry)
			if getString(entry, "entry_id") != contentHash(core) {
				errors = append(errors, fmt.Sprintf("entry %v canonical id mismatch", entry["index"]))
			}
			entryID := getString(entry, "entry_id")
			proof := getMap(proofs, entryID)
			if getString(proof, "entry_id") != entryID {
				errors = append(errors, fmt.Sprintf("entry %v proof entry_id mismatch", entry["index"]))
			}
			if !sameNumber(proof["index"], entry["index"]) {
				errors = append(errors, fmt.Sprintf("entry %v proof index mismatch", entry["index"]))
			}
			if getString(proof, "tree_root") != root {
				errors = append(errors, fmt.Sprintf("entry %v proof tree root mismatch", entry["index"]))
			}
			if !sameNumber(proof["tree_size"], tree["size"]) {
				errors = append(errors, fmt.Sprintf("entry %v proof tree size mismatch", entry["index"]))
			}
			if root != "" && !verifyInclusion(entryID, getSlice(proof, "audit_path"), root) {
				errors = append(errors, fmt.Sprintf("entry %v inclusion proof invalid", entry["index"]))
			}
			entryType := getString(entry, "entry_type")
			entryByType[entryType] = entry
			if entryType == approvalEntryType {
				approvalEntries = append(approvalEntries, entry)
			}
			if entryType == runtimeEntryType {
				runtimeEntries = append(runtimeEntries, entry)
			}
			if entryType == policyDecisionEntryType {
				policyEntries = append(policyEntries, entry)
			}
		}
	}

	contractEntry := entryByType[contractEntryType]
	evalEntry := entryByType[evalEntryType]
	gateEntry := entryByType[gateEntryType]
	if contractEntry == nil {
		errors = append(errors, "missing contract registration entry")
	}
	if evalEntry == nil {
		errors = append(errors, "missing eval entry")
	}
	if gateEntry == nil {
		errors = append(errors, "missing gate entry")
	}

	contractWrapper := getMap(pack, "contract")
	contractBody := getMap(contractWrapper, "body")
	var contractDigest string
	if contractBody == nil {
		errors = append(errors, "contract body missing")
	} else {
		contractDigest = contentHash(contractBody)
		if getString(contractWrapper, "hash") != contractDigest {
			errors = append(errors, "packed contract hash does not match contract body")
		}
	}

	if contractEntry != nil && evalEntry != nil && gateEntry != nil && contractDigest != "" {
		if !(numberInt(contractEntry["index"]) < numberInt(evalEntry["index"]) && numberInt(evalEntry["index"]) < numberInt(gateEntry["index"])) {
			errors = append(errors, "chain ordering must be contract registration < eval < gate")
		}
		evalWrapper := getMap(pack, "eval")
		evalPayload := getMap(evalEntry, "payload")
		gatePayload := getMap(gateEntry, "payload")
		if getString(contractWrapper, "chain_entry_id") != getString(contractEntry, "entry_id") {
			errors = append(errors, "packed contract chain_entry_id mismatch")
		}
		if getString(evalWrapper, "chain_entry_id") != getString(evalEntry, "entry_id") {
			errors = append(errors, "packed eval chain_entry_id mismatch")
		}
		if getString(evalWrapper, "results_hash") != getString(evalPayload, "results_hash") {
			errors = append(errors, "packed eval results_hash mismatch")
		}
		if getString(getMap(contractEntry, "payload"), "contract_hash") != contractDigest {
			errors = append(errors, "contract entry hash does not match packed contract")
		}
		if getString(evalPayload, "contract_hash") != contractDigest {
			errors = append(errors, "eval entry references a different contract hash")
		}
		if getString(gatePayload, "contract_hash") != contractDigest {
			errors = append(errors, "gate entry references a different contract hash")
		}
		results := getMap(evalPayload, "results")
		if results == nil {
			errors = append(errors, "eval entry results missing")
		} else {
			if getString(evalPayload, "results_hash") != contentHash(results) {
				errors = append(errors, "eval results hash mismatch")
			}
			recomputed := evaluateContract(contractBody, results, approvalEntries)
			stored := getMap(gatePayload, "decision")
			for _, k := range []string{"outcome", "passed", "checks", "holdout", "approvals", "results_hash"} {
				if !canonicalEqual(stored[k], recomputed[k]) {
					errors = append(errors, "gate decision mismatch for "+k)
				}
			}
			subject := getMap(pack, "subject")
			if subject == nil {
				errors = append(errors, "subject must be an object")
				subject = map[string]any{}
			}
			if !canonicalEqual(subject["agent"], contractBody["agent"]) {
				errors = append(errors, "packed subject agent mismatch")
			}
			if !canonicalEqual(stored["agent"], contractBody["agent"]) {
				errors = append(errors, "gate decision agent mismatch")
			}
			if !canonicalEqual(evalPayload["agent"], contractBody["agent"]) {
				errors = append(errors, "eval entry agent mismatch")
			}
			expectedEnvironment := results["environment"]
			if expectedEnvironment == nil {
				expectedEnvironment = map[string]any{}
			}
			if !canonicalEqual(subject["environment"], expectedEnvironment) {
				errors = append(errors, "packed subject environment mismatch")
			}
			packedDecision := getMap(pack, "gate_decision")
			for _, k := range []string{"outcome", "passed", "checks", "holdout", "approvals", "results_hash", "contract_entry_id", "eval_entry_id"} {
				if !canonicalEqual(packedDecision[k], stored[k]) {
					errors = append(errors, "packed gate decision mismatch for "+k)
				}
			}
			if getString(packedDecision, "gate_entry_id") != getString(gateEntry, "entry_id") {
				errors = append(errors, "packed gate decision gate_entry_id mismatch")
			}
		}
	}

	if contractDigest != "" && contractBody != nil {
		for _, runtimeEntry := range runtimeEntries {
			verifyRuntimeAttestationEntry(runtimeEntry, contractBody, contractDigest, &errors)
		}
	}
	if contractDigest != "" {
		for _, policyEntry := range policyEntries {
			verifyPolicyDecisionEntry(policyEntry, pack, contractDigest, &errors)
		}
	}

	frameworkMappings, frameworkMappingsOK := pack["framework_mappings"].([]any)
	if !frameworkMappingsOK {
		errors = append(errors, "framework_mappings must be a list")
	} else if !canonicalEqual(frameworkMappings, defaultFrameworkMappings(getMap(pack, "gate_decision"))) {
		errors = append(errors, "framework mappings do not match gate decision")
	}

	decision := getString(getMap(pack, "gate_decision"), "outcome")
	if decision != "" && decision != "passed" {
		warnings = append(warnings, "proof pack is valid but gate outcome is "+decision)
	}
	return result{OK: len(errors) == 0, Errors: errors, Warnings: warnings, Decision: decision}
}

func verifyRuntimeAttestationEntry(entry, contractBody map[string]any, contractDigest string, errors *[]string) {
	label := fmt.Sprintf("runtime attestation entry %v", entry["index"])
	payload := getMap(entry, "payload")
	if payload == nil {
		*errors = append(*errors, label+" payload missing")
		return
	}
	if getString(payload, "contract_hash") != contractDigest {
		*errors = append(*errors, label+" references a different contract hash")
	}
	if getString(entry, "timestamp") != getString(payload, "timestamp") {
		*errors = append(*errors, label+" timestamp mismatch")
	}
	action := getMap(payload, "action")
	if action == nil {
		*errors = append(*errors, label+" action missing")
		return
	}
	if getString(action, "timestamp") == "" {
		*errors = append(*errors, label+" action timestamp missing")
		return
	}
	expected, err := evaluateRuntimeAction(contractBody, action)
	if err != "" {
		*errors = append(*errors, label+" replay failed: "+err)
		return
	}
	for _, k := range []string{"contract_id", "contract_hash", "action_hash", "timestamp", "passed", "outcome", "checks"} {
		if !canonicalEqual(payload[k], expected[k]) {
			*errors = append(*errors, label+" mismatch for "+k)
		}
	}
}

func verifyPolicyDecisionEntry(entry, pack map[string]any, contractDigest string, errors *[]string) {
	label := fmt.Sprintf("policy decision entry %v", entry["index"])
	payload := getMap(entry, "payload")
	if payload == nil {
		*errors = append(*errors, label+" payload missing")
		return
	}
	if getString(payload, "contract_hash") != contractDigest {
		*errors = append(*errors, label+" references a different contract hash")
	}
	if getString(entry, "timestamp") != getString(payload, "evaluated_at") {
		*errors = append(*errors, label+" timestamp mismatch")
	}
	policyPack := getMap(payload, "policy_pack")
	if policyPack == nil {
		*errors = append(*errors, label+" policy_pack missing")
		return
	}
	if getString(payload, "policy_pack_hash") != contentHash(policyPack) {
		*errors = append(*errors, label+" policy_pack hash mismatch")
	}
	if getString(payload, "policy_pack_id") != getString(policyPack, "id") {
		*errors = append(*errors, label+" policy_pack id mismatch")
	}
	if getString(payload, "policy_pack_version") != getString(policyPack, "version") {
		*errors = append(*errors, label+" policy_pack version mismatch")
	}
	action := getMap(payload, "action")
	if action == nil {
		*errors = append(*errors, label+" action missing")
		return
	}
	evaluatedAt := getString(payload, "evaluated_at")
	if evaluatedAt == "" {
		*errors = append(*errors, label+" evaluated_at missing")
		return
	}
	expected, err := evaluatePolicyDecision(policyPack, action, pack, evaluatedAt)
	if err != "" {
		*errors = append(*errors, label+" replay failed: "+err)
		return
	}
	for _, k := range []string{"policy_pack_id", "policy_pack_version", "policy_pack_hash", "policy_pack", "contract_hash", "action_hash", "evaluated_at", "passed", "outcome", "checks", "matched_rules", "action"} {
		if !canonicalEqual(payload[k], expected[k]) {
			*errors = append(*errors, label+" mismatch for "+k)
		}
	}
}

func verifyEntry(entry map[string]any, key, tsaKey string) []string {
	var errors []string
	core := entryCore(entry)
	expectedEntryID := contentHash(core)
	if getString(entry, "entry_id") != expectedEntryID {
		errors = append(errors, fmt.Sprintf("entry %v id mismatch", entry["index"]))
	}
	if getString(core, "payload_hash") != contentHash(core["payload"]) {
		errors = append(errors, fmt.Sprintf("entry %v payload hash mismatch", entry["index"]))
	}
	signaturePayload := map[string]any{"entry_id": entry["entry_id"], "core": core}
	if token := getMap(entry, "timestamp_token"); token != nil {
		message := map[string]any{
			"entry_id":        entry["entry_id"],
			"entry_timestamp": core["timestamp"],
			"payload_hash":    core["payload_hash"],
		}
		if !verifyTimestampToken(message, token, tsaKey) {
			errors = append(errors, fmt.Sprintf("entry %v timestamp token invalid", entry["index"]))
		}
		signaturePayload["timestamp_token"] = token
	}
	if sig := getMap(entry, "signature"); sig == nil || !verifyValue(signaturePayload, sig, key) {
		errors = append(errors, fmt.Sprintf("entry %v signature invalid", entry["index"]))
	}
	return errors
}

func verifyTimestampToken(message any, token map[string]any, tsaKey string) bool {
	if getString(token, "schema") != "trustai.timestamp-token/0.1" {
		return false
	}
	sig := getMap(token, "signature")
	if sig == nil {
		return false
	}
	unsigned := withoutKeys(token, "signature")
	serialSource := withoutKeys(unsigned, "serial")
	if getString(token, "serial") != contentHash(serialSource) {
		return false
	}
	if getString(token, "message_hash") != contentHash(message) {
		return false
	}
	return verifyValue(map[string]any{"timestamp_token": unsigned}, sig, tsaKey)
}

func evaluatePolicyDecision(policyPack, action, pack map[string]any, evaluatedAt string) (map[string]any, string) {
	if err := validatePolicyPack(policyPack); err != "" {
		return nil, err
	}
	if evaluatedAt == "" {
		return nil, "policy decision evaluated_at missing"
	}
	if mustParseTime(evaluatedAt).IsZero() {
		return nil, "policy decision evaluated_at invalid"
	}
	context := map[string]any{"action": action, "proof": pack, "policy": policyPack}
	var matchedRules []any
	var checks []any
	denied := false
	freshness := evaluateProofFreshness(pack, policyPack, evaluatedAt)
	freshnessCheck := map[string]any{"name": "proof_freshness"}
	for k, v := range freshness {
		freshnessCheck[k] = v
	}
	checks = append(checks, freshnessCheck)
	if !getBool(freshness, "passed") {
		denied = true
	}
	for _, rawRule := range getSlice(policyPack, "rules") {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			return nil, "policy pack rule must be an object"
		}
		matches := true
		for _, rawCondition := range getSlice(rule, "conditions") {
			condition, ok := rawCondition.(map[string]any)
			if !ok {
				return nil, "policy rule condition must be an object"
			}
			matched, err := policyConditionMatches(condition, context)
			if err != "" {
				return nil, err
			}
			if !matched {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		effect := getString(rule, "effect")
		if effect == "" {
			effect = "deny"
		}
		ruleCheck := map[string]any{"name": getString(rule, "id"), "effect": effect, "matched": true, "passed": true}
		if effect == "deny" {
			ruleCheck["passed"] = false
			denied = true
		} else if effect == "require_approval" {
			role := getString(rule, "approval_role")
			approved := policyApprovalPresent(action, role)
			ruleCheck["approval_role"] = role
			ruleCheck["passed"] = approved
			if !approved {
				denied = true
			}
		} else if effect == "allow" {
			ruleCheck["passed"] = true
		} else {
			return nil, "unsupported policy effect: " + effect
		}
		matchedRules = append(matchedRules, rule)
		checks = append(checks, ruleCheck)
	}
	passed := !denied
	outcome := "denied"
	if passed {
		outcome = "allowed"
	}
	contractHash := getString(getMap(pack, "contract"), "hash")
	if contractHash == "" {
		contractHash = getString(action, "contract_hash")
	}
	return map[string]any{
		"policy_pack_id":      policyPack["id"],
		"policy_pack_version": policyPack["version"],
		"policy_pack_hash":    contentHash(policyPack),
		"policy_pack":         policyPack,
		"contract_hash":       contractHash,
		"action_hash":         contentHash(action),
		"evaluated_at":        evaluatedAt,
		"passed":              passed,
		"outcome":             outcome,
		"checks":              checks,
		"matched_rules":       matchedRules,
		"action":              action,
	}, ""
}

func evaluateProofFreshness(pack, policyPack map[string]any, now string) map[string]any {
	if pack == nil {
		return map[string]any{"passed": false, "checks": []any{map[string]any{"name": "active_proof_pack", "passed": false, "reason": "missing proof pack"}}}
	}
	nowTime := mustParseTime(now)
	decay := getMap(policyPack, "proof_decay")
	var checks []any
	gateTS := getString(getMap(pack, "gate_decision"), "evaluated_at")
	if gateTS == "" {
		gateTS = getString(pack, "issued_at")
	}
	if threshold := decay["max_gate_age_hours"]; threshold != nil {
		checks = append(checks, freshnessAgeCheck("max_gate_age_hours", gateTS, threshold, nowTime, "", "gate decision timestamp"))
	}
	latestByType := map[string]string{}
	latestParsedByType := map[string]time.Time{}
	invalidTimestampByType := map[string]string{}
	for _, rawEntry := range getSlice(getMap(pack, "chain"), "entries") {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			continue
		}
		entryType := getString(entry, "entry_type")
		timestamp := getString(entry, "timestamp")
		if entryType == "" || timestamp == "" {
			continue
		}
		parsed := mustParseTime(timestamp)
		if parsed.IsZero() {
			if _, exists := invalidTimestampByType[entryType]; !exists {
				invalidTimestampByType[entryType] = "invalid timestamp"
			}
			continue
		}
		if previous, exists := latestParsedByType[entryType]; !exists || parsed.After(previous) {
			latestByType[entryType] = timestamp
			latestParsedByType[entryType] = parsed
		}
	}
	entryFreshness := []struct{ policyKey, entryType string }{
		{"max_soak_age_hours", "soak_report.completed"},
		{"max_runtime_attestation_age_hours", runtimeEntryType},
		{"max_shadow_replay_age_hours", "shadow_replay.completed"},
	}
	for _, item := range entryFreshness {
		threshold := decay[item.policyKey]
		if threshold == nil {
			continue
		}
		if reason, invalid := invalidTimestampByType[item.entryType]; invalid {
			checks = append(checks, map[string]any{"name": item.policyKey, "entry_type": item.entryType, "passed": false, "reason": "invalid " + item.entryType + " timestamp: " + reason})
			continue
		}
		timestamp := latestByType[item.entryType]
		if timestamp == "" {
			checks = append(checks, map[string]any{"name": item.policyKey, "entry_type": item.entryType, "passed": false, "reason": "missing " + item.entryType + " evidence"})
			continue
		}
		checks = append(checks, freshnessAgeCheck(item.policyKey, timestamp, threshold, nowTime, item.entryType, item.entryType+" timestamp"))
	}
	passed := true
	for _, rawCheck := range checks {
		if !getBool(rawCheck.(map[string]any), "passed") {
			passed = false
		}
	}
	return map[string]any{"passed": passed, "checks": checks}
}

func freshnessAgeCheck(name, timestamp string, threshold any, now time.Time, entryType, timestampLabel string) map[string]any {
	check := map[string]any{"name": name, "operator": "<=", "threshold": threshold, "passed": false}
	if entryType != "" {
		check["entry_type"] = entryType
	}
	if timestamp == "" {
		check["reason"] = "missing " + timestampLabel
		return check
	}
	parsed := mustParseTime(timestamp)
	if parsed.IsZero() {
		check["reason"] = "invalid " + timestampLabel
		return check
	}
	actual := pythonFloatNumber(now.Sub(parsed).Hours())
	check["actual"] = actual
	passed, err := compareNumbers(actual, threshold, "<=")
	if err != "" {
		check["reason"] = err
	} else {
		check["passed"] = passed
	}
	return check
}

func validatePolicyPack(policyPack map[string]any) string {
	if getString(policyPack, "spec_version") != policyPackSpecVersion {
		return fmt.Sprintf("policy pack spec_version must be %s", policyPackSpecVersion)
	}
	for _, field := range []string{"id", "version"} {
		if getString(policyPack, field) == "" {
			return "policy pack missing required field: " + field
		}
	}
	rules := getSlice(policyPack, "rules")
	if len(rules) == 0 {
		return "policy pack missing required field: rules"
	}
	return ""
}

func resolvePolicyField(context map[string]any, dotted string) any {
	var current any = context
	for _, part := range strings.Split(dotted, ".") {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		value, exists := m[part]
		if !exists {
			return nil
		}
		current = value
	}
	return current
}

func policyConditionMatches(condition, context map[string]any) (bool, string) {
	actual := resolvePolicyField(context, getString(condition, "field"))
	operator := getString(condition, "operator")
	passed, err := comparePolicyValues(actual, condition["value"], operator)
	if err == "type mismatch" {
		return false, ""
	}
	return passed, err
}

func comparePolicyValues(actual, expected any, op string) (bool, string) {
	if op == "==" {
		return canonicalEqual(actual, expected) || sameNumber(actual, expected), ""
	}
	if op == "!=" {
		return !(canonicalEqual(actual, expected) || sameNumber(actual, expected)), ""
	}
	if op == ">=" || op == ">" || op == "<=" || op == "<" {
		passed, err := compareNumbers(actual, expected, op)
		if err != "" {
			return false, "type mismatch"
		}
		return passed, ""
	}
	return false, "unsupported policy operator: " + op
}

func policyApprovalPresent(action map[string]any, role string) bool {
	approvals, ok := action["approvals"].([]any)
	if !ok {
		if approval := getMap(action, "approval"); approval != nil {
			approvals = []any{approval}
		}
	}
	for _, rawApproval := range approvals {
		approval, ok := rawApproval.(map[string]any)
		if !ok {
			continue
		}
		roleMatches := role == "" || getString(approval, "role") == role
		if roleMatches && getString(approval, "approved_at") != "" {
			return true
		}
	}
	return false
}

func evaluateRuntimeAction(contract, action map[string]any) (map[string]any, string) {
	timestamp := getString(action, "timestamp")
	if timestamp == "" {
		return nil, "runtime action timestamp missing"
	}
	if mustParseTime(timestamp).IsZero() {
		return nil, "runtime action timestamp invalid"
	}
	var checks []any
	blastRadius := getMap(contract, "blast_radius")
	if threshold := blastRadius["max_notional_usd"]; threshold != nil {
		if actual := action["notional_usd"]; actual != nil {
			passed, _ := compareNumbers(actual, threshold, "<=")
			checks = append(checks, map[string]any{"name": "max_notional_usd", "actual": actual, "operator": "<=", "threshold": threshold, "passed": passed})
		}
	}
	if threshold := blastRadius["max_daily_orders"]; threshold != nil {
		if actual := action["daily_order_count"]; actual != nil {
			passed, _ := compareNumbers(actual, threshold, "<=")
			checks = append(checks, map[string]any{"name": "max_daily_orders", "actual": actual, "operator": "<=", "threshold": threshold, "passed": passed})
		}
	}
	if expectedRisk := getString(getMap(contract, "agent"), "risk_class"); expectedRisk != "" {
		if actualRisk := getString(action, "risk_class"); actualRisk != "" {
			checks = append(checks, map[string]any{"name": "risk_class", "actual": actualRisk, "operator": "==", "threshold": expectedRisk, "passed": actualRisk == expectedRisk})
		}
	}
	if getBool(action, "requires_human_approval") {
		approval := getMap(action, "approval")
		approved := getString(approval, "approved_at") != ""
		checks = append(checks, map[string]any{"name": "human_approval", "actual": approved, "operator": "==", "threshold": true, "passed": approved})
	}
	passed := true
	for _, raw := range checks {
		if !getBool(raw.(map[string]any), "passed") {
			passed = false
		}
	}
	outcome := "failed"
	if passed {
		outcome = "passed"
	}
	return map[string]any{
		"contract_id":   contract["id"],
		"contract_hash": contentHash(contract),
		"action_hash":   contentHash(action),
		"timestamp":     timestamp,
		"passed":        passed,
		"outcome":       outcome,
		"checks":        checks,
		"action":        action,
	}, ""
}

func evaluateContract(contract, results map[string]any, approvalEntries []map[string]any) map[string]any {
	digest := contentHash(contract)
	metricResults := getMap(results, "metrics")
	var checks []any
	for _, raw := range getSlice(contract, "metrics") {
		metric := raw.(map[string]any)
		name := getString(metric, "name")
		op := getString(metric, "operator")
		threshold := metric["threshold"]
		actual := metricResults[name]
		passed := false
		var reason any
		if actual == nil {
			reason = "missing metric"
		} else if ok, err := compareNumbers(actual, threshold, op); err == "" {
			passed = ok
		} else {
			reason = "type mismatch: " + err
		}
		checks = append(checks, map[string]any{
			"name":      name,
			"operator":  op,
			"threshold": threshold,
			"actual":    actual,
			"passed":    passed,
			"reason":    reason,
		})
	}
	holdout := evaluateHoldout(contract, results)
	approvals := evaluateApprovals(contract, results, approvalEntries, digest)
	allChecks := true
	for _, raw := range checks {
		if !getBool(raw.(map[string]any), "passed") {
			allChecks = false
		}
	}
	passed := allChecks && getBool(holdout, "passed") && getBool(approvals, "passed")
	outcome := "failed"
	if passed {
		outcome = "passed"
	}
	evaluatedAt := results["evaluated_at"]
	if evaluatedAt == nil {
		evaluatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"contract_id":   contract["id"],
		"contract_hash": digest,
		"agent":         contract["agent"],
		"evaluated_at":  evaluatedAt,
		"outcome":       outcome,
		"passed":        passed,
		"checks":        checks,
		"holdout":       holdout,
		"approvals":     approvals,
		"results_hash":  contentHash(results),
	}
}

func evaluateHoldout(contract, results map[string]any) map[string]any {
	freezeAt := mustParseTime(getString(getMap(contract, "freeze"), "frozen_at"))
	minTimestamp := mustParseTime(getString(getMap(contract, "holdout"), "min_timestamp"))
	requirePostFreeze := true
	if v, ok := getMap(contract, "holdout")["require_post_freeze"].(bool); ok {
		requirePostFreeze = v
	}
	records := getSlice(getMap(results, "dataset"), "records")
	var errors []any
	checked := 0
	if len(records) == 0 {
		errors = append(errors, "dataset.records must be a non-empty list")
	} else {
		for _, raw := range records {
			checked++
			record, ok := raw.(map[string]any)
			if !ok {
				errors = append(errors, fmt.Sprintf("record %d missing timestamp", checked))
				continue
			}
			ts := getString(record, "timestamp")
			if ts == "" {
				errors = append(errors, fmt.Sprintf("record %d missing timestamp", checked))
				continue
			}
			parsed := mustParseTime(ts)
			if requirePostFreeze && !parsed.After(freezeAt) {
				errors = append(errors, fmt.Sprintf("record %v is not post-freeze", recordID(record, checked)))
			}
			if parsed.Before(minTimestamp) {
				errors = append(errors, fmt.Sprintf("record %v is before holdout minimum", recordID(record, checked)))
			}
		}
	}
	return map[string]any{
		"passed":          len(errors) == 0,
		"records_checked": checked,
		"freeze_at":       getString(getMap(contract, "freeze"), "frozen_at"),
		"min_timestamp":   getString(getMap(contract, "holdout"), "min_timestamp"),
		"errors":          errors,
	}
}

func evaluateApprovals(contract, results map[string]any, entries []map[string]any, digest string) map[string]any {
	var actual []any
	for _, approval := range getSlice(results, "approvals") {
		actual = append(actual, approval)
	}
	for _, entry := range entries {
		payload := getMap(entry, "payload")
		if getString(payload, "contract_hash") != digest {
			continue
		}
		approval := cloneMap(getMap(payload, "approval"))
		approval["approval_entry_id"] = entry["entry_id"]
		actual = append(actual, approval)
	}
	actualByRole := map[string]map[string]any{}
	for _, raw := range actual {
		if approval, ok := raw.(map[string]any); ok {
			role := getString(approval, "role")
			if role != "" {
				actualByRole[role] = approval
			}
		}
	}
	var errors []any
	required := getSlice(contract, "required_approvals")
	for _, raw := range required {
		approval := raw.(map[string]any)
		role := getString(approval, "role")
		if actualByRole[role] == nil {
			errors = append(errors, "missing approval role: "+role)
		} else if getString(actualByRole[role], "approved_at") == "" {
			errors = append(errors, "approval role "+role+" missing approved_at")
		}
	}
	return map[string]any{"passed": len(errors) == 0, "required": required, "actual": actual, "errors": errors}
}

func defaultFrameworkMappings(decision map[string]any) []any {
	var contractID any
	var gateEntryID any
	if decision != nil {
		contractID = decision["contract_id"]
		gateEntryID = decision["gate_entry_id"]
	}
	evidence := func() map[string]any {
		return map[string]any{"contract_id": contractID, "gate_entry_id": gateEntryID}
	}
	return []any{
		map[string]any{
			"framework": "ISO 42001",
			"controls":  []any{"AI system impact assessment", "Evaluation and monitoring", "Human oversight"},
			"evidence":  evidence(),
		},
		map[string]any{
			"framework": "NIST AI RMF",
			"controls":  []any{"Measure 2.5", "Manage 1.3", "Govern 6.1"},
			"evidence":  evidence(),
		},
		map[string]any{
			"framework": "EU AI Act Annex III",
			"controls":  []any{"Technical documentation", "Logging", "Human oversight"},
			"evidence":  evidence(),
		},
		map[string]any{
			"framework": "SR 11-7",
			"controls":  []any{"Model validation", "Ongoing monitoring", "Change control"},
			"evidence":  evidence(),
		},
		map[string]any{
			"framework": "SOC 2",
			"controls":  []any{"Change management", "Logical access", "Monitoring"},
			"evidence":  evidence(),
		},
	}
}

func entryCore(entry map[string]any) map[string]any {
	return withoutKeys(entry, "entry_id", "signature", "timestamp_token")
}

func verifyValue(value any, sig map[string]any, key string) bool {
	if getString(sig, "alg") != "HMAC-SHA256" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(canonicalBytes(value))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(getString(sig, "value")))
}

func verifyPackedChainTree(tree map[string]any, entries []any, label string) []string {
	var errors []string
	if tree == nil {
		return []string{label + " tree must be an object"}
	}
	size, sizeOK := intValue(tree["size"])
	root := getString(tree, "root")
	rootOK := isSHA256Hex(root)
	if !sizeOK || size < 0 {
		errors = append(errors, label+" tree size must be a non-negative integer")
	}
	if !rootOK {
		errors = append(errors, label+" tree root must be a SHA-256 hex digest")
	}
	if !sizeOK || size < 0 {
		return errors
	}

	validEntries := 0
	indexes := []int64{}
	seenIndexes := map[int64]bool{}
	duplicateIndexes := false
	idsByIndex := map[int64]string{}
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		validEntries++
		index, ok := intValue(entry["index"])
		if !ok {
			continue
		}
		indexes = append(indexes, index)
		if seenIndexes[index] {
			duplicateIndexes = true
		}
		seenIndexes[index] = true
		if entryID := getString(entry, "entry_id"); entryID != "" {
			idsByIndex[index] = entryID
		}
	}

	if int64(validEntries) > size {
		errors = append(errors, label+" tree size is smaller than packed entry count")
	}
	if duplicateIndexes {
		errors = append(errors, label+" entries contain duplicate indexes")
	}
	if len(indexes) > 0 {
		maxIndex := indexes[0]
		for _, index := range indexes[1:] {
			if index > maxIndex {
				maxIndex = index
			}
		}
		if maxIndex >= size {
			errors = append(errors, label+" tree size is smaller than packed entry indexes")
		}
	}

	complete := rootOK && int64(len(indexes)) == size && int64(len(idsByIndex)) == size
	if complete {
		entryIDs := make([]string, 0, int(size))
		for index := int64(0); index < size; index++ {
			entryID, ok := idsByIndex[index]
			if !ok {
				complete = false
				break
			}
			entryIDs = append(entryIDs, entryID)
		}
		if complete && root != merkleRoot(entryIDs) {
			errors = append(errors, label+" tree root does not match packed entries")
		}
	}
	return errors
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func merkleRoot(entryIDs []string) string {
	if len(entryIDs) == 0 {
		sum := sha256.Sum256([]byte(emptyRoot))
		return hex.EncodeToString(sum[:])
	}
	level := make([]string, 0, len(entryIDs))
	for _, entryID := range entryIDs {
		level = append(level, leafHash(entryID))
	}
	for len(level) > 1 {
		level = nextLevel(level)
	}
	return level[0]
}

func nextLevel(level []string) []string {
	next := []string{}
	for index := 0; index < len(level); index += 2 {
		if index+1 >= len(level) {
			next = append(next, level[index])
		} else {
			next = append(next, nodeHash(level[index], level[index+1]))
		}
	}
	return next
}

func verifyInclusion(entryID string, proof []any, expectedRoot string) bool {
	computed := leafHash(entryID)
	for _, raw := range proof {
		step, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		position := getString(step, "position")
		sibling := getString(step, "hash")
		if sibling == "" {
			return false
		}
		if position == "left" {
			computed = nodeHash(sibling, computed)
		} else if position == "right" {
			computed = nodeHash(computed, sibling)
		} else {
			return false
		}
	}
	return computed == expectedRoot
}

func leafHash(entryID string) string {
	sum := sha256.Sum256([]byte(leafPrefix + entryID))
	return hex.EncodeToString(sum[:])
}

func nodeHash(leftHex, rightHex string) string {
	left, err1 := hex.DecodeString(leftHex)
	right, err2 := hex.DecodeString(rightHex)
	if err1 != nil || err2 != nil {
		return ""
	}
	data := append([]byte(nodePrefix), left...)
	data = append(data, right...)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func contentHash(value any) string {
	sum := sha256.Sum256(canonicalBytes(value))
	return hex.EncodeToString(sum[:])
}

func canonicalBytes(value any) []byte {
	var b strings.Builder
	writeCanonical(&b, value)
	return []byte(b.String())
}

func writeCanonical(b *strings.Builder, value any) {
	switch v := value.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if v {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		b.WriteString(quoteString(v))
	case json.Number:
		b.WriteString(v.String())
	case float64:
		b.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
	case int:
		b.WriteString(strconv.Itoa(v))
	case []any:
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, item)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(quoteString(k))
			b.WriteByte(':')
			writeCanonical(b, v[k])
		}
		b.WriteByte('}')
	default:
		data, _ := json.Marshal(v)
		b.Write(data)
	}
}

func quoteString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(buf.String(), "\n")
}

func loadJSON(path string) (map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.UseNumber()
	var value map[string]any
	if err := dec.Decode(&value); err != nil && err != io.EOF {
		return nil, err
	}
	return value, nil
}

func withoutKeys(m map[string]any, keys ...string) map[string]any {
	blocked := map[string]bool{}
	for _, key := range keys {
		blocked[key] = true
	}
	out := map[string]any{}
	for k, v := range m {
		if !blocked[k] {
			out[k] = v
		}
	}
	return out
}

func getMap(m map[string]any, key string) map[string]any {
	if key == "" {
		return m
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

func getSlice(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	if key == "" {
		if v, ok := any(m).([]any); ok {
			return v
		}
		return nil
	}
	if v, ok := m[key].([]any); ok {
		return v
	}
	return nil
}

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, _ := m[key].(bool)
	return v
}

func intValue(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case float64:
		i := int64(n)
		return i, n == float64(i)
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

func numberInt(v any) int64 {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return i
	case float64:
		return int64(n)
	case int:
		return int64(n)
	}
	return 0
}

func pythonFloatNumber(value float64) json.Number {
	text := strconv.FormatFloat(value, 'f', -1, 64)
	if !strings.ContainsAny(text, ".eE") {
		text += ".0"
	}
	return json.Number(text)
}

func numberFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}

func sameNumber(left, right any) bool {
	if canonicalEqual(left, right) {
		return true
	}
	lf, lok := numberFloat(left)
	rf, rok := numberFloat(right)
	return lok && rok && lf == rf
}

func compareNumbers(actual, threshold any, op string) (bool, string) {
	a, okA := numberFloat(actual)
	t, okT := numberFloat(threshold)
	if !okA || !okT {
		return false, "non-numeric comparison"
	}
	switch op {
	case ">=":
		return a >= t, ""
	case ">":
		return a > t, ""
	case "<=":
		return a <= t, ""
	case "<":
		return a < t, ""
	case "==":
		return a == t, ""
	case "!=":
		return a != t, ""
	default:
		return false, "unsupported operator"
	}
}

func canonicalEqual(left, right any) bool {
	return string(canonicalBytes(left)) == string(canonicalBytes(right))
}

func cloneMap(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func mustParseTime(value string) time.Time {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func recordID(record map[string]any, fallback int) any {
	if id := record["id"]; id != nil {
		return id
	}
	return fallback
}

func getenvDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
