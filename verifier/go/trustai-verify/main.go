package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
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
	defaultSigningKey    = "trustai-local-dev-key-change-me"
	defaultTSAKey        = "trustai-local-tsa-key-change-me"

	contractEntryType = "verification_contract.registered"
	evalEntryType     = "eval.completed"
	gateEntryType     = "promotion_gate.decided"
	approvalEntryType = "human_approval.granted"

	leafPrefix = "trustai-merkle-leaf-v1\x00"
	nodePrefix = "trustai-merkle-node-v1\x00"
)

type result struct {
	OK       bool
	Errors   []string
	Warnings []string
	Decision string
}

func main() {
	key := flag.String("key", getenvDefault("TRUSTAI_SIGNING_KEY", defaultSigningKey), "local HMAC signing key")
	tsaKey := flag.String("tsa-key", getenvDefault("TRUSTAI_TSA_KEY", defaultTSAKey), "local TSA HMAC key")
	jsonOut := flag.Bool("json", false, "emit machine-readable verification result")
	quiet := flag.Bool("quiet", false, "suppress success details")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: trustai-verify [--key KEY] [--tsa-key KEY] [--json] <proof-pack.json>")
		os.Exit(2)
	}
	pack, err := loadJSON(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load proof pack: %v\n", err)
		os.Exit(2)
	}
	res := verifyProofPack(pack, *key, *tsaKey)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else if res.OK {
		if !*quiet {
			fmt.Printf("verified proof pack: %s\n", flag.Arg(0))
			if res.Decision != "" {
				fmt.Printf("decision: %s\n", res.Decision)
			}
			for _, warning := range res.Warnings {
				fmt.Printf("warning: %s\n", warning)
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "proof pack verification failed: %s\n", flag.Arg(0))
		for _, err := range res.Errors {
			fmt.Fprintf(os.Stderr, "- %s\n", err)
		}
	}
	if !res.OK {
		os.Exit(1)
	}
}

func verifyProofPack(pack map[string]any, key, tsaKey string) result {
	var errors []string
	var warnings []string

	if getString(pack, "spec_version") != proofPackSpecVersion {
		errors = append(errors, fmt.Sprintf("unsupported proof pack spec_version: %v", pack["spec_version"]))
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
	tree := getMap(chain, "tree")
	root := getString(tree, "root")
	entries := getSlice(chain, "entries")
	proofs := getMap(chain, "inclusion_proofs")
	entryByType := map[string]map[string]any{}
	var approvalEntries []map[string]any

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
		if getString(getMap(contractEntry, "payload"), "contract_hash") != contractDigest {
			errors = append(errors, "contract entry hash does not match packed contract")
		}
		evalPayload := getMap(evalEntry, "payload")
		gatePayload := getMap(gateEntry, "payload")
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

	decision := getString(getMap(pack, "gate_decision"), "outcome")
	if decision != "" && decision != "passed" {
		warnings = append(warnings, "proof pack is valid but gate outcome is "+decision)
	}
	return result{OK: len(errors) == 0, Errors: errors, Warnings: warnings, Decision: decision}
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
			"entry_id":         entry["entry_id"],
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
		"min_timestamp":  getString(getMap(contract, "holdout"), "min_timestamp"),
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
