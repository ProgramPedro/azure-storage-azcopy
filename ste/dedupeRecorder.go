// Copyright © Microsoft <wastore@microsoft.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package ste

import (
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/Azure/azure-storage-azcopy/v10/common"
)

// This file implements "Phase 1" of the block-level dedupe prototype: "record + measure".
//
// Building on the read-only Phase 0 observer (sourceGridObserver.go), it records each
// source committed block that carries content hashes into a per-job DedupeHashTable, and
// measures the "would-be" dedupe hit rate: how many migrated blocks have content identical
// to a block already recorded earlier in the same job (within a blob or across blobs).
//
// Like Phase 0, it is gated on AZCOPY_DEDUPE_OBSERVE=true and NEVER changes transfer
// behavior. Its only job is to prove the real, end-to-end dedupe potential with hard numbers
// before any bytes are actually skipped (Phase 2) or the chunk grid is changed (Phase 3).

// dedupeJobState holds a single job's dedupe table plus cumulative would-be-hit counters.
type dedupeJobState struct {
	table *common.DedupeHashTable

	// Counters are cumulative across every blob processed for the job, and are updated
	// atomically because transfers (and therefore observeSourceGrid calls) run concurrently.
	hashedBlocks   int64 // blocks that carried crc64+sha256 (i.e. were eligible for dedupe)
	wouldBeHits    int64 // eligible blocks whose content was already recorded by an earlier block
	dedupableBytes int64 // total size of would-be-hit blocks: bytes that need not be re-transferred
}

var (
	dedupeJobsMu sync.Mutex
	dedupeJobs   = make(map[common.JobID]*dedupeJobState)
)

// dedupeStateForJob returns the dedupe state for a job, creating it on first use. The map is
// only ever populated when the prototype flag is on (observeSourceGrid is the sole caller), so
// no per-job memory is allocated in the default code path.
func dedupeStateForJob(jobID common.JobID) *dedupeJobState {
	dedupeJobsMu.Lock()
	defer dedupeJobsMu.Unlock()

	st, ok := dedupeJobs[jobID]
	if !ok {
		st = &dedupeJobState{table: common.NewDedupeHashTable()}
		dedupeJobs[jobID] = st
	}
	return st
}

// clearDedupeStateForJob drops a job's dedupe table to release its memory. It is safe to call
// when no state exists. Wiring this to a job-teardown hook is a follow-up; for the opt-in
// prototype (one job per process invocation) the table is released at process exit.
func clearDedupeStateForJob(jobID common.JobID) {
	dedupeJobsMu.Lock()
	defer dedupeJobsMu.Unlock()

	if st, ok := dedupeJobs[jobID]; ok {
		st.table.Clear()
		delete(dedupeJobs, jobID)
	}
}

// blockHasHashes reports whether a planned block carries content hashes from the extended
// GetBlockList response. When the service GetHash feature is off (or include was not honored),
// both hashes are left zero and the block is not eligible for dedupe measurement.
func blockHasHashes(b PlannedBlock) bool {
	return b.CRC64 != 0 || b.SHA256 != ([32]byte{})
}

// measureAndRecord performs the Phase 1 lookup-then-record over a set of planned blocks against
// the given table. For each block that carries hashes it (1) looks the content up, counting a
// would-be hit when identical content was already recorded, then (2) records the block keyed to
// where it is being migrated (targetURI). It returns the number of eligible (hashed) blocks, the
// number of would-be hits, and the total size of those hit blocks.
//
// It is deliberately free of any jptm/logging dependency so it can be unit tested directly.
//
// Note: between the Lookup and Insert of a given block another goroutine may insert identical
// content, so concurrent identical blocks can be under-counted as misses. That is acceptable for a
// measurement phase — the reported hit rate is conservative (never over-counted).
func measureAndRecord(table *common.DedupeHashTable, jobID common.JobID, targetURI string, blocks []PlannedBlock) (hashed, hits, dedupableBytes int64) {
	for _, b := range blocks {
		if !blockHasHashes(b) {
			continue
		}
		hashed++

		if _, hit := table.Lookup(b.CRC64, b.SHA256); hit {
			hits++
			dedupableBytes += b.Size
		}

		table.Insert(common.BlockEntry{
			JobID:     jobID,
			CRC64:     b.CRC64,
			SHA256:    b.SHA256,
			TargetURI: targetURI,
			// ETag is populated in Phase 2, where recording happens after a successful
			// destination write; Phase 1 records pre-write, for measurement only.
		})
	}
	return hashed, hits, dedupableBytes
}

// sanitizedDestForDedupe returns the destination blob URL with any query string (e.g. a SAS
// token) stripped, so credentials are never stored in the table. If the URL cannot be parsed it
// is returned unchanged (the table is in-memory and prototype-only).
func sanitizedDestForDedupe(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery = ""
	return u.String()
}

// dedupePercent returns hits/total as a percentage, treating total==0 as 0%.
func dedupePercent(hits, total int64) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(hits) / float64(total)
}

// recordSourceGridForDedupe implements Phase 1 for a single transfer (blob). It records the
// source's committed blocks into the per-job table, accumulates the would-be-hit counters, and
// logs both this blob's contribution and the running job-wide hit rate. It changes no transfer
// behavior.
func recordSourceGridForDedupe(jptm IJobPartTransferMgr, plan *SourceGridPlan) {
	info := jptm.Info()
	st := dedupeStateForJob(info.JobID)
	targetURI := sanitizedDestForDedupe(info.Destination)

	hashed, hits, dedupableBytes := measureAndRecord(st.table, info.JobID, targetURI, plan.Blocks)
	if hashed == 0 {
		return // nothing eligible (service GetHash feature off, or include not honored)
	}

	totalHashed := atomic.AddInt64(&st.hashedBlocks, hashed)
	totalHits := atomic.AddInt64(&st.wouldBeHits, hits)
	totalBytes := atomic.AddInt64(&st.dedupableBytes, dedupableBytes)

	jptm.LogAtLevelForCurrentTransfer(common.LogInfo, fmt.Sprintf(
		"dedupe-phase1: blob %q would-be-hits=%d/%d blocks; job cumulative would-be-hits=%d/%d blocks (%.1f%%), dedupable bytes=%d, table entries=%d",
		info.SrcFilePath, hits, hashed,
		totalHits, totalHashed, dedupePercent(totalHits, totalHashed),
		totalBytes, st.table.Len()))
}
