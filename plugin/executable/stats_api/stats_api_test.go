/*
 * Copyright (C) 2020-2026, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package stats_api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/klauspost/compress/gzip"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func TestRingBuffer(t *testing.T) {
	rb := NewRingBuffer(5)
	for i := 1; i <= 10; i++ {
		rb.Push(LogEntry{
			Domain:    fmt.Sprintf("example%d.com.", i),
			ClientIP:  "192.168.1.1",
			IsBlocked: i%2 == 0,
			IsCached:  i%3 == 0,
		})
	}

	total, logs := rb.QueryLogs(10, 0, "", "all")
	if total != 5 {
		t.Fatalf("expected total 5, got %d", total)
	}
	if len(logs) != 5 {
		t.Fatalf("expected 5 logs, got %d", len(logs))
	}

	if logs[0].Domain != "example10.com." {
		t.Errorf("expected newest domain example10.com., got %s", logs[0].Domain)
	}

	totalSearch, searchLogs := rb.QueryLogs(10, 0, "example9", "all")
	if totalSearch != 1 || searchLogs[0].Domain != "example9.com." {
		t.Errorf("search failed, total: %d", totalSearch)
	}

	totalBlocked, blockedLogs := rb.QueryLogs(10, 0, "", "blocked")
	if totalBlocked != 3 {
		t.Errorf("expected 3 blocked logs, got %d", totalBlocked)
	}
	for _, l := range blockedLogs {
		if !l.IsBlocked {
			t.Errorf("expected blocked log, got unblocked: %s", l.Domain)
		}
	}

	_, pageLogs := rb.QueryLogs(2, 1, "", "all")
	if len(pageLogs) != 2 {
		t.Fatalf("expected 2 page items, got %d", len(pageLogs))
	}
	if pageLogs[0].Domain != logs[1].Domain {
		t.Errorf("pagination offset mismatch: got %s, expected %s", pageLogs[0].Domain, logs[1].Domain)
	}

	// Test Clear
	rb.Clear()
	totalClear, logsClear := rb.QueryLogs(10, 0, "", "all")
	if totalClear != 0 || len(logsClear) != 0 {
		t.Errorf("expected 0 logs after clear, got %d", totalClear)
	}
}

func TestRingBufferExportImport(t *testing.T) {
	rb1 := NewRingBuffer(5)
	for i := 1; i <= 8; i++ {
		rb1.Push(LogEntry{
			Domain:   fmt.Sprintf("domain%d.com.", i),
			ClientIP: "10.0.0.1",
		})
	}

	exported, seqID := rb1.Export()
	if len(exported) != 5 {
		t.Fatalf("expected 5 exported entries, got %d", len(exported))
	}
	if seqID != 8 {
		t.Errorf("expected seqID 8, got %d", seqID)
	}
	if exported[0].Domain != "domain4.com." {
		t.Errorf("expected oldest in exported to be domain4.com., got %s", exported[0].Domain)
	}
	if exported[4].Domain != "domain8.com." {
		t.Errorf("expected newest in exported to be domain8.com., got %s", exported[4].Domain)
	}

	// Import into same capacity
	rb2 := NewRingBuffer(5)
	rb2.Import(exported, seqID)
	total, logs2 := rb2.QueryLogs(10, 0, "", "all")
	if total != 5 || len(logs2) != 5 {
		t.Fatalf("expected 5 logs in rb2, got %d", total)
	}
	if logs2[0].Domain != "domain8.com." {
		t.Errorf("expected newest log to be domain8.com., got %s", logs2[0].Domain)
	}
	if logs2[4].Domain != "domain4.com." {
		t.Errorf("expected oldest log to be domain4.com., got %s", logs2[4].Domain)
	}

	// Test pushing another entry to rb2 to verify seqID continues
	rb2.Push(LogEntry{Domain: "domain9.com."})
	_, logsAfterPush := rb2.QueryLogs(1, 0, "", "all")
	if logsAfterPush[0].Domain != "domain9.com." {
		t.Errorf("expected newest log domain9.com., got %s", logsAfterPush[0].Domain)
	}

	// Import into smaller capacity (3)
	rb3 := NewRingBuffer(3)
	rb3.Import(exported, seqID)
	total3, logs3 := rb3.QueryLogs(10, 0, "", "all")
	if total3 != 3 || len(logs3) != 3 {
		t.Fatalf("expected 3 logs in rb3, got %d", total3)
	}
	if logs3[0].Domain != "domain8.com." {
		t.Errorf("expected newest log domain8.com., got %s", logs3[0].Domain)
	}
	if logs3[2].Domain != "domain6.com." {
		t.Errorf("expected oldest log domain6.com., got %s", logs3[2].Domain)
	}
}

func TestTopStats(t *testing.T) {
	top := NewTopStats()

	top.Record("a.com.", "192.168.1.1", false)
	top.Record("a.com.", "192.168.1.1", false)
	top.Record("b.com.", "192.168.1.2", true)

	domains, _, blocked := top.GetTop(10)

	if len(domains) == 0 || domains[0].Domain != "a.com." || domains[0].Count != 2 {
		t.Errorf("top domains mismatch: %+v", domains)
	}

	if len(blocked) == 0 || blocked[0].Domain != "b.com." {
		t.Errorf("top blocked mismatch: %+v", blocked)
	}

	// Test Clear
	top.Clear()
	dClear, _, _ := top.GetTop(10)
	if len(dClear) != 0 {
		t.Errorf("expected 0 top domains after clear, got %d", len(dClear))
	}
}

func TestTopStatsExportImport(t *testing.T) {
	top1 := NewTopStats()
	top1.Record("a.com.", "192.168.1.1", false)
	top1.Record("a.com.", "192.168.1.1", false)
	top1.Record("b.com.", "192.168.1.2", true)

	d, c, b := top1.Export()
	top2 := NewTopStats()
	top2.Import(d, c, b)

	domains, clients, blocked := top2.GetTop(10)
	if len(domains) != 1 || domains[0].Domain != "a.com." || domains[0].Count != 2 {
		t.Errorf("top domains export/import mismatch: %+v", domains)
	}
	if len(clients) != 2 {
		t.Errorf("top clients count mismatch: %+v", clients)
	}
	if len(blocked) != 1 || blocked[0].Domain != "b.com." {
		t.Errorf("top blocked mismatch: %+v", blocked)
	}
}

func TestHistoryStats(t *testing.T) {
	h := NewHistoryStats()
	now := time.Now()

	h.Record(now, false, false)
	h.Record(now, true, false)
	h.Record(now, false, true)

	points := h.GetHistory(24)
	if len(points) != 24 {
		t.Fatalf("expected 24 history points, got %d", len(points))
	}

	lastPoint := points[len(points)-1]
	if lastPoint.Total != 3 || lastPoint.Blocked != 1 || lastPoint.Cached != 1 {
		t.Errorf("history point mismatch: %+v", lastPoint)
	}

	parsedTime, err := time.Parse(time.RFC3339, lastPoint.Time)
	if err != nil {
		t.Fatalf("failed to parse history point time: %v", err)
	}
	expectedHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
	if parsedTime.Unix() != expectedHour.Unix() {
		t.Errorf("expected history point time unix %d, got %d", expectedHour.Unix(), parsedTime.Unix())
	}
}

func TestHistoryStatsExportImport(t *testing.T) {
	h1 := NewHistoryStats()
	now := time.Now()
	h1.Record(now, false, false)
	h1.Record(now, true, true)

	exported := h1.Export()
	if len(exported) == 0 {
		t.Fatalf("expected exported history points")
	}

	h2 := NewHistoryStats()
	h2.Import(exported)
	points := h2.GetHistory(24)
	lastPoint := points[len(points)-1]
	if lastPoint.Total != 2 || lastPoint.Blocked != 1 || lastPoint.Cached != 1 {
		t.Errorf("history stats import mismatch: %+v", lastPoint)
	}
}

func TestStatsAPIHTTPEndpoints(t *testing.T) {
	s := NewStatsAPI(&Args{Capacity: 100}, zap.NewNop())
	router := s.Router()

	s.ringBuffer.Push(LogEntry{
		Domain:    "test.com.",
		ClientIP:  "192.168.1.50",
		IsBlocked: true,
		IsCached:  false,
		ElapsedMS: 15.5,
		Upstream:  "UDP://8.8.8.8:53",
		Rule:      "qname test.com.",
	})
	s.totalQueries.Add(1)
	s.blockedQueries.Add(1)
	s.totalLatencyUs.Add(15500)
	s.topStats.Record("test.com.", "192.168.1.50", true)
	s.historyStats.Record(time.Now(), true, false)

	// Test GET /api/v1/stats
	reqStats := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	wStats := httptest.NewRecorder()
	router.ServeHTTP(wStats, reqStats)

	if wStats.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", wStats.Code)
	}

	var statsResp map[string]any
	if err := json.Unmarshal(wStats.Body.Bytes(), &statsResp); err != nil {
		t.Fatalf("failed to unmarshal stats response: %v", err)
	}
	if statsResp["total_queries"].(float64) != 1 {
		t.Errorf("expected total_queries 1, got %v", statsResp["total_queries"])
	}
	if _, ok := statsResp["qps"]; !ok {
		t.Errorf("expected qps field in stats response")
	}

	// Test GET /api/v1/history
	reqHist := httptest.NewRequest(http.MethodGet, "/api/v1/history?points=24", nil)
	wHist := httptest.NewRecorder()
	router.ServeHTTP(wHist, reqHist)

	if wHist.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for history, got %d", wHist.Code)
	}
	var histResp map[string]any
	if err := json.Unmarshal(wHist.Body.Bytes(), &histResp); err != nil {
		t.Fatalf("failed to unmarshal history response: %v", err)
	}
	histPoints := histResp["points"].([]any)
	if len(histPoints) != 24 {
		t.Errorf("expected 24 history points, got %d", len(histPoints))
	}

	// Test GET /api/v1/dump
	reqDump := httptest.NewRequest(http.MethodGet, "/api/v1/dump", nil)
	wDump := httptest.NewRecorder()
	router.ServeHTTP(wDump, reqDump)
	if wDump.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for dump, got %d", wDump.Code)
	}
	dumpBytes := wDump.Body.Bytes()
	if len(dumpBytes) == 0 {
		t.Fatalf("expected non-empty dump body")
	}

	// Test POST /api/v1/load_dump
	s2 := NewStatsAPI(&Args{Capacity: 100}, zap.NewNop())
	router2 := s2.Router()
	reqLoadDump := httptest.NewRequest(http.MethodPost, "/api/v1/load_dump", bytes.NewReader(dumpBytes))
	wLoadDump := httptest.NewRecorder()
	router2.ServeHTTP(wLoadDump, reqLoadDump)
	if wLoadDump.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for load_dump, got %d", wLoadDump.Code)
	}
	if s2.totalQueries.Load() != 1 {
		t.Errorf("expected s2 total queries to be 1 after load_dump, got %d", s2.totalQueries.Load())
	}

	// Test POST /api/v1/logs/clear
	reqClearLogs := httptest.NewRequest(http.MethodPost, "/api/v1/logs/clear", nil)
	wClearLogs := httptest.NewRecorder()
	router.ServeHTTP(wClearLogs, reqClearLogs)

	if wClearLogs.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for clear logs, got %d", wClearLogs.Code)
	}

	// Verify logs ring buffer is empty
	totalLogs, logs := s.ringBuffer.QueryLogs(10, 0, "", "all")
	if totalLogs != 0 || len(logs) != 0 {
		t.Errorf("expected 0 logs after clear, got %d", totalLogs)
	}

	// Test POST /api/v1/cache/clear
	reqClearCache := httptest.NewRequest(http.MethodPost, "/api/v1/cache/clear", nil)
	wClearCache := httptest.NewRecorder()
	router.ServeHTTP(wClearCache, reqClearCache)

	if wClearCache.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for clear cache, got %d", wClearCache.Code)
	}
}

func TestStatsAPIExec(t *testing.T) {
	s := NewStatsAPI(&Args{Capacity: 100}, zap.NewNop())

	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	qCtx.SetUpstreamSelected("8.8.8.8:53", "UDP", "remote", "forward_remote")
	qCtx.AddRuleHit("main_sequence", []string{"qname google.com."}, "forward_remote")

	execFunc := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		time.Sleep(10 * time.Millisecond)
		resp := new(dns.Msg)
		resp.SetReply(qCtx.Q())
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{142, 250, 190, 46},
		})
		qCtx.SetResponse(resp)
		return nil
	})

	walker := sequence.NewChainWalker([]*sequence.ChainNode{
		{E: execFunc},
	}, nil)

	err := s.Exec(context.Background(), qCtx, walker)
	if err != nil {
		t.Fatalf("Exec returned error: %v", err)
	}

	if s.totalQueries.Load() != 1 {
		t.Errorf("expected 1 total query, got %d", s.totalQueries.Load())
	}

	totalLogs, logs := s.ringBuffer.QueryLogs(10, 0, "", "all")
	if totalLogs != 1 {
		t.Fatalf("expected 1 log entry, got %d", totalLogs)
	}
	if logs[0].Domain != "google.com." {
		t.Errorf("expected domain google.com., got %s", logs[0].Domain)
	}
	if logs[0].Upstream != "8.8.8.8:53" {
		t.Errorf("expected upstream 8.8.8.8:53, got %s", logs[0].Upstream)
	}
	if logs[0].Rule != "qname google.com." {
		t.Errorf("expected rule qname google.com., got %s", logs[0].Rule)
	}
}

func TestStatsAPIPersistence(t *testing.T) {
	tempDir := t.TempDir()
	dumpFilePath := filepath.Join(tempDir, "stats.dump")

	// Phase 1: Start stats_api with dump_file configured
	s1 := NewStatsAPI(&Args{
		Capacity:     50,
		DumpFile:     dumpFilePath,
		DumpInterval: 600,
	}, zap.NewNop())

	// Push test logs and stats
	for i := 1; i <= 10; i++ {
		s1.ringBuffer.Push(LogEntry{
			Domain:    fmt.Sprintf("test%d.com.", i),
			ClientIP:  "192.168.1.100",
			IsBlocked: i%2 == 0,
			IsCached:  i%3 == 0,
			ElapsedMS: float64(i * 5),
		})
		s1.totalQueries.Add(1)
		if i%2 == 0 {
			s1.blockedQueries.Add(1)
		}
		if i%3 == 0 {
			s1.cachedQueries.Add(1)
		}
		if i%4 == 0 {
			s1.hostsQueries.Add(1)
		}
		if i%5 == 0 {
			s1.arbitraryQueries.Add(1)
		}
		s1.totalLatencyUs.Add(uint64(i * 5000))
		s1.topStats.Record(fmt.Sprintf("test%d.com.", i), "192.168.1.100", i%2 == 0)
		s1.historyStats.Record(time.Now(), i%2 == 0, i%3 == 0)
	}

	// Close s1 -> triggers dumpStats()
	if err := s1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify file exists
	fi, err := os.Stat(dumpFilePath)
	if err != nil {
		t.Fatalf("dump file was not created: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatalf("dump file is empty")
	}

	// Verify gzip header and compression
	f, err := os.Open(dumpFilePath)
	if err != nil {
		t.Fatalf("failed to open dump file: %v", err)
	}
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("failed to create gzip reader on dump file: %v", err)
	}
	if gr.Name != statsDumpHeader {
		t.Errorf("expected gzip header %s, got %s", statsDumpHeader, gr.Name)
	}
	_ = gr.Close()
	_ = f.Close()

	// Phase 2: Start new instance s2 with same dump_file -> loads dump automatically
	s2 := NewStatsAPI(&Args{
		Capacity:     50,
		DumpFile:     dumpFilePath,
		DumpInterval: 600,
	}, zap.NewNop())
	defer s2.Close()

	if s2.totalQueries.Load() != 10 {
		t.Errorf("expected 10 total queries after load, got %d", s2.totalQueries.Load())
	}
	if s2.blockedQueries.Load() != 5 {
		t.Errorf("expected 5 blocked queries after load, got %d", s2.blockedQueries.Load())
	}
	if s2.cachedQueries.Load() != 3 {
		t.Errorf("expected 3 cached queries after load, got %d", s2.cachedQueries.Load())
	}
	if s2.hostsQueries.Load() != 2 {
		t.Errorf("expected 2 hosts queries after load, got %d", s2.hostsQueries.Load())
	}
	if s2.arbitraryQueries.Load() != 2 {
		t.Errorf("expected 2 arbitrary queries after load, got %d", s2.arbitraryQueries.Load())
	}

	totalLogs, logs := s2.ringBuffer.QueryLogs(10, 0, "", "all")
	if totalLogs != 10 || len(logs) != 10 {
		t.Fatalf("expected 10 logs in s2, got total=%d len=%d", totalLogs, len(logs))
	}
	if logs[0].Domain != "test10.com." {
		t.Errorf("expected newest log test10.com., got %s", logs[0].Domain)
	}

	topDomains, topClients, topBlocked := s2.topStats.GetTop(10)
	if len(topDomains) == 0 {
		t.Errorf("expected top domains to be restored")
	}
	if len(topClients) == 0 || topClients[0].ClientIP != "192.168.1.100" {
		t.Errorf("expected top clients to be restored")
	}
	if len(topBlocked) == 0 {
		t.Errorf("expected top blocked to be restored")
	}
}

func TestStatsAPINonExistentDumpFile(t *testing.T) {
	tempDir := t.TempDir()
	dumpFilePath := filepath.Join(tempDir, "non_existent_stats.dump")

	// Should not error or panic
	s := NewStatsAPI(&Args{
		DumpFile: dumpFilePath,
	}, zap.NewNop())
	defer s.Close()

	if s.totalQueries.Load() != 0 {
		t.Errorf("expected 0 total queries, got %d", s.totalQueries.Load())
	}
}

func TestStatsAPICachedPercentageExcludesBlocked(t *testing.T) {
	s := NewStatsAPI(&Args{Capacity: 100}, zap.NewNop())
	router := s.Router()

	// 100 total queries: 50 blocked, 25 cached, 25 forwarded to upstream
	s.totalQueries.Store(100)
	s.blockedQueries.Store(50)
	s.cachedQueries.Store(25)
	s.totalLatencyUs.Store(50000)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}

	var statsResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &statsResp); err != nil {
		t.Fatalf("failed to unmarshal stats response: %v", err)
	}

	// blocked_percentage = 50 / 100 = 50%
	if blockedPct := statsResp["blocked_percentage"].(float64); blockedPct != 50.0 {
		t.Errorf("expected blocked_percentage 50.0, got %v", blockedPct)
	}

	// cached_percentage = 25 / (100 - 50) = 50% (previously 25%)
	if cachedPct := statsResp["cached_percentage"].(float64); cachedPct != 50.0 {
		t.Errorf("expected cached_percentage 50.0, got %v", cachedPct)
	}
}

func TestStatsAPIQPS(t *testing.T) {
	s := NewStatsAPI(&Args{Capacity: 100}, zap.NewNop())
	defer s.Close()

	// Initially QPS is 0
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	var statsResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &statsResp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if qps, ok := statsResp["qps"]; !ok {
		t.Fatalf("expected qps field in stats response")
	} else if qps.(float64) != 0 {
		t.Errorf("expected initial qps 0, got %v", qps)
	}
}

func TestStatsAPICachedPercentageExcludesHostsAndArbitrary(t *testing.T) {
	s := NewStatsAPI(&Args{Capacity: 100}, zap.NewNop())
	router := s.Router()

	// 100 total queries: 20 blocked, 15 hosts, 15 arbitrary, 25 cached, 25 forwarded to upstream
	// denominator = 100 - (20 + 15 + 15) = 50
	// cached_percentage = 25 / 50 = 50%
	s.totalQueries.Store(100)
	s.blockedQueries.Store(20)
	s.hostsQueries.Store(15)
	s.arbitraryQueries.Store(15)
	s.cachedQueries.Store(25)
	s.totalLatencyUs.Store(50000)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}

	var statsResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &statsResp); err != nil {
		t.Fatalf("failed to unmarshal stats response: %v", err)
	}

	if hostsQueries := statsResp["hosts_queries"].(float64); hostsQueries != 15 {
		t.Errorf("expected hosts_queries 15, got %v", hostsQueries)
	}
	if arbitraryQueries := statsResp["arbitrary_queries"].(float64); arbitraryQueries != 15 {
		t.Errorf("expected arbitrary_queries 15, got %v", arbitraryQueries)
	}
	if blockedPct := statsResp["blocked_percentage"].(float64); blockedPct != 20.0 {
		t.Errorf("expected blocked_percentage 20.0, got %v", blockedPct)
	}
	if cachedPct := statsResp["cached_percentage"].(float64); cachedPct != 50.0 {
		t.Errorf("expected cached_percentage 50.0, got %v", cachedPct)
	}
}

func TestStatsAPIExecWithHostsAndArbitrary(t *testing.T) {
	s := NewStatsAPI(&Args{Capacity: 100}, zap.NewNop())

	// Test 1: Normal hosts resolution
	q1 := new(dns.Msg)
	q1.SetQuestion("lan.local.", dns.TypeA)
	qCtx1 := query_context.NewContext(q1)

	execHosts := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		resp := new(dns.Msg)
		resp.SetReply(qCtx.Q())
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "lan.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 168, 1, 10},
		})
		qCtx.SetResponse(resp)
		qCtx.SetFromHosts()
		return nil
	})

	walker1 := sequence.NewChainWalker([]*sequence.ChainNode{{E: execHosts}}, nil)
	if err := s.Exec(context.Background(), qCtx1, walker1); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if s.hostsQueries.Load() != 1 {
		t.Errorf("expected hostsQueries 1, got %d", s.hostsQueries.Load())
	}
	_, logs1 := s.ringBuffer.QueryLogs(1, 0, "", "all")
	if len(logs1) != 1 || logs1[0].Upstream != "hosts" {
		t.Errorf("expected upstream 'hosts', got %+v", logs1)
	}

	// Test 2: Hosts returning 0.0.0.0 (adblock) -> should be counted in blockedQueries, NOT hostsQueries
	q2 := new(dns.Msg)
	q2.SetQuestion("ad.example.com.", dns.TypeA)
	qCtx2 := query_context.NewContext(q2)

	execHostsBlock := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		resp := new(dns.Msg)
		resp.SetReply(qCtx.Q())
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "ad.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{0, 0, 0, 0},
		})
		qCtx.SetResponse(resp)
		qCtx.SetFromHosts()
		return nil
	})

	walker2 := sequence.NewChainWalker([]*sequence.ChainNode{{E: execHostsBlock}}, nil)
	if err := s.Exec(context.Background(), qCtx2, walker2); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if s.blockedQueries.Load() != 1 {
		t.Errorf("expected blockedQueries 1, got %d", s.blockedQueries.Load())
	}
	if s.hostsQueries.Load() != 1 { // Should still be 1 (not incremented)
		t.Errorf("expected hostsQueries to remain 1, got %d", s.hostsQueries.Load())
	}

	// Test 3: Arbitrary resolution
	q3 := new(dns.Msg)
	q3.SetQuestion("custom.zone.", dns.TypeA)
	qCtx3 := query_context.NewContext(q3)

	execArbitrary := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		resp := new(dns.Msg)
		resp.SetReply(qCtx.Q())
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "custom.zone.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{10, 0, 0, 1},
		})
		qCtx.SetResponse(resp)
		qCtx.SetFromArbitrary()
		return nil
	})

	walker3 := sequence.NewChainWalker([]*sequence.ChainNode{{E: execArbitrary}}, nil)
	if err := s.Exec(context.Background(), qCtx3, walker3); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if s.arbitraryQueries.Load() != 1 {
		t.Errorf("expected arbitraryQueries 1, got %d", s.arbitraryQueries.Load())
	}
	_, logs3 := s.ringBuffer.QueryLogs(1, 0, "", "all")
	if len(logs3) != 1 || logs3[0].Upstream != "arbitrary" {
		t.Errorf("expected upstream 'arbitrary', got %+v", logs3)
	}
}

func TestStatsAPINoAnswerUpstreamAndBlocked(t *testing.T) {
	s := NewStatsAPI(&Args{Capacity: 100}, zap.NewNop())

	// Case 1: Upstream returns NXDOMAIN (no answers) -> NOT blocked
	q1 := new(dns.Msg)
	q1.SetQuestion("apps.itunes-nocookie.com.", dns.TypeA)
	qCtx1 := query_context.NewContext(q1)
	qCtx1.SetUpstreamSelected("https://doh.pub/dns-query", "DoH", "remote", "forward_remote")

	execUpstreamNX := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		resp := new(dns.Msg)
		resp.SetReply(qCtx.Q())
		resp.Rcode = dns.RcodeNameError
		qCtx.SetResponse(resp)
		return nil
	})

	walker1 := sequence.NewChainWalker([]*sequence.ChainNode{{E: execUpstreamNX}}, nil)
	if err := s.Exec(context.Background(), qCtx1, walker1); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if s.blockedQueries.Load() != 0 {
		t.Errorf("expected blockedQueries 0, got %d", s.blockedQueries.Load())
	}
	_, logs1 := s.ringBuffer.QueryLogs(1, 0, "", "all")
	if len(logs1) != 1 || logs1[0].IsBlocked || logs1[0].Status != "NXDOMAIN" || logs1[0].Upstream != "https://doh.pub/dns-query" {
		t.Errorf("expected unblocked NXDOMAIN upstream log, got %+v", logs1)
	}

	// Case 2: Cache returns NXDOMAIN (no answers) -> NOT blocked
	q2 := new(dns.Msg)
	q2.SetQuestion("cached-nx.example.com.", dns.TypeA)
	qCtx2 := query_context.NewContext(q2)
	qCtx2.SetCacheState(true, false, 300, 300)

	execCacheNX := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		resp := new(dns.Msg)
		resp.SetReply(qCtx.Q())
		resp.Rcode = dns.RcodeNameError
		qCtx.SetResponse(resp)
		return nil
	})

	walker2 := sequence.NewChainWalker([]*sequence.ChainNode{{E: execCacheNX}}, nil)
	if err := s.Exec(context.Background(), qCtx2, walker2); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if s.blockedQueries.Load() != 0 {
		t.Errorf("expected blockedQueries 0, got %d", s.blockedQueries.Load())
	}
	_, logs2 := s.ringBuffer.QueryLogs(1, 0, "", "all")
	if len(logs2) != 1 || logs2[0].IsBlocked || logs2[0].Status != "NXDOMAIN" || logs2[0].Upstream != "cache" {
		t.Errorf("expected unblocked NXDOMAIN cache log, got %+v", logs2)
	}

	// Case 3: Local reject (no upstream, NXDOMAIN) -> IS blocked
	q3 := new(dns.Msg)
	q3.SetQuestion("ad.reject.com.", dns.TypeA)
	qCtx3 := query_context.NewContext(q3)

	execLocalReject := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		resp := new(dns.Msg)
		resp.SetReply(qCtx.Q())
		resp.Rcode = dns.RcodeNameError
		qCtx.SetResponse(resp)
		return nil
	})

	walker3 := sequence.NewChainWalker([]*sequence.ChainNode{{E: execLocalReject}}, nil)
	if err := s.Exec(context.Background(), qCtx3, walker3); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if s.blockedQueries.Load() != 1 {
		t.Errorf("expected blockedQueries 1, got %d", s.blockedQueries.Load())
	}
	_, logs3 := s.ringBuffer.QueryLogs(1, 0, "", "all")
	if len(logs3) != 1 || !logs3[0].IsBlocked {
		t.Errorf("expected blocked log, got %+v", logs3)
	}

	// Case 4: Upstream dropped (r == nil with upstream) -> NOT blocked
	q4 := new(dns.Msg)
	q4.SetQuestion("timeout.example.com.", dns.TypeA)
	qCtx4 := query_context.NewContext(q4)
	qCtx4.SetUpstreamSelected("8.8.8.8:53", "UDP", "remote", "forward_remote")

	execUpstreamDrop := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		return nil
	})

	walker4 := sequence.NewChainWalker([]*sequence.ChainNode{{E: execUpstreamDrop}}, nil)
	if err := s.Exec(context.Background(), qCtx4, walker4); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if s.blockedQueries.Load() != 1 { // Still 1 from case 3
		t.Errorf("expected blockedQueries to remain 1, got %d", s.blockedQueries.Load())
	}
	_, logs4 := s.ringBuffer.QueryLogs(1, 0, "", "all")
	if len(logs4) != 1 || logs4[0].IsBlocked || logs4[0].Status != "DROPPED" {
		t.Errorf("expected unblocked DROPPED log, got %+v", logs4)
	}

	// Case 5: Local drop (r == nil without upstream) -> IS blocked
	q5 := new(dns.Msg)
	q5.SetQuestion("local.drop.com.", dns.TypeA)
	qCtx5 := query_context.NewContext(q5)

	execLocalDrop := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		return nil
	})

	walker5 := sequence.NewChainWalker([]*sequence.ChainNode{{E: execLocalDrop}}, nil)
	if err := s.Exec(context.Background(), qCtx5, walker5); err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if s.blockedQueries.Load() != 2 {
		t.Errorf("expected blockedQueries 2, got %d", s.blockedQueries.Load())
	}
	_, logs5 := s.ringBuffer.QueryLogs(1, 0, "", "all")
	if len(logs5) != 1 || !logs5[0].IsBlocked || logs5[0].Status != "DROPPED" {
		t.Errorf("expected blocked DROPPED log, got %+v", logs5)
	}
}
