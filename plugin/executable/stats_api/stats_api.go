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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/klauspost/compress/gzip"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	PluginType      = "stats_api"
	statsDumpHeader = "mosdns_stats_v1"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

var _ sequence.RecursiveExecutable = (*StatsAPI)(nil)

type Args struct {
	Listen       string `yaml:"listen"`
	Capacity     int    `yaml:"capacity"`
	DumpFile     string `yaml:"dump_file"`
	DumpInterval int    `yaml:"dump_interval"`
}

func (a *Args) init() {
	if a.Capacity <= 0 {
		a.Capacity = 2000
	}
	utils.SetDefaultUnsignNum(&a.DumpInterval, 600)
}

type AnswerDTO struct {
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  uint32 `json:"ttl"`
}

type LogEntry struct {
	ID        string      `json:"id"`
	Timestamp string      `json:"timestamp"`
	ClientIP  string      `json:"client_ip"`
	Domain    string      `json:"domain"`
	QType     string      `json:"qtype"`
	Status    string      `json:"status"`
	IsBlocked bool        `json:"is_blocked"`
	IsCached  bool        `json:"is_cached"`
	ElapsedMS float64     `json:"elapsed_ms"`
	Upstream  string      `json:"upstream,omitempty"`
	Rule      string      `json:"rule,omitempty"`
	Answers   []AnswerDTO `json:"answers"`
}

type RingBuffer struct {
	mu       sync.RWMutex
	buf      []LogEntry
	capacity int
	head     int
	count    int
	seqID    uint64
}

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = 2000
	}
	return &RingBuffer{
		buf:      make([]LogEntry, capacity),
		capacity: capacity,
	}
}

func (r *RingBuffer) Push(entry LogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.seqID++
	nowSec := time.Now().Unix()
	entry.ID = fmt.Sprintf("%d-%d", nowSec, r.seqID)

	r.buf[r.head] = entry
	r.head = (r.head + 1) % r.capacity
	if r.count < r.capacity {
		r.count++
	}
}

func (r *RingBuffer) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.buf = make([]LogEntry, r.capacity)
	r.head = 0
	r.count = 0
	r.seqID = 0
}

func (r *RingBuffer) QueryLogs(limit, offset int, search, filter string) (int, []LogEntry) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	all := make([]LogEntry, 0, r.count)
	for i := 0; i < r.count; i++ {
		idx := (r.head - 1 - i + r.capacity) % r.capacity
		all = append(all, r.buf[idx])
	}

	searchLower := strings.ToLower(strings.TrimSpace(search))
	filterLower := strings.ToLower(strings.TrimSpace(filter))

	filtered := make([]LogEntry, 0, len(all))
	for _, entry := range all {
		if filterLower == "blocked" && !entry.IsBlocked {
			continue
		}
		if filterLower == "cached" && !entry.IsCached {
			continue
		}

		if searchLower != "" {
			if !strings.Contains(strings.ToLower(entry.Domain), searchLower) &&
				!strings.Contains(strings.ToLower(entry.ClientIP), searchLower) {
				continue
			}
		}

		filtered = append(filtered, entry)
	}

	total := len(filtered)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return total, []LogEntry{}
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return total, filtered[offset:end]
}

// Export returns logs in chronological order (oldest first) and current seqID.
func (r *RingBuffer) Export() ([]LogEntry, uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entries := make([]LogEntry, 0, r.count)
	for i := 0; i < r.count; i++ {
		idx := (r.head - r.count + i + r.capacity) % r.capacity
		entries = append(entries, r.buf[idx])
	}
	return entries, r.seqID
}

// Import restores logs into ring buffer adapting to current capacity.
func (r *RingBuffer) Import(entries []LogEntry, seqID uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.buf = make([]LogEntry, r.capacity)
	r.head = 0
	r.count = 0
	r.seqID = seqID

	start := 0
	if len(entries) > r.capacity {
		start = len(entries) - r.capacity
	}
	for i := start; i < len(entries); i++ {
		r.buf[r.head] = entries[i]
		r.head = (r.head + 1) % r.capacity
		if r.count < r.capacity {
			r.count++
		}
	}
}

type TopItem struct {
	Domain   string `json:"domain,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
	Count    uint64 `json:"count"`
}

type TopStats struct {
	mu         sync.RWMutex
	topDomains map[string]uint64
	topClients map[string]uint64
	topBlocked map[string]uint64
}

func NewTopStats() *TopStats {
	return &TopStats{
		topDomains: make(map[string]uint64),
		topClients: make(map[string]uint64),
		topBlocked: make(map[string]uint64),
	}
}

func (t *TopStats) Record(domain, clientIP string, isBlocked bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if domain != "" {
		if isBlocked {
			t.topBlocked[domain]++
		} else {
			t.topDomains[domain]++
		}
	}
	if clientIP != "" {
		t.topClients[clientIP]++
	}
}

func (t *TopStats) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.topDomains = make(map[string]uint64)
	t.topClients = make(map[string]uint64)
	t.topBlocked = make(map[string]uint64)
}

func (t *TopStats) Export() (map[string]uint64, map[string]uint64, map[string]uint64) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	domains := make(map[string]uint64, len(t.topDomains))
	for k, v := range t.topDomains {
		domains[k] = v
	}
	clients := make(map[string]uint64, len(t.topClients))
	for k, v := range t.topClients {
		clients[k] = v
	}
	blocked := make(map[string]uint64, len(t.topBlocked))
	for k, v := range t.topBlocked {
		blocked[k] = v
	}
	return domains, clients, blocked
}

func (t *TopStats) Import(domains, clients, blocked map[string]uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.topDomains = make(map[string]uint64, len(domains))
	for k, v := range domains {
		t.topDomains[k] = v
	}
	t.topClients = make(map[string]uint64, len(clients))
	for k, v := range clients {
		t.topClients[k] = v
	}
	t.topBlocked = make(map[string]uint64, len(blocked))
	for k, v := range blocked {
		t.topBlocked[k] = v
	}
}

func getSortedTop(m map[string]uint64, isClient bool, limit int) []TopItem {
	type pair struct {
		key   string
		count uint64
	}
	pairs := make([]pair, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, pair{key: k, count: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].count > pairs[j].count
	})

	if limit > len(pairs) {
		limit = len(pairs)
	}
	res := make([]TopItem, 0, limit)
	for i := 0; i < limit; i++ {
		item := TopItem{Count: pairs[i].count}
		if isClient {
			item.ClientIP = pairs[i].key
		} else {
			item.Domain = pairs[i].key
		}
		res = append(res, item)
	}
	return res
}

func (t *TopStats) GetTop(limit int) ([]TopItem, []TopItem, []TopItem) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if limit <= 0 {
		limit = 10
	}

	cleanTopDomains := make(map[string]uint64, len(t.topDomains))
	for domain, count := range t.topDomains {
		if _, isBlocked := t.topBlocked[domain]; !isBlocked {
			cleanTopDomains[domain] = count
		}
	}

	topDomains := getSortedTop(cleanTopDomains, false, limit)
	topClients := getSortedTop(t.topClients, true, limit)
	topBlocked := getSortedTop(t.topBlocked, false, limit)
	return topDomains, topClients, topBlocked
}

type HistoryPoint struct {
	Time    string `json:"time"`
	Total   uint64 `json:"total"`
	Blocked uint64 `json:"blocked"`
	Cached  uint64 `json:"cached"`
}

type HistoryBucket struct {
	Total   atomic.Uint64
	Blocked atomic.Uint64
	Cached  atomic.Uint64
}

type HistoryBucketData struct {
	Total   uint64 `json:"total"`
	Blocked uint64 `json:"blocked"`
	Cached  uint64 `json:"cached"`
}

type HistoryStats struct {
	mu     sync.RWMutex
	points map[int64]*HistoryBucket
}

func NewHistoryStats() *HistoryStats {
	return &HistoryStats{
		points: make(map[int64]*HistoryBucket),
	}
}

func (h *HistoryStats) Record(t time.Time, isBlocked, isCached bool) {
	tHour := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location()).Unix()

	h.mu.RLock()
	bucket, ok := h.points[tHour]
	h.mu.RUnlock()

	if !ok {
		h.mu.Lock()
		bucket, ok = h.points[tHour]
		if !ok {
			bucket = &HistoryBucket{}
			h.points[tHour] = bucket

			// Clean up old buckets beyond 48 hours
			cutoff := t.Add(-48 * time.Hour).Unix()
			for k := range h.points {
				if k < cutoff {
					delete(h.points, k)
				}
			}
		}
		h.mu.Unlock()
	}

	bucket.Total.Add(1)
	if isBlocked {
		bucket.Blocked.Add(1)
	}
	if isCached {
		bucket.Cached.Add(1)
	}
}

func (h *HistoryStats) GetHistory(numPoints int) []HistoryPoint {
	if numPoints <= 0 {
		numPoints = 24
	}
	now := time.Now()
	nowHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
	res := make([]HistoryPoint, 0, numPoints)

	h.mu.RLock()
	defer h.mu.RUnlock()

	for i := numPoints - 1; i >= 0; i-- {
		slotTime := nowHour.Add(time.Duration(-i) * time.Hour)
		slotUnix := slotTime.Unix()

		var total, blocked, cached uint64
		if bucket, ok := h.points[slotUnix]; ok {
			total = bucket.Total.Load()
			blocked = bucket.Blocked.Load()
			cached = bucket.Cached.Load()
		}

		res = append(res, HistoryPoint{
			Time:    slotTime.Format(time.RFC3339),
			Total:   total,
			Blocked: blocked,
			Cached:  cached,
		})
	}
	return res
}

func (h *HistoryStats) Export() map[int64]HistoryBucketData {
	h.mu.RLock()
	defer h.mu.RUnlock()

	res := make(map[int64]HistoryBucketData, len(h.points))
	for k, v := range h.points {
		if v != nil {
			res[k] = HistoryBucketData{
				Total:   v.Total.Load(),
				Blocked: v.Blocked.Load(),
				Cached:  v.Cached.Load(),
			}
		}
	}
	return res
}

func (h *HistoryStats) Import(points map[int64]HistoryBucketData) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.points = make(map[int64]*HistoryBucket, len(points))
	cutoff := time.Now().Add(-48 * time.Hour).Unix()
	for k, v := range points {
		if k >= cutoff {
			bucket := &HistoryBucket{}
			bucket.Total.Store(v.Total)
			bucket.Blocked.Store(v.Blocked)
			bucket.Cached.Store(v.Cached)
			h.points[k] = bucket
		}
	}
}

type StatsDumpData struct {
	Version          int                         `json:"version"`
	Timestamp        int64                       `json:"timestamp"`
	TotalQueries     uint64                      `json:"total_queries"`
	BlockedQueries   uint64                      `json:"blocked_queries"`
	CachedQueries    uint64                      `json:"cached_queries"`
	HostsQueries     uint64                      `json:"hosts_queries,omitempty"`
	ArbitraryQueries uint64                      `json:"arbitrary_queries,omitempty"`
	TotalLatencyUs   uint64                      `json:"total_latency_us"`
	TopDomains       map[string]uint64           `json:"top_domains,omitempty"`
	TopClients       map[string]uint64           `json:"top_clients,omitempty"`
	TopBlocked       map[string]uint64           `json:"top_blocked,omitempty"`
	History          map[int64]HistoryBucketData `json:"history,omitempty"`
	Logs             []LogEntry                  `json:"logs,omitempty"`
	SeqID            uint64                      `json:"seq_id,omitempty"`
}

type StatsAPI struct {
	args   *Args
	logger *zap.Logger

	ringBuffer   *RingBuffer
	topStats     *TopStats
	historyStats *HistoryStats

	totalQueries     atomic.Uint64
	blockedQueries   atomic.Uint64
	cachedQueries    atomic.Uint64
	hostsQueries     atomic.Uint64
	arbitraryQueries atomic.Uint64
	totalLatencyUs   atomic.Uint64
	currentQPS       atomic.Uint64

	updatedCount atomic.Uint64
	closeNotify  chan struct{}
	httpServer   *http.Server
	closeOnce    sync.Once
}

func Init(bp *coremain.BP, args any) (any, error) {
	a := args.(*Args)
	s := NewStatsAPI(a, bp.L())
	bp.RegAPI(s.Router())
	return s, nil
}

func QuickSetup(bq sequence.BQ, s string) (any, error) {
	fields := strings.Fields(s)
	listen := ""
	capacity := 2000
	dumpFile := ""
	dumpInterval := 600
	if len(fields) > 0 {
		listen = fields[0]
	}
	if len(fields) > 1 {
		if c, err := strconv.Atoi(fields[1]); err == nil && c > 0 {
			capacity = c
		}
	}
	if len(fields) > 2 {
		dumpFile = fields[2]
	}
	if len(fields) > 3 {
		if d, err := strconv.Atoi(fields[3]); err == nil && d > 0 {
			dumpInterval = d
		}
	}
	return NewStatsAPI(&Args{
		Listen:       listen,
		Capacity:     capacity,
		DumpFile:     dumpFile,
		DumpInterval: dumpInterval,
	}, bq.L()), nil
}

func NewStatsAPI(args *Args, logger *zap.Logger) *StatsAPI {
	args.init()
	if logger == nil {
		logger = zap.NewNop()
	}
	s := &StatsAPI{
		args:         args,
		logger:       logger,
		ringBuffer:   NewRingBuffer(args.Capacity),
		topStats:     NewTopStats(),
		historyStats: NewHistoryStats(),
		closeNotify:  make(chan struct{}),
	}

	if err := s.loadDump(); err != nil {
		s.logger.Error("failed to load stats dump", zap.Error(err))
	}
	s.startDumpLoop()
	s.startQPSLoop()

	if len(args.Listen) > 0 {
		srv := &http.Server{
			Addr:    args.Listen,
			Handler: s.Router(),
		}
		s.httpServer = srv
		go func() {
			logger.Info("starting stats api http server", zap.String("addr", args.Listen))
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("stats api http server error", zap.Error(err))
			}
		}()
	}
	return s
}

func (s *StatsAPI) Router() *chi.Mux {
	r := chi.NewRouter()

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if req.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, req)
		})
	})

	r.Get("/api/v1/stats", s.handleStats)
	r.Get("/api/v1/logs", s.handleLogs)
	r.Get("/api/v1/top", s.handleTop)
	r.Get("/api/v1/history", s.handleHistory)
	r.Get("/api/v1/dump", s.handleDump)
	r.Post("/api/v1/load_dump", s.handleLoadDump)
	r.Post("/api/v1/logs/clear", s.handleClearLogs)
	r.Post("/api/v1/cache/clear", s.handleClearCache)

	return r
}

func (s *StatsAPI) handleStats(w http.ResponseWriter, req *http.Request) {
	total := s.totalQueries.Load()
	blocked := s.blockedQueries.Load()
	cached := s.cachedQueries.Load()
	hosts := s.hostsQueries.Load()
	arbitrary := s.arbitraryQueries.Load()
	latUs := s.totalLatencyUs.Load()

	var blockedPct, cachedPct, avgLat float64
	if total > 0 {
		blockedPct = float64(blocked) / float64(total) * 100.0
		avgLat = (float64(latUs) / float64(total)) / 1000.0
	}
	excluded := blocked + hosts + arbitrary
	if total > excluded {
		cachedPct = float64(cached) / float64(total-excluded) * 100.0
		if cachedPct > 100.0 {
			cachedPct = 100.0
		}
	}

	blockedPct = math.Round(blockedPct*100) / 100
	cachedPct = math.Round(cachedPct*100) / 100
	avgLat = math.Round(avgLat*100) / 100
	qps := s.currentQPS.Load()

	resp := map[string]any{
		"total_queries":      total,
		"blocked_queries":    blocked,
		"cached_queries":     cached,
		"hosts_queries":      hosts,
		"arbitrary_queries":  arbitrary,
		"blocked_percentage": blockedPct,
		"cached_percentage":  cachedPct,
		"avg_latency_ms":     avgLat,
		"qps":                qps,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *StatsAPI) handleLogs(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	limitStr := q.Get("limit")
	offsetStr := q.Get("offset")
	search := q.Get("search")
	filter := q.Get("filter")

	limit := 50
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	if limit > 500 {
		limit = 500
	}
	offset := 0
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}

	total, items := s.ringBuffer.QueryLogs(limit, offset, search, filter)
	if items == nil {
		items = []LogEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"total": total,
		"items": items,
	})
}

func (s *StatsAPI) handleTop(w http.ResponseWriter, req *http.Request) {
	limitStr := req.URL.Query().Get("limit")
	limit := 10
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}

	topDomains, topClients, topBlocked := s.topStats.GetTop(limit)
	if topDomains == nil {
		topDomains = []TopItem{}
	}
	if topClients == nil {
		topClients = []TopItem{}
	}
	if topBlocked == nil {
		topBlocked = []TopItem{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"top_domains": topDomains,
		"top_clients": topClients,
		"top_blocked": topBlocked,
	})
}

func (s *StatsAPI) handleHistory(w http.ResponseWriter, req *http.Request) {
	pointsStr := req.URL.Query().Get("points")
	numPoints := 24
	if p, err := strconv.Atoi(pointsStr); err == nil && p > 0 {
		numPoints = p
	}
	if numPoints > 168 { // Max 7 days of hourly points
		numPoints = 168
	}

	points := s.historyStats.GetHistory(numPoints)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"points": points,
	})
}

func (s *StatsAPI) handleDump(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	if err := s.writeDump(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *StatsAPI) handleLoadDump(w http.ResponseWriter, req *http.Request) {
	if err := s.readDump(req.Body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.updatedCount.Add(1)
	w.WriteHeader(http.StatusOK)
}

func (s *StatsAPI) handleClearLogs(w http.ResponseWriter, req *http.Request) {
	s.ringBuffer.Clear()
	s.topStats.Clear()
	s.updatedCount.Add(1)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Logs cleared successfully",
	})
}

func (s *StatsAPI) handleClearCache(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Cache clear request processed",
	})
}

func (s *StatsAPI) writeDump(w io.Writer) error {
	gw, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return err
	}
	gw.Name = statsDumpHeader

	data := StatsDumpData{
		Version:          1,
		Timestamp:        time.Now().Unix(),
		TotalQueries:     s.totalQueries.Load(),
		BlockedQueries:   s.blockedQueries.Load(),
		CachedQueries:    s.cachedQueries.Load(),
		HostsQueries:     s.hostsQueries.Load(),
		ArbitraryQueries: s.arbitraryQueries.Load(),
		TotalLatencyUs:   s.totalLatencyUs.Load(),
	}

	data.TopDomains, data.TopClients, data.TopBlocked = s.topStats.Export()
	data.History = s.historyStats.Export()
	data.Logs, data.SeqID = s.ringBuffer.Export()

	if err := json.NewEncoder(gw).Encode(&data); err != nil {
		_ = gw.Close()
		return fmt.Errorf("failed to encode stats dump: %w", err)
	}

	return gw.Close()
}

func (s *StatsAPI) readDump(r io.Reader) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	if gr.Name != statsDumpHeader {
		return fmt.Errorf("invalid stats dump header: got %s, want %s", gr.Name, statsDumpHeader)
	}

	var data StatsDumpData
	if err := json.NewDecoder(gr).Decode(&data); err != nil {
		return fmt.Errorf("failed to decode stats dump: %w", err)
	}

	s.totalQueries.Store(data.TotalQueries)
	s.blockedQueries.Store(data.BlockedQueries)
	s.cachedQueries.Store(data.CachedQueries)
	s.hostsQueries.Store(data.HostsQueries)
	s.arbitraryQueries.Store(data.ArbitraryQueries)
	s.totalLatencyUs.Store(data.TotalLatencyUs)

	s.topStats.Import(data.TopDomains, data.TopClients, data.TopBlocked)
	s.historyStats.Import(data.History)
	s.ringBuffer.Import(data.Logs, data.SeqID)

	return nil
}

func (s *StatsAPI) loadDump() error {
	if len(s.args.DumpFile) == 0 {
		return nil
	}
	f, err := os.Open(s.args.DumpFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.logger.Info("stats dump file does not exist, starting with empty stats", zap.String("file", s.args.DumpFile))
			return nil
		}
		return err
	}
	defer f.Close()

	if err := s.readDump(f); err != nil {
		return err
	}
	s.logger.Info("stats dump loaded successfully", zap.String("file", s.args.DumpFile))
	return nil
}

func (s *StatsAPI) dumpStats() error {
	if len(s.args.DumpFile) == 0 {
		return nil
	}
	f, err := os.Create(s.args.DumpFile)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := s.writeDump(f); err != nil {
		return fmt.Errorf("failed to write stats dump, %w", err)
	}
	s.logger.Info("stats dumped successfully", zap.String("file", s.args.DumpFile))
	return nil
}

func (s *StatsAPI) startDumpLoop() {
	if len(s.args.DumpFile) == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Duration(s.args.DumpInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if s.updatedCount.Swap(0) > 0 {
					if err := s.dumpStats(); err != nil {
						s.logger.Error("failed to dump stats", zap.Error(err))
					}
				}
			case <-s.closeNotify:
				return
			}
		}
	}()
}

func (s *StatsAPI) startQPSLoop() {
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		const windowSize = 5
		history := make([]uint64, windowSize)
		timestamps := make([]int64, windowSize)
		lastTotal := s.totalQueries.Load()

		for {
			select {
			case now := <-ticker.C:
				curTotal := s.totalQueries.Load()
				var delta uint64
				if curTotal >= lastTotal {
					delta = curTotal - lastTotal
				}
				lastTotal = curTotal

				nowSec := now.Unix()
				idx := int(nowSec % windowSize)
				history[idx] = delta
				timestamps[idx] = nowSec

				var sum uint64
				validSecs := 0
				for i := 0; i < windowSize; i++ {
					if timestamps[i] > 0 && nowSec-timestamps[i] < windowSize {
						sum += history[i]
						validSecs++
					}
				}

				var qps uint64
				if validSecs > 0 {
					qps = (sum + uint64(validSecs)/2) / uint64(validSecs)
				}
				s.currentQPS.Store(qps)

			case <-s.closeNotify:
				return
			}
		}
	}()
}

func (s *StatsAPI) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	start := time.Now()
	err := next.ExecNext(ctx, qCtx)
	elapsed := time.Since(start)

	s.totalQueries.Add(1)
	s.totalLatencyUs.Add(uint64(elapsed.Microseconds()))
	s.updatedCount.Add(1)

	var clientIP string
	if clientAddr := qCtx.ServerMeta.ClientAddr; clientAddr.IsValid() {
		clientIP = clientAddr.String()
	}
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}

	qQuestion := qCtx.QQuestion()
	domain := qQuestion.Name
	qtypeStr := dns.TypeToString[qQuestion.Qtype]
	if qtypeStr == "" {
		qtypeStr = fmt.Sprintf("TYPE%d", qQuestion.Qtype)
	}

	isCached := qCtx.CacheState.Hit || qCtx.CacheState.LazyHit
	if isCached {
		s.cachedQueries.Add(1)
	}

	hasUpstream := isCached || qCtx.UpstreamSelected != nil

	r := qCtx.R()
	var status string
	var answers []AnswerDTO
	isBlocked := false

	if r == nil {
		status = "DROPPED"
		if !hasUpstream {
			isBlocked = true
		}
	} else {
		if rcodeStr, ok := dns.RcodeToString[r.Rcode]; ok {
			status = rcodeStr
		} else {
			status = fmt.Sprintf("RCODE%d", r.Rcode)
		}

		if !hasUpstream && (r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeRefused) && qQuestion.Qtype != dns.TypeHTTPS {
			isBlocked = true
		}

		for _, rr := range r.Answer {
			hdr := rr.Header()
			rrTypeStr := dns.TypeToString[hdr.Rrtype]
			if rrTypeStr == "" {
				rrTypeStr = fmt.Sprintf("TYPE%d", hdr.Rrtype)
			}
			var dataStr string
			switch record := rr.(type) {
			case *dns.A:
				dataStr = record.A.String()
				if dataStr == "0.0.0.0" || dataStr == "127.0.0.1" {
					isBlocked = true
				}
			case *dns.AAAA:
				dataStr = record.AAAA.String()
				if dataStr == "::" || dataStr == "::1" {
					isBlocked = true
				}
			case *dns.CNAME:
				dataStr = record.Target
			case *dns.TXT:
				dataStr = strings.Join(record.Txt, " ")
			case *dns.PTR:
				dataStr = record.Ptr
			case *dns.MX:
				dataStr = record.Mx
			default:
				dataStr = rr.String()
			}
			answers = append(answers, AnswerDTO{
				Type: rrTypeStr,
				Data: dataStr,
				TTL:  hdr.Ttl,
			})
		}
	}

	if isBlocked {
		s.blockedQueries.Add(1)
	}

	isHosts := qCtx.FromHosts && !isBlocked && !isCached && qCtx.UpstreamSelected == nil
	if isHosts {
		s.hostsQueries.Add(1)
	}

	isArbitrary := qCtx.FromArbitrary && !isBlocked && !isCached && qCtx.UpstreamSelected == nil
	if isArbitrary {
		s.arbitraryQueries.Add(1)
	}

	// Extract Upstream information
	var upstream string
	if isCached {
		upstream = "cache"
	} else if isHosts {
		upstream = "hosts"
	} else if isArbitrary {
		upstream = "arbitrary"
	} else if u := qCtx.UpstreamSelected; u != nil {
		if u.Addr != "" {
			if !strings.Contains(u.Addr, "://") {
				if u.Protocol == "DoH" {
					upstream = "https://" + u.Addr
				} else if u.Protocol == "DoT" {
					upstream = "tls://" + u.Addr
				} else if u.Protocol == "DoQ" {
					upstream = "quic://" + u.Addr
				} else {
					upstream = u.Addr
				}
			} else {
				upstream = u.Addr
			}
		} else if u.Tag != "" {
			upstream = u.Tag
		}
	}

	// Extract Rule information
	var rule string
	for i := len(qCtx.RuleHits) - 1; i >= 0; i-- {
		hit := qCtx.RuleHits[i]
		exec := strings.TrimSpace(hit.Exec)

		if exec == "accept" || exec == "return" || strings.HasPrefix(exec, "jump ") || strings.HasPrefix(exec, "ttl ") {
			continue
		}

		var positiveMatches []string
		for _, m := range hit.Matches {
			m = strings.TrimSpace(m)
			if m != "" && m != "has_resp" && !strings.HasPrefix(m, "!") {
				positiveMatches = append(positiveMatches, m)
			}
		}

		if len(positiveMatches) > 0 {
			rule = strings.Join(positiveMatches, ",")
			break
		}

		if exec != "" && exec != "$stats_collector" {
			rule = exec
			break
		}

		if hit.Sequence != "" && hit.Sequence != "has_resp_sequence" && hit.Sequence != "main_sequence" {
			rule = hit.Sequence
			break
		}
	}

	if rule == "" {
		if isCached {
			rule = "cache"
		} else if isHosts {
			rule = "hosts"
		} else if isArbitrary {
			rule = "arbitrary"
		} else {
			rule = "-"
		}
	}

	s.topStats.Record(domain, clientIP, isBlocked)
	s.historyStats.Record(start, isBlocked, isCached)

	elapsedMS := math.Round(float64(elapsed.Microseconds())/10.0) / 100.0

	entry := LogEntry{
		Timestamp: start.Format(time.RFC3339),
		ClientIP:  clientIP,
		Domain:    domain,
		QType:     qtypeStr,
		Status:    status,
		IsBlocked: isBlocked,
		IsCached:  isCached,
		ElapsedMS: elapsedMS,
		Upstream:  upstream,
		Rule:      rule,
		Answers:   answers,
	}

	s.ringBuffer.Push(entry)

	return err
}

func (s *StatsAPI) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeNotify)
		if err := s.dumpStats(); err != nil {
			s.logger.Error("failed to dump stats on close", zap.Error(err))
		}
		if s.httpServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.httpServer.Shutdown(ctx)
		}
	})
	return nil
}
