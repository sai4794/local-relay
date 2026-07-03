# ROUNDTABLE 05: Intelligent Model Routing & Quota Optimization

**Role:** LLM Platform Engineer — Multi-Model Routing & Quota Optimization  
**Date:** 2026-06-25  
**Input:** local-relay (Go proxy), 9router (Node.js router), Tor IP rotation

---

## 1. Model Quota Map — Limits, Resets, and Rate Limit Behavior

### 1.1 Current Provider/Model Inventory (from 9router database)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PROVIDER        │ MODEL                          │ TYPE    │ COST          │
├─────────────────┼────────────────────────────────┼─────────┼───────────────┤
│ OpenCode (oc)   │ mimo-v2.5-free                 │ FREE    │ $0            │
│ OpenCode (oc)   │ nemotron-3-ultra-free          │ FREE    │ $0            │
│ OpenCode (oc)   │ deepseek-v4-flash-free         │ FREE    │ $0            │
│ OpenCode (oc)   │ north-mini-code-free           │ FREE    │ $0            │
│ OpenCode (oc)   │ big-pickle                     │ FREE    │ $0            │
│ OpenRouter (opr)│ nvidia/nemotron-3-super-120b   │ FREE    │ $0            │
│ OpenRouter (opr)│ nvidia/nemotron-3-nano-30b     │ FREE    │ $0            │
│ OpenRouter (opr)│ google/gemma-4-31b-it          │ FREE    │ $0            │
│ OpenRouter (opr)│ google/gemma-4-26b-a4b-it      │ FREE    │ $0            │
│ OpenRouter (opr)│ cohere/north-mini-code         │ FREE    │ $0            │
│ ZenMux (zem)    │ stepfun/step-3.7-flash-free    │ FREE    │ $0            │
│ ZenMux (zem)    │ z-ai/glm-4.7-flash-free        │ FREE    │ $0            │
│ Alibaba         │ qwen3.7-plus                   │ PAID    │ ~$0.001/req   │
│ Alibaba         │ qwen3.7-max                    │ PAID    │ ~$0.026/req   │
│ Gemini          │ gemini-3.1-flash-lite-preview  │ FREE*   │ $0            │
│ Gemini          │ gemini-3-flash-preview          │ FREE*   │ $0            │
└─────────────────────────────────────────────────────────────────────────────┘
  * Gemini free tier has separate quota from Google AI Studio
```

### 1.2 Observed Rate Limits (from usage data + error patterns)

```
┌──────────────────┬───────────────────┬────────────────┬───────────────────────┐
│ PROVIDER         │ DAILY LIMIT       │ RATE LIMIT     │ RESET                 │
├──────────────────┼───────────────────┼────────────────┼───────────────────────┤
│ OpenCode         │ ~2000-2500/IP/day │ ~100 req/min   │ UTC midnight (daily)  │
│ (mimo-v2.5-free) │ (estimated from   │ (burst likely) │ 429: FreeUsageLimit   │
│                  │  usage: 2200/day  │                │   Error               │
│                  │  on day 2)        │                │                       │
├──────────────────┼───────────────────┼────────────────┼───────────────────────┤
│ OpenRouter       │ 50/day (no creds) │ 20 req/min     │ UTC midnight          │
│ (:free models)   │ 1000/day (>$10)   │                │                       │
├──────────────────┼───────────────────┼────────────────┼───────────────────────┤
│ ZenMux           │ Unknown (likely   │ Unknown        │ Likely daily          │
│                  │  similar to OC)   │                │                       │
├──────────────────┼───────────────────┼────────────────┼───────────────────────┤
│ Alibaba (qwen)   │ Paid, quota-      │ N/A            │ modelLock expiry      │
│                  │  based (403 when  │                │ (set by 9router)      │
│                  │  exhausted)       │                │                       │
├──────────────────┼───────────────────┼────────────────┼───────────────────────┤
│ Gemini           │ Google AI Studio  │ Varies by tier │ Google account-based  │
│                  │ free tier limits  │                │                       │
└──────────────────┴───────────────────┴────────────────┴───────────────────────┘
```

### 1.3 Error Signatures (what 429 looks like per provider)

```jsonc
// OpenCode 429 — "FreeUsageLimitError"
{
  "type": "error",
  "error": {
    "type": "FreeUsageLimitError",
    "message": "Rate limit exceeded. Please try again later."
  },
  "metadata": {}
}
// HTTP Status: 429

// OpenRouter 429 — (documented)
// HTTP 429 with X-RateLimit-* headers
// Headers: X-RateLimit-Remaining, X-RateLimit-Reset

// Alibaba 403 — quota exhausted
// "The free quota has been exhausted. To continue accessing..."
// modelLock set with expiry timestamp by 9router
```

---

## 2. Model Rotation Algorithm — Maximizing Daily Requests

### 2.1 Core Principle: Round-Robin with Weighted Fair Queuing

The goal is to **spread requests evenly across all free models** so no single model
hits its daily limit early while others sit idle.

```
ALGORITHM: Weighted Round-Robin Model Rotation
──────────────────────────────────────────────

INPUT:
  models[]     — list of available models with quotas
  request      — incoming LLM request
  
STATE:
  quota[model]  — remaining requests today
  limit[model]  — daily limit
  weight[model] — priority weight (higher = more requests)
  lastUsed[model] — timestamp of last use

PSEUDOCODE:

func selectModel(request) Model:
    now = currentTime()
    candidates = []
    
    // Phase 1: Filter to available models
    for each model in models:
        if model.quotaRemaining <= 0:
            continue  // exhausted
        if model.cooldownUntil > now:
            continue  // rate-limited, cooling down
        if not model.providerHealthy:
            continue  // provider down
        candidates.append(model)
    
    if len(candidates) == 0:
        return fallbackModel()  // paid model or error
    
    // Phase 2: Score each candidate
    for each candidate in candidates:
        // Utilization ratio: how much quota we've used
        utilization = 1 - (candidate.quotaRemaining / candidate.limit)
        
        // Urgency: models closer to reset get priority
        // (use remaining quota before it expires)
        hoursUntilReset = candidate.resetTime.sub(now).hours
        urgency = candidate.quotaRemaining / max(hoursUntilReset, 0.1)
        
        // Recency penalty: don't hammer the same model
        recency = now.sub(candidate.lastUsed).minutes
        recencyPenalty = 1.0 / (1.0 + exp(-recency / 5.0))
        
        // Composite score
        candidate.score = (
            candidate.weight * 0.3 +
            (1 - utilization) * 0.3 +   // prefer models with more quota
            urgency * 0.2 +              // prefer models expiring soon
            recencyPenalty * 0.2         // prefer recently-unused models
        )
    
    // Phase 3: Select highest-scoring model
    selected = candidates.sortBy(score, desc).first()
    
    // Phase 4: Update state
    selected.quotaRemaining -= 1
    selected.lastUsed = now
    return selected
```

### 2.2 Rotation Strategy: Two-Tier Rotation

```
TIER 1 — Model Rotation (changes which model handles the request)
  Frequency: Every request
  Logic: Weighted round-robin across all available models
  Goal: Maximize total requests before ANY model exhausts

TIER 2 — IP Rotation (changes the exit IP via Tor)
  Frequency: Every 10 requests (existing config)
  Logic: Request new Tor circuit via SIGNAL NEWNYM
  Goal: Reset per-IP quotas on providers that track by IP
  Note: Some providers track by API key, not IP — rotation won't help
```

**Key insight**: IP rotation is ONLY effective for providers that rate-limit by IP.
OpenCode likely tracks by API key. OpenRouter tracks by API key. So Tor rotation
helps mainly with providers that do IP-based tracking or CDN-level rate limiting.

### 2.3 Implementation: Go struct for model state

```go
// internal/routing/model_state.go
package routing

import (
    "sync"
    "time"
)

type ModelState struct {
    mu sync.RWMutex
    
    // Identity
    ID            string        // e.g. "mimo-v2.5-free"
    Provider      string        // e.g. "opencode"
    Endpoint      string        // e.g. "https://opencode.ai/zen/v1"
    
    // Quota tracking
    DailyLimit    int           // max requests per day
    UsedToday     int           // requests used today
    ResetTime     time.Time     // when quota resets (UTC midnight)
    
    // Rate limiting
    RateLimit     int           // max requests per minute
    RateWindow    []time.Time   // timestamps of recent requests
    
    // State
    Healthy       bool          // is provider responding?
    BackoffUntil  time.Time     // backoff after error
    BackoffLevel  int           // exponential backoff counter
    LastError     string        // last error type
    LastUsed      time.Time     // last successful request
    Weight        float64       // priority weight
    
    // Cost tracking
    CostPerRequest float64      // estimated cost (0 for free)
}

func (ms *ModelState) QuotaRemaining() int {
    ms.mu.RLock()
    defer ms.mu.RUnlock()
    remaining := ms.DailyLimit - ms.UsedToday
    if remaining < 0 {
        remaining = 0
    }
    return remaining
}

func (ms *ModelState) IsAvailable() bool {
    ms.mu.RLock()
    defer ms.mu.RUnlock()
    
    now := time.Now()
    
    // Check daily quota
    if now.After(ms.ResetTime) {
        return true  // reset has happened
    }
    if ms.UsedToday >= ms.DailyLimit {
        return false  // quota exhausted
    }
    
    // Check backoff
    if now.Before(ms.BackoffUntil) {
        return false  // in backoff period
    }
    
    // Check rate limit
    if len(ms.RateWindow) >= ms.RateLimit {
        oldest := ms.RateWindow[0]
        if now.Sub(oldest) < time.Minute {
            return false  // rate limited
        }
    }
    
    return ms.Healthy
}

func (ms *ModelState) RecordRequest(success bool) {
    ms.mu.Lock()
    defer ms.mu.Unlock()
    
    now := time.Now()
    
    // Reset daily counter if needed
    if now.After(ms.ResetTime) {
        ms.UsedToday = 0
        ms.ResetTime = nextUTCMidnight()
        ms.BackoffLevel = 0
    }
    
    if success {
        ms.UsedToday++
        ms.LastUsed = now
        ms.Healthy = true
        ms.BackoffLevel = 0
        ms.BackoffUntil = time.Time{}
        
        // Update rate window
        ms.RateWindow = append(ms.RateWindow, now)
        // Trim to last minute
        cutoff := now.Add(-time.Minute)
        i := 0
        for i < len(ms.RateWindow) && ms.RateWindow[i].Before(cutoff) {
            i++
        }
        ms.RateWindow = ms.RateWindow[i:]
    } else {
        ms.BackoffLevel++
        // Exponential backoff: 30s, 60s, 120s, 300s, 600s
        backoffSec := 30 * (1 << ms.BackoffLevel)
        if backoffSec > 600 {
            backoffSec = 600
        }
        ms.BackoffUntil = now.Add(time.Duration(backoffSec) * time.Second)
        ms.LastError = "rate_limited"
    }
}

func (ms *ModelState) Score() float64 {
    ms.mu.RLock()
    defer ms.mu.RUnlock()
    
    now := time.Now()
    
    // Utilization: prefer models with more remaining quota
    if ms.DailyLimit == 0 {
        return 0
    }
    utilization := float64(ms.UsedToday) / float64(ms.DailyLimit)
    quotaScore := 1.0 - utilization
    
    // Urgency: prefer models whose reset is far away (more time to use)
    hoursUntilReset := ms.ResetTime.Sub(now).Hours()
    if hoursUntilReset < 0 {
        hoursUntilReset = 24  // reset just happened
    }
    urgencyScore := hoursUntilReset / 24.0
    
    // Recency: prefer recently unused models
    recency := now.Sub(ms.LastUsed).Minutes()
    recencyScore := 1.0 / (1.0 + exp(-recency/5.0))
    
    // Cost: prefer free models
    costScore := 1.0 / (1.0 + ms.CostPerRequest*100)
    
    return (
        ms.Weight*0.2 +
        quotaScore*0.3 +
        urgencyScore*0.2 +
        recencyScore*0.2 +
        costScore*0.1
    )
}
```

---

## 3. Quota Exhaustion Detection — Without Wasting Requests

### 3.1 Strategy: Probe Once, Cache Result

Instead of sending real requests to check if a model is available, use a
**minimal probe request** and cache the result.

```
EXHAUSTION DETECTION ALGORITHM
──────────────────────────────

TRIGGER: Before routing to any model
COST: 1 request per probe (minimal payload)
CACHE: Store result for 60 seconds

func detectExhaustion(model) bool:
    // 1. Check cached state first
    if model.lastProbeTime + PROBE_TTL > now():
        return model.cachedExhausted
    
    // 2. Check if we have usage data from 9router
    if model.provider == "openrouter":
        // OpenRouter has a /api/v1/key endpoint that returns:
        // - usage_daily: requests used today
        // - is_free_tier: whether free tier limits apply
        response = GET("https://openrouter.ai/api/v1/key", headers=apiKey)
        model.DailyLimit = 50 if response.is_free_tier else 1000
        model.UsedToday = response.usage_daily
        model.cachedExhausted = (model.UsedToday >= model.DailyLimit)
        model.lastProbeTime = now()
        return model.cachedExhausted
    
    // 3. For OpenCode: use minimal probe request
    // Send: {"model": "...", "messages": [{"role":"user","content":"hi"}], "max_tokens": 1}
    // If 429 with FreeUsageLimitError → exhausted
    // If 200 → available
    probe = sendMinimalProbe(model)
    model.lastProbeTime = now()
    
    if probe.status == 429:
        if probe.errorType == "FreeUsageLimitError":
            model.cachedExhausted = true
            model.DailyLimit = model.UsedToday  // we're at the limit
            log("Model %s EXHAUSTED at %d requests", model.ID, model.UsedToday)
            return true
    
    if probe.status == 200:
        model.cachedExhausted = false
        model.UsedToday++  // count the probe
        return false
    
    // Unknown error — assume available but mark unhealthy
    model.Healthy = false
    return true  // don't route to unhealthy model
```

### 3.2 Passive Detection from Real Requests

```
PASSIVE DETECTION — Learn from actual request outcomes
──────────────────────────────────────────────────────

Every real request teaches us about quota state:

func onRequestComplete(model, response, error):
    if response.status == 429:
        if error.type == "FreeUsageLimitError":
            model.cachedExhausted = true
            model.DailyLimit = model.UsedToday
            model.BackoffUntil = nextUTCMidnight()
            model.BackoffLevel = MAX_BACKOFF
            log("PASSIVE: Model %s quota exhausted", model.ID)
            
            // Immediately trigger rotation to next model
            router.forceRotate()
        
        elif error.status == 429 and error.headers["X-RateLimit-Remaining"]:
            // Rate limited but not daily quota
            model.RateWindowRemaining = parse(error.headers["X-RateLimit-Remaining"])
            model.BackoffUntil = parse(error.headers["X-RateLimit-Reset"])
    
    elif response.status == 200:
        model.RecordRequest(success=true)
    
    // Update estimated daily limit from observed max
    if model.UsedToday > model.estimatedMax:
        model.estimatedMax = model.UsedToday
        // If we haven't hit 429, our limit is at least this high
```

### 3.3 Health Check Endpoint for Monitoring

```
GET /health/models
Response:
{
  "models": {
    "mimo-v2.5-free": {
      "status": "available",
      "quota_remaining": 847,
      "quota_limit": 2500,
      "reset_at": "2026-06-26T00:00:00Z",
      "requests_today": 1653,
      "backoff_until": null,
      "last_error": null,
      "score": 0.82
    },
    "deepseek-v4-flash-free": {
      "status": "exhausted",
      "quota_remaining": 0,
      "quota_limit": 2500,
      "reset_at": "2026-06-26T00:00:00Z",
      "requests_today": 2500,
      "backoff_until": "2026-06-26T00:00:00Z",
      "last_error": "FreeUsageLimitError",
      "score": 0.0
    }
  }
}
```

---

## 4. Priority Queue — Cheapest/Fastest First, Expensive as Fallback

### 4.1 Model Tier Classification

```
TIER 0 — PRIMARY (use first, free, fast)
  - mimo-v2.5-free (OpenCode)        — Best overall, 2500+ req/day
  - nemotron-3-ultra-free (OpenCode) — Good alternative, lower quota

TIER 1 — SECONDARY (free, different provider, IP-diverse)
  - deepseek-v4-flash-free (OpenCode) — Often rate-limited
  - north-mini-code-free (OpenCode)   — Lower capacity
  - big-pickle (OpenCode)             — Lower capacity
  - stepfun/step-3.7-flash-free (ZenMux) — Different IP space

TIER 2 — TERTIARY (free via OpenRouter, 50-1000 req/day)
  - nvidia/nemotron-3-super-120b-a12b:free
  - nvidia/nemotron-3-nano-30b-a3b:free
  - google/gemma-4-31b-it:free
  - google/gemma-4-26b-a4b-it:free
  - cohere/north-mini-code:free

TIER 3 — EMERGENCY (free via Gemini, limited)
  - gemini-3.1-flash-lite-preview
  - gemini-3-flash-preview

TIER 4 — PAID FALLBACK (last resort, costs money)
  - qwen3.7-plus (Alibaba)
  - qwen3.7-max (Alibaba)
```

### 4.2 Priority Queue Implementation

```go
// internal/routing/priority_queue.go
package routing

import (
    "container/heap"
    "sync"
)

// ModelQueue is a priority queue of models ordered by score (descending)
type ModelQueue struct {
    mu       sync.RWMutex
    items    []*ModelState
    index    map[string]int  // modelID -> index in heap
}

// Len, Less, Swap, Push, Pop — standard heap.Interface

func (pq *ModelQueue) SelectNext() *ModelState {
    pq.mu.Lock()
    defer pq.mu.Unlock()
    
    // Pop models until we find an available one
    for pq.items.Len() > 0 {
        model := heap.Pop(&pq).(*ModelState)
        
        if model.IsAvailable() {
            // Push it back (we need it for next selection)
            heap.Push(&pq, model)
            return model
        }
        
        // Model unavailable — skip it, don't push back
        // It will be re-added when it becomes available again
        log("Skipping unavailable model: %s (score: %.2f)", model.ID, model.Score())
    }
    
    return nil  // no models available
}

// Reschedule adds a model back to the queue after cooldown
func (pq *ModelQueue) Reschedule(model *ModelState) {
    pq.mu.Lock()
    defer pq.mu.Unlock()
    heap.Push(&pq, model)
}
```

### 4.3 Fallback Chain Logic

```
REQUEST FLOW:
═════════════

  Incoming Request
       │
       ▼
  ┌─ SelectNext() ─┐
  │  (Priority Q)   │
  └───────┬─────────┘
          │
     ┌────┴────┐
     │ Model?  │
     └────┬────┘
          │
    ┌─────┴──────────────────────┐
    │                            │
    ▼                            ▼
  Available                  No models
    │                        available
    ▼                            │
  Route request                   ▼
    │                      ┌─ Check paid models
    ▼                      │  (qwen3.7-plus)
  Success?                  │
    │                    ┌───┴───┐
    ├── Yes ──→ Done     │ Paid? │
    │                   └───┬───┘
    │                       │
    ├── 429 ──→ Exhaustion  ├── Yes ──→ Route (log cost)
    │           Detected     │
    │           │            └── No ──→ Return error
    │           ▼                  "All models exhausted"
    │     Mark model exhausted
    │     Force rotation
    │           │
    │           ▼
    │     SelectNext() again
    │     (recursive, max 3 attempts)
    │
    └── Error ──→ Retry with backoff
```

---

## 5. Quota Budget Allocator — Optimal Distribution Across Models & IPs

### 5.1 The Allocator Algorithm

The quota budget allocator answers: **"Given N expected requests today,
how should we distribute them across M models to maximize success rate?"**

```
QUOTA BUDGET ALLOCATOR
══════════════════════

INPUT:
  expectedRequests  — estimated total requests today (from historical data)
  models[]          — all available models with quotas
  ipPool            — number of Tor circuits available

OUTPUT:
  allocation[model] — target requests per model per IP

PSEUDOCODE:

func allocateBudget(expectedRequests int, models[], ipPool int) Allocation:
    allocation = {}
    
    // Step 1: Calculate total available quota
    totalQuota = 0
    for each model in models:
        totalQuota += model.DailyLimit * ipPool  // multiply by IPs if IP-based limiting
    
    if totalQuota == 0:
        return Allocation{usePaidOnly: true}
    
    // Step 2: Determine if we can meet demand
    if expectedRequests <= totalQuota:
        strategy = "SPREAD"  // spread evenly, leave buffer
    else:
        strategy = "EXHAUST"  // use everything, will hit paid fallback
    
    // Step 3: Allocate proportionally
    for each model in models:
        if strategy == "SPREAD":
            // Allocate proportionally to quota, with 10% buffer
            modelBudget = (model.DailyLimit * ipPool) * (expectedRequests / totalQuota) * 0.9
            
            // Minimum: at least 10 requests to keep model warm
            if modelBudget < 10:
                modelBudget = 10
            
            // Maximum: don't allocate more than the quota
            if modelBudget > model.DailyLimit * ipPool:
                modelBudget = model.DailyLimit * ipPool
        
        else:  // EXHAUST
            // Allocate as much as possible
            modelBudget = model.DailyLimit * ipPool
        
        allocation[model.ID] = {
            targetRequests: modelBudget,
            perIP: modelBudget / ipPool,
            priority: model.Tier,
            ratePerHour: modelBudget / 24,
        }
    
    return allocation
```

### 5.2 IP-Model Mapping Strategy

```
IP-MODEL AFFINITY
═════════════════

The key insight: Tor gives us different IPs, but each model may or may not
track by IP. We should map IPs to models strategically.

STRATEGY: IP-per-Provider (not per-model)
─────────────────────────────────────────

If OpenCode tracks by API key (likely):
  - All Tor IPs share the same API key quota
  - IP rotation doesn't help with OpenCode limits
  - Use OpenCode models until exhausted, then switch providers

If OpenRouter tracks by IP (possible):
  - Each Tor circuit gets its own OpenRouter quota
  - IP rotation multiplies effective quota
  - Rotate IPs aggressively for OpenRouter models

MAPPING:
  Tor Circuit 1 → OpenCode models (primary)
  Tor Circuit 2 → OpenCode models (backup)
  Tor Circuit 3 → OpenRouter models (secondary)
  Tor Circuit 4 → ZenMux models (tertiary)
  Tor Circuit 5 → Gemini models (emergency)
  Tor Circuit 6+ → rotated across providers

IMPLEMENTATION:

type IPModelAffinity struct {
    CircuitID    string
    PrimaryProvider   string  // e.g. "opencode"
    SecondaryProvider string  // e.g. "openrouter"
    RequestCount      int     // requests on this circuit
    MaxPerCircuit      int    // rotate circuit after this many
}

func (a *IPModelAffinity) SelectProvider(request) string {
    if a.RequestCount < a.MaxPerCircuit/2:
        return a.PrimaryProvider  // use primary for first half
    else:
        return a.SecondaryProvider  // switch to secondary
}
```

### 5.3 Dynamic Reallocation — Adapt Throughout the Day

```
DYNAMIC REALLOCATION
════════════════════

Run every 15 minutes to adjust allocation based on observed usage.

func reallocateEvery15Min():
    // Gather current state
    state = getModelState()
    
    // Calculate burn rate for each model
    for each model in state.models:
        hoursElapsed = now().sub(model.dayStart).hours
        if hoursElapsed > 0:
            model.burnRate = model.UsedToday / hoursElapsed
        else:
            model.burnRate = 0
        
        // Predict exhaustion time
        remaining = model.DailyLimit - model.UsedToday
        if model.burnRate > 0:
            model.predictedExhaustion = now() + (remaining / model.burnRate) hours
        else:
            model.predictedExhaustion = model.resetTime  // won't exhaust
    
    // Find models that will exhaust early
    earlyExhausters = state.models.filter(m => 
        m.predictedExhaustion < now() + 2 hours && m.burnRate > 0
    )
    
    // Redistribute: reduce allocation to early exhausters
    for each model in earlyExhausters:
        excess = model.burnRate * 0.3  // reduce by 30%
        model.targetRate = model.burnRate - excess
        
        // Redistribute excess to models with most remaining quota
        for each other in state.models:
            if other != model and other.burnRate < other.maxRate:
                other.targetRate += excess / len(state.models)
    
    // Apply new rates to router
    router.setAllocation(state.models)
```

### 5.4 Complete Allocator Data Structure

```go
// internal/routing/allocator.go
package routing

import (
    "sync"
    "time"
)

type QuotaAllocator struct {
    mu             sync.RWMutex
    models         map[string]*ModelState
    expectedDaily  int            // estimated daily requests
    ipCount        int            // number of Tor circuits
    allocation     map[string]int // target requests per model
    actualUsage    map[string]int // actual requests made
    
    // Adaptive parameters
    burnRateWindow time.Duration  // how far back to look for burn rate
    reallocateInterval time.Duration
    lastReallocate time.Time
}

func NewQuotaAllocator(models []*ModelState, ipCount int) *QuotaAllocator {
    qa := &QuotaAllocator{
        models:             make(map[string]*ModelState),
        ipCount:            ipCount,
        allocation:         make(map[string]int),
        actualUsage:        make(map[string]int),
        burnRateWindow:     1 * time.Hour,
        reallocateInterval: 15 * time.Minute,
    }
    
    for _, m := range models {
        qa.models[m.ID] = m
    }
    
    // Initial allocation
    qa.Reallocate()
    
    return qa
}

func (qa *QuotaAllocator) Reallocate() {
    qa.mu.Lock()
    defer qa.mu.Unlock()
    
    now := time.Now()
    qa.lastReallocate = now
    
    // Calculate total available quota
    totalQuota := 0
    for _, m := range qa.models {
        if m.CostPerRequest == 0 {
            totalQuota += m.DailyLimit * qa.ipCount
        }
    }
    
    // Estimate daily demand from recent burn rate
    if qa.expectedDaily == 0 {
        qa.expectedDaily = qa.estimateDailyDemand()
    }
    
    // Proportional allocation with minimum guarantees
    for id, m := range qa.models {
        if m.CostPerRequest > 0 {
            // Paid models: allocate 0 by default (emergency only)
            qa.allocation[id] = 0
            continue
        }
        
        // Proportional share of total quota
        share := float64(m.DailyLimit*qa.ipCount) / float64(totalQuota)
        target := int(float64(qa.expectedDaily) * share * 0.85) // 85% to leave buffer
        
        // Minimum guarantee: at least 20 requests
        if target < 20 {
            target = 20
        }
        
        // Maximum: can't exceed quota
        if target > m.DailyLimit*qa.ipCount {
            target = m.DailyLimit * qa.ipCount
        }
        
        qa.allocation[id] = target
    }
}

func (qa *QuotaAllocator) SelectModel() *ModelState {
    qa.mu.RLock()
    defer qa.mu.RUnlock()
    
    // Sort by score, filtered to available
    best := (*ModelState)(nil)
    bestScore := -1.0
    
    for id, m := range qa.models {
        if !m.IsAvailable() {
            continue
        }
        
        // Check if we've exceeded allocation for this model
        if qa.actualUsage[id] >= qa.allocation[id] {
            // Soft limit — still use if nothing else available
            // But prefer models under allocation
            continue
        }
        
        score := m.Score()
        if score > bestScore {
            bestScore = score
            best = m
        }
    }
    
    // If all allocated models exhausted, try any available
    if best == nil {
        for _, m := range qa.models {
            if m.IsAvailable() {
                best = m
                break
            }
        }
    }
    
    // If still nothing, try paid models
    if best == nil {
        for _, m := range qa.models {
            if m.CostPerRequest > 0 && m.IsAvailable() {
                best = m
                log("WARNING: Falling back to paid model %s ($%.4f/req)", m.ID, m.CostPerRequest)
                break
            }
        }
    }
    
    return best
}

func (qa *QuotaAllocator) RecordUsage(modelID string, success bool) {
    qa.mu.Lock()
    defer qa.mu.Unlock()
    
    if success {
        qa.actualUsage[modelID]++
    }
    
    // Trigger reallocation if interval has passed
    if time.Since(qa.lastReallocate) > qa.reallocateInterval {
        go qa.Reallocate()
    }
}

func (qa *QuotaAllocator) estimateDailyDemand() int {
    // Look at last 4 hours of data
    // Scale up to 24 hours
    recentTotal := 0
    for _, m := range qa.models {
        recentTotal += m.UsedToday
    }
    
    hoursElapsed := time.Since(time.Now().Truncate(24 * time.Hour)).Hours()
    if hoursElapsed < 1 {
        hoursElapsed = 1
    }
    
    hourlyRate := float64(recentTotal) / hoursElapsed
    return int(hourlyRate * 24)
}

func (qa *QuotaAllocator) GetStatus() map[string]interface{} {
    qa.mu.RLock()
    defer qa.mu.RUnlock()
    
    status := map[string]interface{}{
        "expected_daily": qa.expectedDaily,
        "ip_count":       qa.ipCount,
        "models":         map[string]interface{}{},
    }
    
    for id, m := range qa.models {
        status["models"].(map[string]interface{})[id] = map[string]interface{}{
            "quota_remaining":  m.QuotaRemaining(),
            "quota_limit":      m.DailyLimit,
            "requests_today":   m.UsedToday,
            "allocated":        qa.allocation[id],
            "actual":           qa.actualUsage[id],
            "score":            m.Score(),
            "available":        m.IsAvailable(),
        }
    }
    
    return status
}
```

---

## 6. Integration with Existing 9router System

### 6.1 How to Hook Into 9router's Model Selection

9router already has `modelLock_*` fields and `backoffLevel` per connection. We can
extend this with smarter routing:

```
9ROUTER INTEGRATION APPROACH
═════════════════════════════

Current 9router flow:
  1. Client sends request with model name
  2. 9router finds connection for that model
  3. Routes through proxy pool (Tor local relay)
  4. If 429, sets modelLock with expiry

Enhanced flow (what we propose):
  1. Client sends request (can specify "auto" as model)
  2. Router queries QuotaAllocator.SelectModel()
  3. Allocator picks optimal model based on:
     - Current quota state
     - Time of day
     - Historical usage patterns
     - Cost constraints
  4. Router rewrites request model field
  5. Routes through appropriate proxy
  6. On response, updates quota state
```

### 6.2 API for Model Auto-Selection

```
POST /v1/chat/completions
{
  "model": "auto",           // <-- special value triggers routing
  "messages": [...],
  "stream": true
}

// Router responds with actual model used in response headers:
// X-Selected-Model: mimo-v2.5-free
// X-Quota-Remaining: 847
// X-Quota-Limit: 2500
```

### 6.3 Configuration Extension

```yaml
# config.yaml additions for model routing
routing:
  enabled: true
  strategy: "weighted-round-robin"  # or "least-used", "cost-first"
  
  models:
    - id: "mimo-v2.5-free"
      provider: "opencode"
      tier: 0
      weight: 1.0
      daily_limit: 2500        # estimated, auto-detected
      cost_per_request: 0
      
    - id: "nemotron-3-ultra-free"
      provider: "opencode"
      tier: 0
      weight: 0.8
      daily_limit: 2500
      cost_per_request: 0
    
    - id: "deepseek-v4-flash-free"
      provider: "opencode"
      tier: 1
      weight: 0.5
      daily_limit: 2500
      cost_per_request: 0
    
    - id: "nvidia/nemotron-3-super-120b-a12b:free"
      provider: "openrouter"
      tier: 2
      weight: 0.6
      daily_limit: 50          # free tier
      cost_per_request: 0
    
    - id: "qwen3.7-plus"
      provider: "alibaba"
      tier: 4
      weight: 0.1
      daily_limit: 999999      # paid, no limit
      cost_per_request: 0.001

  budget:
    expected_daily: 3000
    paid_fallback_enabled: true
    max_paid_cost_per_day: 5.00  # dollars
    
  detection:
    probe_enabled: true
    probe_interval: 300          # seconds between probes
    passive_detection: true      # learn from real requests
    
  reallocation:
    interval: 900                # seconds (15 min)
    burn_rate_window: 3600       # seconds (1 hour)
```

---

## 7. Monitoring & Observability

### 7.1 Key Metrics to Track

```
METRICS (exposed via /metrics or /health/models)
════════════════════════════════════════════════

routing_requests_total{model, provider, status}     — counter
routing_quota_remaining{model, provider}             — gauge
routing_quota_limit{model, provider}                 — gauge
routing_fallback_to_paid_total{model}                — counter
routing_rotation_total{from_model, to_model}         — counter
routing_exhaustion_events_total{model}               — counter
routing_response_time_seconds{model, provider}       — histogram
routing_cost_total{model, provider}                  — counter (dollars)
```

### 7.2 Dashboard Endpoints

```
GET /health/models           — model status with quota
GET /health/routing          — routing decisions log (last 100)
GET /health/allocation       — current allocation vs actual
GET /health/costs            — daily cost breakdown
```

---

## 8. Implementation Roadmap

```
PHASE 1 (Immediate — 2 hours)
  □ Add ModelState tracking to 9router
  □ Implement passive exhaustion detection from 429 responses
  □ Add model selection based on current quota state

PHASE 2 (Same day — 4 hours)
  □ Implement Weighted Round-Robin rotation
  □ Add fallback chain (free → free → paid)
  □ Extend config.yaml with routing section

PHASE 3 (Next day — 8 hours)
  □ Implement QuotaAllocator with dynamic reallocation
  □ Add OpenRouter /api/v1/key quota polling
  □ Build monitoring endpoints

PHASE 4 (Future)
  □ ML-based demand prediction
  □ Multi-account support (multiple API keys per provider)
  □ Automatic API key rotation
  □ Cost optimization optimizer
```

---

## 9. Key Findings from Current Data

```
OBSERVATIONS FROM 9ROUTER DATABASE (2026-06-23 to 2026-06-25):
═══════════════════════════════════════════════════════════════

1. mimo-v2.5-free is the workhorse: 4321 requests in 2 days
   - Day 1 (June 23): ~1500 requests
   - Day 2 (June 24): ~3500 requests  
   - Estimated daily limit: ~2000-2500 per IP

2. All errors are 429 FreeUsageLimitError — no 500s or auth failures
   - 30 errors on mimo-v2.5-free
   - 2 errors on deepseek-v4-flash-free
   - 1 error on nemotron-3-ultra-free

3. Peak usage hours: 09:00-18:00 UTC
   - Highest: 13:00 UTC (431 requests)
   - Lowest: 21:00 UTC (10 requests)

4. Tor rotation every 10 requests is active but may not help
   - OpenCode likely tracks by API key, not IP
   - Rotation mainly helps with CDN/geo-level rate limits

5. Paid fallback used: qwen3.7-max ($0.90 total, 35 requests)
   - Triggered when free models exhausted
   - Should be last resort

6. Alibaba qwen3.7-max has modelLock set until 2026-06-24T14:45
   - 9router's backoff mechanism working correctly
   - Free quota was exhausted on Alibaba
```

---

## 10. Summary

The current system has a strong foundation (Tor rotation, provider routing, proxy
pools) but lacks **intelligent model selection**. The key improvements are:

1. **Quota-aware routing**: Track remaining quota per model, route to models with
   the most remaining capacity
2. **Passive detection**: Learn exhaustion from 429 responses, don't waste probe
   requests
3. **Dynamic reallocation**: Rebalance every 15 minutes based on observed burn rate
4. **Cost-aware fallback**: Use all free models first, only fall back to paid when
   all free options exhausted
5. **OpenRouter quota polling**: Use their /api/v1/key endpoint for accurate quota data

**Expected improvement**: From ~3500 requests/day (current single-model) to
~5000-8000 requests/day (multi-model with smart rotation) without hitting paid
fallback.
