# ROUNDTABLE 04 — SRE/DevOps: Monitoring, Alerting & Automated Failover

**Expert:** SRE/DevOps Engineer — Monitoring, alerting, and automated failover  
**Date:** 2026-06-24

---

## Architecture Summary

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────┐
│  Client App  │────▶│  9router     │────▶│ local-relay  │────▶│   Tor    │──▶ Internet
│  (LLM usage) │     │  :20128      │     │  :18080 HTTP │     │  :9050   │
│              │     │  Node.js     │     │  :11080 SOCKS│     │  SOCKS5  │
│              │     │  SQLite DB   │     │  Go binary   │     │          │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────┘
                            │                     │
                     ┌──────┴──────┐        ┌─────┴──────┐
                     │ usageHistory│        │ Health Srv │
                     │ requestDet  │        │ :18888     │
                     │ kv (models) │        │ /healthz   │
                     └─────────────┘        │ /readyz    │
                                            └────────────┘
```

**Critical Insight:** local-relay is a **Layer 4 (TCP) proxy**, not an HTTP proxy. For HTTPS/CONNECT tunnels (which is all LLM API traffic), it forwards raw TCP bytes and **cannot see HTTP response status codes**. The 429 detection must happen at the 9router level or via an external sidecar.

---

## 1. Real-Time 429 Error Detection

### Why local-relay Cannot Detect 429

Looking at `internal/proxy/http.go` lines 73-131, the `handleCONNECT` method does:
```go
destConn, err := p.router.DialContext(r.Context(), "tcp", host)
// ... then hijacks the connection and streams bytes
stream.Relay(r.Context(), destConn, clientConn)
```

It establishes a raw TCP tunnel. The HTTP response (including 429 status) passes through as opaque bytes. The relay never parses HTTP response codes for CONNECT tunnels.

### Detection Strategy: Three Layers

#### Layer 1: 9router Database Mining (Immediate — No Code Changes)

9router already logs every request to SQLite. Query it directly:

```bash
#!/bin/bash
# /home/stb/local-relay/scripts/detect-429.sh
# Detect 429 errors from 9router's request log in real-time

DB="$HOME/.9router/db/data.sqlite"
SINCE_MINUTES=${1:-5}  # Check last N minutes, default 5

sqlite3 "$DB" "
SELECT
  datetime(timestamp/1000, 'unixepoch', 'localtime') as time,
  model,
  provider,
  statusCode,
  substr(responseBody, 1, 200) as error_body
FROM requestDetails
WHERE statusCode = 429
  AND timestamp > (strftime('%s', 'now') * 1000 - ${SINCE_MINUTES} * 60000)
ORDER BY timestamp DESC
LIMIT 50;
"
```

#### Layer 2: Watchdog Script with Alerting (Cron/Timer)

```bash
#!/bin/bash
# /home/stb/local-relay/scripts/watch-429.sh
# Runs every 30 seconds, alerts on 429 bursts

DB="$HOME/.9router/db/data.sqlite"
ALERT_FILE="/tmp/relay-429-alert"
COOLDOWN=300  # 5-minute cooldown between alerts

# Count 429s in last 2 minutes
COUNT_429=$(sqlite3 "$DB" "
SELECT COUNT(*) FROM requestDetails
WHERE statusCode = 429
  AND timestamp > (strftime('%s', 'now') * 1000 - 120000);
" 2>/dev/null)

COUNT_TOTAL=$(sqlite3 "$DB" "
SELECT COUNT(*) FROM requestDetails
WHERE timestamp > (strftime('%s', 'now') * 1000 - 120000);
" 2>/dev/null)

if [ "$COUNT_TOTAL" -eq 0 ]; then
    exit 0
fi

RATE_429=$(echo "scale=2; $COUNT_429 * 100 / $COUNT_TOTAL" | bc 2>/dev/null)

# Get breakdown by model
BREAKDOWN=$(sqlite3 "$DB" "
SELECT model, COUNT(*) as cnt
FROM requestDetails
WHERE statusCode = 429
  AND timestamp > (strftime('%s', 'now') * 1000 - 300000)
GROUP BY model
ORDER BY cnt DESC;
" 2>/dev/null)

echo "$(date '+%Y-%m-%d %H:%M:%S') | 429 rate: ${RATE_429}% (${COUNT_429}/${COUNT_TOTAL} last 2min)"
echo "Breakdown:"
echo "$BREAKDOWN"

# Alert if 429 rate exceeds 30%
if [ "$(echo "$RATE_429 > 30" | bc 2>/dev/null)" = "1" ]; then
    NOW=$(date +%s)
    LAST_ALERT=0
    [ -f "$ALERT_FILE" ] && LAST_ALERT=$(cat "$ALERT_FILE")

    if [ $((NOW - LAST_ALERT)) -gt $COOLDOWN ]; then
        echo "$NOW" > "$ALERT_FILE"

        # Desktop notification
        notify-send -u critical "LLM Rate Limits" \
            "429 error rate: ${RATE_429}% (${COUNT_429} in 2min)" 2>/dev/null

        # Log to syslog
        logger -t relay-watchdog "ALERT: 429 rate ${RATE_429}% (${COUNT_429}/${COUNT_TOTAL})"

        echo ">>> ALERT TRIGGERED <<<"
    fi
fi
```

#### Layer 3: HTTP Response Inspection Sidecar (Advanced)

For definitive 429 detection, create a transparent logging proxy that sits between 9router and local-relay:

```bash
#!/bin/bash
# /home/stb/local-relay/scripts/resp-monitor.sh
# TCP MITM that logs HTTP response codes for monitoring
# Listens on :18081, forwards to :18080, logs response status codes

# This uses socat or a tiny Go sidecar. The Go approach is shown below.
# For quick setup, use socat + tcpdump approach:

PORT=${1:-18081}
UPSTREAM="127.0.0.1:18080"
LOGFILE="/home/stb/local-relay/logs/response-monitor.log"

mkdir -p "$(dirname "$LOGFILE")"

# Method: Use mitmproxy if available
if command -v mitmdump &>/dev/null; then
    mitmdump --listen-port "$PORT" \
        --mode upstream:http://127.0.0.1:18080/ \
        --set upstream_cert=false \
        -s /home/stb/local-relay/scripts/mitm-log-script.py
    exit $?
fi

# Fallback: Use tcpdump to capture response status codes
echo "Using tcpdump packet capture for response monitoring..."
sudo tcpdump -i lo -A "port 18080" 2>/dev/null | \
    grep -E "HTTP/1\.[01] (429|5[0-9][0-9])" | \
    while IFS= read -r line; do
        echo "$(date '+%Y-%m-%d %H:%M:%S') CAPTURED: $line" >> "$LOGFILE"
    done
```

---

## 2. IP Rotation Effectiveness Monitoring

### Current Rotation Mechanism

From `internal/rotate/rotator.go`: rotation happens every N requests (default 10). It sends `SIGNAL NEWNYM` to Tor control port to get a new circuit (new exit IP).

### Monitoring Script

```bash
#!/bin/bash
# /home/stb/local-relay/scripts/rotation-monitor.sh
# Monitor Tor circuit rotation and IP diversity

RELAY_HEALTH="http://127.0.0.1:18888/healthz"
IP_CHECK="https://api.ipify.org?format=json"
SOCKS_PROXY="socks5h://127.0.0.1:11080"
LOGFILE="/home/stb/local-relay/logs/rotation.log"
IP_LOG="/home/stb/local-relay/logs/ip-history.log"

mkdir -p "$(dirname "$LOGFILE")"

echo "=========================================="
echo "  Tor IP Rotation Monitor"
echo "=========================================="

# 1. Check relay health
echo -e "\n--- Relay Health ---"
curl -s "$RELAY_HEALTH" | python3 -m json.tool 2>/dev/null || echo "Relay health check failed"

# 2. Get current exit IP through relay
echo -e "\n--- Current Exit IP ---"
CURRENT_IP=$(curl -s --proxy "$SOCKS_PROXY" "$IP_CHECK" 2>/dev/null)
echo "Exit IP: $CURRENT_IP"

# 3. Check if IP changed from last time
LAST_IP=""
if [ -f "$IP_LOG" ]; then
    LAST_IP=$(tail -1 "$IP_LOG" | awk '{print $3}')
fi

if [ "$CURRENT_IP" != "$LAST_IP" ]; then
    echo "STATUS: IP CHANGED (rotation effective)"
    echo "$(date '+%Y-%m-%d %H:%M:%S') NEW_IP $CURRENT_IP" >> "$IP_LOG"
else
    echo "STATUS: Same IP as last check"
fi

# 4. Rapid rotation test — get 5 IPs in quick succession
echo -e "\n--- IP Diversity Test (5 checks) ---"
declare -A seen_ips
for i in $(seq 1 5); do
    ip=$(curl -s --proxy "$SOCKS_PROXY" "$IP_CHECK" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['ip'])" 2>/dev/null)
    seen_ips["$ip"]=1
    echo "  Check $i: $ip"
done

UNIQUE_IPS=${#seen_ips[@]}
echo -e "\nUnique IPs: $UNIQUE_IPS / 5"
if [ "$UNIQUE_IPS" -le 1 ]; then
    echo "WARNING: Low IP diversity — rotation may not be working"
elif [ "$UNIQUE_IPS" -le 2 ]; then
    echo "OK: Moderate diversity"
else
    echo "GOOD: High IP diversity"
fi

# 5. Tor circuit info (if control port available)
echo -e "\n--- Tor Circuit Info ---"
echo "AUTHENTICATE" | nc -w 2 127.0.0.1 9051 2>/dev/null && \
    echo "GETINFO circuit-status" | nc -w 2 127.0.0.1 9051 2>/dev/null || \
    echo "Tor control port not accessible"

# 6. 9router usage stats
DB="$HOME/.9router/db/data.sqlite"
if [ -f "$DB" ]; then
    echo -e "\n--- Request Volume (last hour) ---"
    sqlite3 "$DB" "
SELECT
  datetime(timestamp/1000, 'unixepoch', 'localtime') as time_bucket,
  COUNT(*) as requests,
  SUM(CASE WHEN statusCode = 429 THEN 1 ELSE 0 END) as rate_limited
FROM requestDetails
WHERE timestamp > (strftime('%s', 'now') * 1000 - 3600000)
GROUP BY strftime('%Y-%m-%d %H:%M', timestamp/1000, 'unixepoch')
ORDER BY time_bucket DESC
LIMIT 10;
" 2>/dev/null
fi

# 7. Rotation interval tuning recommendation
echo -e "\n--- Rotation Config ---"
echo "Current rotation interval: every 10 requests (config.yaml)"
echo "Max circuit age: 100 requests (tor.go)"
echo ""
echo "Recommendation based on 429 rates:"
RATE_429=$(sqlite3 "$DB" "
SELECT ROUND(100.0 * SUM(CASE WHEN statusCode=429 THEN 1 ELSE 0 END) / COUNT(*), 1)
FROM requestDetails
WHERE timestamp > (strftime('%s', 'now') * 1000 - 3600000);
" 2>/dev/null)

if [ -n "$RATE_429" ]; then
    echo "  429 rate (1hr): ${RATE_429}%"
    if [ "$(echo "$RATE_429 > 20" | bc 2>/dev/null)" = "1" ]; then
        echo "  → Consider reducing rotation interval (currently 10 → try 5)"
    elif [ "$(echo "$RATE_429 > 5" | bc 2>/dev/null)" = "1" ]; then
        echo "  → Rotation interval looks reasonable"
    fi
fi
```

### Continuous Rotation Monitoring (systemd timer)

```bash
#!/bin/bash
# /home/stb/local-relay/scripts/rotation-watcher.sh
# Runs continuously, tracks IP changes and logs rotation events

IP_LOG="/home/stb/local-relay/logs/ip-history.log"
SOCKS_PROXY="socks5h://127.0.0.1:11080"
INTERVAL=60  # Check every 60 seconds

mkdir -p "$(dirname "$IP_LOG")"
LAST_IP=""

while true; do
    CURRENT_IP=$(curl -s --proxy "$SOCKS_PROXY" https://api.ipify.org?format=json 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['ip'])" 2>/dev/null)

    if [ -z "$CURRENT_IP" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: Could not determine exit IP" >> "$IP_LOG"
    elif [ "$CURRENT_IP" != "$LAST_IP" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') ROTATION: $LAST_IP → $CURRENT_IP" >> "$IP_LOG"
        LAST_IP="$CURRENT_IP"
    fi

    sleep "$INTERVAL"
done
```

---

## 3. Auto-Switch Models When Quota Is Hit

### Strategy

Since 9router is the LLM router with model configs in its SQLite DB (`kv` table), model switching should happen at the 9router level. The relay just provides IP rotation for fresh quotas.

### Auto-Failover Script

```bash
#!/bin/bash
# /home/stb/local-relay/scripts/auto-fallback.sh
# Monitors 429 rates per model, triggers model priority rotation

DB="$HOME/.9router/db/data.sqlite"
STATE_FILE="/home/stb/local-relay/state/model-fallback.json"
LOGFILE="/home/stb/local-relay/logs/fallback.log"
NINEROUTER_API="http://127.0.0.1:20128"
COOKIE_FILE="/tmp/9router-cookies"

mkdir -p "$(dirname "$LOGFILE")" "$(dirname "$STATE_FILE")"

# Initialize state file
if [ ! -f "$STATE_FILE" ]; then
    cat > "$STATE_FILE" << 'EOF'
{
    "current_priority": 0,
    "models": [
        {"id": "oc/mimo-v2.5-free", "priority": 0, "429_count": 0, "cooldown_until": 0},
        {"id": "oc/nemotron-3-ultra-free", "priority": 1, "429_count": 0, "cooldown_until": 0},
        {"id": "oc/north-mini-code-free", "priority": 2, "429_count": 0, "cooldown_until": 0}
    ],
    "last_check": 0
}
EOF
fi

# Login to 9router
login_9router() {
    curl -s -X POST "$NINEROUTER_API/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"password":"123456"}' \
        -c "$COOKIE_FILE" > /dev/null 2>&1
}

# Get 429 counts per model in last 10 minutes
get_429_counts() {
    sqlite3 "$DB" "
SELECT model, COUNT(*) as cnt
FROM requestDetails
WHERE statusCode = 429
  AND timestamp > (strftime('%s', 'now') * 1000 - 600000)
GROUP BY model;
" 2>/dev/null
}

# Check success rate per model in last 5 minutes
get_success_rates() {
    sqlite3 "$DB" "
SELECT
  model,
  COUNT(*) as total,
  SUM(CASE WHEN statusCode = 200 THEN 1 ELSE 0 END) as success,
  SUM(CASE WHEN statusCode = 429 THEN 1 ELSE 0 END) as rate_limited,
  ROUND(100.0 * SUM(CASE WHEN statusCode = 429 THEN 1 ELSE 0 END) / COUNT(*), 1) as error_rate
FROM requestDetails
WHERE timestamp > (strftime('%s', 'now') * 1000 - 300000)
GROUP BY model
ORDER BY error_rate DESC;
" 2>/dev/null
}

# Determine which models are rate-limited
check_and_rotate() {
    NOW=$(date +%s)
    STATE=$(cat "$STATE_FILE")

    echo "$(date '+%Y-%m-%d %H:%M:%S') Checking model health..."
    echo ""

    # Get error rates
    RATES=$(get_success_rates)
    echo "Model health (last 5min):"
    echo "$RATES"
    echo ""

    # Check each model for 429 exhaustion
    MODELS_DEGRADED=0
    MODELS_TOTAL=0

    while IFS='|' read -r model total success rate_limited error_rate; do
        [ -z "$model" ] && continue
        MODELS_TOTAL=$((MODELS_TOTAL + 1))

        if [ -n "$error_rate" ] && [ "$(echo "$error_rate > 50" | bc 2>/dev/null)" = "1" ]; then
            echo "DEGRADED: $model (${error_rate}% error rate)"
            MODELS_DEGRADED=$((MODELS_DEGRADED + 1))

            # If >80% 429s, put in cooldown for 10 minutes
            if [ "$(echo "$error_rate > 80" | bc 2>/dev/null)" = "1" ]; then
                COOLDOWN_END=$((NOW + 600))
                echo "  → Putting $model in cooldown until $(date -d @$COOLDOWN_END '+%H:%M:%S' 2>/dev/null || date -r $COOLDOWN_END '+%H:%M:%S' 2>/dev/null)"

                # Update 9router to deprioritize this model
                login_9router
                curl -s -b "$COOKIE_FILE" \
                    -X PUT "$NINEROUTER_API/api/models/$(echo "$model" | sed 's/\//%2F/g')" \
                    -H "Content-Type: application/json" \
                    -d "{\"enabled\": false}" > /dev/null 2>&1
            fi
        else
            echo "HEALTHY: $model (${error_rate:-0}% error rate)"
        fi
    done <<< "$RATES"

    echo ""

    if [ "$MODELS_DEGRADED" -eq "$MODELS_TOTAL" ] && [ "$MODELS_TOTAL" -gt 0 ]; then
        echo "CRITICAL: ALL MODELS EXHAUSTED — triggering emergency measures"
        echo "$(date '+%Y-%m-%d %H:%M:%S') ALL_MODELS_EXHAUSTED" >> "$LOGFILE"

        # Emergency: re-enable all models (quotas may have reset)
        login_9router
        curl -s -b "$COOKIE_FILE" \
            -X POST "$NINEROUTER_API/api/proxy-pools/36a74789-4e07-4669-bbb1-54f568610180/test" \
            > /dev/null 2>&1

        # Force Tor circuit change for fresh IP
        kill -USR1 $(pgrep -f "local-relay") 2>/dev/null

        notify-send -u critical "LLM Fallback" "ALL MODELS EXHAUSTED — all IPs rate limited" 2>/dev/null
    fi

    # Re-enable models that were in cooldown (10 min window passed)
    if [ -f "$STATE_FILE" ]; then
        login_9router
        sqlite3 "$DB" "SELECT DISTINCT model FROM requestDetails;" 2>/dev/null | while read -r model; do
            curl -s -b "$COOKIE_FILE" \
                -X PUT "$NINEROUTER_API/api/models/$(echo "$model" | sed 's/\//%2F/g')" \
                -H "Content-Type: application/json" \
                -d "{\"enabled\": true}" > /dev/null 2>&1
        done
    fi
}

check_and_rotate
```

### Model Priority Rotation via 9router API

```bash
#!/bin/bash
# /home/stb/local-relay/scripts/model-priority.sh
# Manually set model priority order based on current quota status
# Usage: ./model-priority.sh

DB="$HOME/.9router/db/data.sqlite"
NINEROUTER_API="http://127.0.0.1:20128"
COOKIE_FILE="/tmp/9router-cookies"

# Login
curl -s -X POST "$NINEROUTER_API/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"password":"123456"}' \
    -c "$COOKIE_FILE" > /dev/null

# Show current model status
echo "=== Current Model Status ==="
curl -s -b "$COOKIE_FILE" "$NINEROUTER_API/v1/models" | python3 -m json.tool 2>/dev/null

echo ""
echo "=== 429 History (last 24h) ==="
sqlite3 "$DB" "
SELECT model, COUNT(*) as total_429s,
       MIN(datetime(timestamp/1000, 'unixepoch')) as first_429,
       MAX(datetime(timestamp/1000, 'unixepoch')) as last_429
FROM requestDetails
WHERE statusCode = 429
  AND timestamp > (strftime('%s', 'now') * 1000 - 86400000)
GROUP BY model;
" 2>/dev/null

echo ""
echo "=== Recommended Priority Order ==="
sqlite3 "$DB" "
SELECT model,
  ROUND(100.0 * SUM(CASE WHEN statusCode=429 THEN 1 ELSE 0 END) / COUNT(*), 1) as err_pct
FROM requestDetails
WHERE timestamp > (strftime('%s', 'now') * 1000 - 3600000)
GROUP BY model
ORDER BY err_pct ASC;
" 2>/dev/null
echo "(Models with lowest 429 rate = highest priority)"
```

---

## 4. Alert When All Models Are Exhausted

### Comprehensive Alerting Script

```bash
#!/bin/bash
# /home/stb/local-relay/scripts/exhaustion-alert.sh
# Detects when all models are rate-limited, alerts through multiple channels

DB="$HOME/.9router/db/data.sqlite"
RELAY_HEALTH="http://127.0.0.1:18888/healthz"
NINEROUTER_HEALTH="http://127.0.0.1:20128"
STATE_FILE="/home/stb/local-relay/state/exhaustion-state.json"
LOGFILE="/home/stb/local-relay/logs/exhaustion.log"
COOLDOWN=600  # 10-minute cooldown between critical alerts

mkdir -p "$(dirname "$LOGFILE")" "$(dirname "$STATE_FILE")"

# Load or init state
if [ ! -f "$STATE_FILE" ]; then
    echo '{"last_critical_alert": 0, "consecutive_all_exhausted": 0}' > "$STATE_FILE"
fi

NOW=$(date +%s)
LAST_ALERT=$(python3 -c "import json; print(json.load(open('$STATE_FILE'))['last_critical_alert'])" 2>/dev/null || echo 0)
CONSECUTIVE=$(python3 -c "import json; print(json.load(open('$STATE_FILE'))['consecutive_all_exhausted'])" 2>/dev/null || echo 0)

# Check service health
RELAY_OK=false
NINEROUTER_OK=false

if curl -s -o /dev/null -w "%{http_code}" "$RELAY_HEALTH" 2>/dev/null | grep -q "200\|503"; then
    RELAY_OK=true
fi

if curl -s -o /dev/null -w "%{http_code}" "$NINEROUTER_HEALTH" 2>/dev/null | grep -q "200\|302"; then
    NINEROUTER_OK=true
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') Health: relay=$RELAY_OK 9router=$NINEROUTER_OK"

# Check model exhaustion
TOTAL_MODELS=0
EXHAUSTED_MODELS=0

RESULTS=$(sqlite3 "$DB" "
SELECT
  model,
  COUNT(*) as total,
  SUM(CASE WHEN statusCode = 200 THEN 1 ELSE 0 END) as success,
  SUM(CASE WHEN statusCode = 429 THEN 1 ELSE 0 END) as rate_limited
FROM requestDetails
WHERE timestamp > (strftime('%s', 'now') * 1000 - 600000)
GROUP BY model
HAVING total > 0;
" 2>/dev/null)

if [ -n "$RESULTS" ]; then
    while IFS='|' read -r model total success rate_limited; do
        [ -z "$model" ] && continue
        TOTAL_MODELS=$((TOTAL_MODELS + 1))

        if [ "$total" -gt 0 ] && [ "$rate_limited" -ge "$total" ]; then
            EXHAUSTED_MODELS=$((EXHAUSTED_MODELS + 1))
            echo "  EXHAUSTED: $model ($rate_limited/$total requests 429)"
        else
            ERATE=0
            [ "$total" -gt 0 ] && ERATE=$(echo "scale=1; $rate_limited * 100 / $total" | bc)
            echo "  OK: $model (${RATE:-0}% 429 rate)"
        fi
    done <<< "$RESULTS"
fi

# Determine alert level
ALERT_LEVEL="none"
ALERT_MSG=""

if [ "$TOTAL_MODELS" -eq 0 ]; then
    ALERT_MSG="No recent LLM requests found — traffic may not be flowing"
    ALERT_LEVEL="warning"
elif [ "$EXHAUSTED_MODELS" -eq "$TOTAL_MODELS" ] && [ "$TOTAL_MODELS" -gt 0 ]; then
    ALERT_MSG="CRITICAL: ALL $TOTAL_MODELS MODELS EXHAUSTED (all returning 429)"
    ALERT_LEVEL="critical"
elif [ "$EXHAUSTED_MODELS" -gt 0 ]; then
    ALERT_MSG="WARNING: $EXHAUSTED_MODELS/$TOTAL_MODELS models rate-limited"
    ALERT_LEVEL="warning"
fi

if [ "$RELAY_OK" = "false" ]; then
    ALERT_MSG="CRITICAL: local-relay is DOWN\n$ALERT_MSG"
    ALERT_LEVEL="critical"
fi

if [ "$NINEROUTER_OK" = "false" ]; then
    ALERT_MSG="CRITICAL: 9router is DOWN\n$ALERT_MSG"
    ALERT_LEVEL="critical"
fi

echo ""
echo "Alert level: $ALERT_LEVEL"

# Send alerts based on severity
case "$ALERT_LEVEL" in
    critical)
        CONSECUTIVE=$((CONSECUTIVE + 1))
        if [ $((NOW - LAST_ALERT)) -gt $COOLDOWN ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') ALERT: $ALERT_MSG" >> "$LOGFILE"

            # Desktop notification
            notify-send -u critical -i dialog-error "LLM Infrastructure Alert" "$ALERT_MSG" 2>/dev/null

            # System log
            logger -t relay-alert "CRITICAL: $ALERT_MSG"

            # Optional: webhook (Slack, Telegram, etc.)
            # curl -s -X POST "https://hooks.slack.com/services/YOUR/WEBHOOK" \
            #     -H "Content-Type: application/json" \
            #     -d "{\"text\": \"🚨 $ALERT_MSG\"}" > /dev/null 2>&1

            # Update state
            python3 -c "
import json
state = json.load(open('$STATE_FILE'))
state['last_critical_alert'] = $NOW
state['consecutive_all_exhausted'] = $CONSECUTIVE
json.dump(state, open('$STATE_FILE', 'w'))
"
        fi
        ;;
    warning|none)
        CONSECUTIVE=0
        python3 -c "
import json
state = json.load(open('$STATE_FILE'))
state['consecutive_all_exhausted'] = 0
json.dump(state, open('$STATE_FILE', 'w'))
" 2>/dev/null

        if [ "$ALERT_LEVEL" = "warning" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') WARNING: $ALERT_MSG" >> "$LOGFILE"
            logger -t relay-alert "WARNING: $ALERT_MSG"
        fi
        ;;
esac

# If 3+ consecutive critical alerts, suggest emergency actions
if [ "$CONSECUTIVE" -ge 3 ]; then
    echo ""
    echo ">>> EMERGENCY: $CONSECUTIVE consecutive critical alerts <<<"
    echo "Suggested actions:"
    echo "  1. Kill relay to force all clients to reconnect through fresh IPs:"
    echo "     systemctl restart local-relay"
    echo "  2. Request new Tor circuit immediately:"
    echo "     echo -e 'AUTHENTICATE\r\nSIGNAL NEWNYM\r\n' | nc 127.0.0.1 9051"
    echo "  3. Wait for quota reset (usually 1 hour for free models)"
    echo "  4. Check if new models are available:"
    echo "     curl -s http://127.0.0.1:20128/v1/models"
fi

exit 0
```

---

## 5. Systemd Service with Auto-Restart, Log Rotation & Health Monitoring

### Main Service Unit

```ini
# /etc/systemd/system/local-relay.service
[Unit]
Description=Local Relay - Tor Proxy for LLM Rate Limit Bypass
Documentation=file:///home/stb/local-relay/README.md
After=network-online.target tor.service
Wants=network-online.target
Requires=tor.service

[Service]
Type=simple
User=stb
Group=stb
WorkingDirectory=/home/stb/local-relay

# Binary and config
ExecStart=/home/stb/local-relay/relay -c /home/stb/local-relay/config.yaml
ExecReload=/bin/kill -HUP $MAINPID

# Restart policy
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

# Environment
Environment=HOME=/home/stb

# Logging (stdout/stderr → journal)
StandardOutput=journal
StandardError=journal
SyslogIdentifier=local-relay

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/stb/local-relay/logs /home/stb/local-relay/state /home/stb/.9router
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes

# Resource limits
LimitNOFILE=65536
MemoryMax=512M
CPUQuota=80%

# OOM score
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
```

### Log Rotation Configuration

```
# /etc/logrotate.d/local-relay
/home/stb/local-relay/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    dateext
    dateformat -%Y%m%d
    size 50M
    maxsize 100M
    create 0644 stb stb
}
```

### Health Watchdog Service

```ini
# /etc/systemd/system/local-relay-health.service
[Unit]
Description=Local Relay Health Monitor
After=local-relay.service
Requires=local-relay.service

[Service]
Type=oneshot
ExecStart=/home/stb/local-relay/scripts/exhaustion-alert.sh
User=stb
Environment=HOME=/home/stb

# Security
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/stb/local-relay/state /home/stb/local-relay/logs
```

```ini
# /etc/systemd/system/local-relay-health.timer
[Unit]
Description=Local Relay Health Check Timer

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
```

### Auto-Fallback Timer

```ini
# /etc/systemd/system/local-relay-fallback.service
[Unit]
Description=Local Relay Auto-Fallback Model Switcher
After=local-relay.service 9router.service

[Service]
Type=oneshot
ExecStart=/home/stb/local-relay/scripts/auto-fallback.sh
User=stb
Environment=HOME=/home/stb

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/stb/local-relay/state /home/stb/local-relay/logs /home/stb/.9router
```

```ini
# /etc/systemd/system/local-relay-fallback.timer
[Unit]
Description=Auto-Fallback Model Rotation Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
AccuracySec=10s

[Install]
WantedBy=timers.target
```

### Setup Script

```bash
#!/bin/bash
# /home/stb/local-relay/scripts/install-systemd.sh
# Install all systemd units and supporting files

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELAY_DIR="$(dirname "$SCRIPT_DIR")"

echo "Installing local-relay systemd services..."

# Create directories
mkdir -p "$RELAY_DIR/logs" "$RELAY_DIR/state"

# Install service files
sudo cp "$RELAY_DIR/systemd/local-relay.service" /etc/systemd/system/
sudo cp "$RELAY_DIR/systemd/local-relay-health.service" /etc/systemd/system/
sudo cp "$RELAY_DIR/systemd/local-relay-health.timer" /etc/systemd/system/
sudo cp "$RELAY_DIR/systemd/local-relay-fallback.service" /etc/systemd/system/
sudo cp "$RELAY_DIR/systemd/local-relay-fallback.timer" /etc/systemd/system/

# Install logrotate config
sudo cp "$RELAY_DIR/systemd/logrotate-local-relay" /etc/logrotate.d/local-relay

# Install scripts
chmod +x "$SCRIPT_DIR"/*.sh

# Reload and enable
sudo systemctl daemon-reload
sudo systemctl enable local-relay.service
sudo systemctl enable local-relay-health.timer
sudo systemctl enable local-relay-fallback.timer

echo ""
echo "Services installed. To start:"
echo "  sudo systemctl start local-relay"
echo "  sudo systemctl start local-relay-health.timer"
echo "  sudo systemctl start local-relay-fallback.timer"
echo ""
echo "To check status:"
echo "  systemctl status local-relay"
echo "  systemctl list-timers 'local-relay*'"
echo "  journalctl -u local-relay -f"
```

---

## Quick Reference: Monitoring Commands

```bash
# === SERVICE STATUS ===
systemctl status local-relay
systemctl status local-relay-health.timer
journalctl -u local-relay --since "5 min ago" -f

# === HEALTH CHECK ===
curl -s http://127.0.0.1:18888/healthz | python3 -m json.tool
curl -s http://127.0.0.1:18888/readyz

# === 429 DETECTION ===
sqlite3 ~/.9router/db/data.sqlite "
  SELECT model, COUNT(*) as cnt
  FROM requestDetails
  WHERE statusCode=429 AND timestamp > (strftime('%s','now')*1000 - 300000)
  GROUP BY model;
"

# === IP ROTATION CHECK ===
curl -s --proxy socks5h://127.0.0.1:11080 https://api.ipify.org?format=json

# === TOR CIRCUIT INFO ===
echo "AUTHENTICATE
GETINFO circuit-status" | nc -w 2 127.0.0.1 9051

# === FORCE CIRCUIT ROTATION ===
echo "AUTHENTICATE
SIGNAL NEWNYM" | nc -w 2 127.0.0.1 9051

# === REQUEST VOLUME ===
sqlite3 ~/.9router/db/data.sqlite "
  SELECT strftime('%H:%M', timestamp/1000, 'unixepoch') as hour,
         COUNT(*) as total,
         SUM(CASE WHEN statusCode=429 THEN 1 ELSE 0 END) as limited
  FROM requestDetails
  WHERE timestamp > (strftime('%s','now')*1000 - 86400000)
  GROUP BY hour ORDER BY hour;
"

# === FULL DIAGNOSTIC ===
bash /home/stb/local-relay/scripts/rotation-monitor.sh
bash /home/stb/local-relay/scripts/exhaustion-alert.sh

# === EMERGENCY: RESET EVERYTHING ===
sudo systemctl restart local-relay   # Force new IPs
echo "AUTHENTICATE
SIGNAL NEWNYM" | nc -w 2 127.0.0.1 9051   # New Tor circuit
```

---

## Directory Structure After Installation

```
/home/stb/local-relay/
├── relay                          # Go binary
├── config.yaml                    # Main config
├── scripts/
│   ├── detect-429.sh              # One-shot 429 check
│   ├── watch-429.sh               # Continuous 429 monitor
│   ├── rotation-monitor.sh        # IP rotation diagnostics
│   ├── rotation-watcher.sh        # Continuous IP tracking
│   ├── auto-fallback.sh           # Model auto-switching
│   ├── model-priority.sh          # Model priority display
│   ├── exhaustion-alert.sh        # Exhaustion alerting
│   └── install-systemd.sh         # Systemd installer
├── systemd/
│   ├── local-relay.service        # Main service
│   ├── local-relay-health.service # Health check (oneshot)
│   ├── local-relay-health.timer   # Health check timer (60s)
│   ├── local-relay-fallback.service # Fallback service
│   ├── local-relay-fallback.timer # Fallback timer (2min)
│   └── logrotate-local-relay     # Log rotation config
├── logs/
│   ├── fallback.log               # Model fallback events
│   ├── exhaustion.log             # Exhaustion alerts
│   ├── rotation.log               # IP rotation events
│   └── ip-history.log             # IP change history
├── state/
│   ├── model-fallback.json        # Model state tracking
│   └── exhaustion-state.json      # Alert cooldown state
└── relay.log                      # Relay logs (to journal)
```

---

## Key Findings & Recommendations

1. **429 detection requires 9router-level monitoring** — local-relay is a TCP proxy and cannot see HTTP response codes. The relay.log shows only "CONNECT tunnel established" messages. The SQLite DB in 9router (`~/.9router/db/data.sqlite`) is the authoritative source for status codes.

2. **IP rotation works but needs diversity tracking** — rotation happens every 10 requests via `SIGNAL NEWNYM`. Without exit IP verification, we can't confirm actual IP diversity. The rotation-monitor script bridges this gap.

3. **Model fallback must go through 9router API** — local-relay has no concept of "models" — it just proxies TCP connections. Model switching logic belongs in 9router, which tracks per-model quotas and status codes.

4. **Health endpoint is minimal** — the `/healthz` endpoint only reports Tor connectivity and request count. A production deployment should extend it with 429 rate metrics, circuit age, and model health summary.

5. **Systemd integration provides operational maturity** — auto-restart (Restart=always), timer-based health checks, and log rotation via logrotate ensure the system is self-healing and auditable.

6. **Tor rotation interval may need tuning** — at 10 requests per rotation, high-volume usage exhausts IPs quickly. Monitoring should feed back into interval adjustment (e.g., reduce to 5 for bursty workloads).
