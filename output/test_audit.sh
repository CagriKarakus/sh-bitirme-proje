#!/usr/bin/env bash
###############################################################################
#
# CIS Benchmark Audit & Remediation Script
#
# Generated on    : 2025-12-06 23:58:47
# Source registry : Rules\index.json
# Rule count      : 3
#
# This script performs:
#   1. Initial audit of all selected rules (BEFORE)
#   2. Remediation for failed rules
#   3. Final audit of all rules (AFTER)
#   4. Generates HTML report with before/after comparison
#
###############################################################################

# Exit on undefined variables only, continue on errors
set -u

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Results storage
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
REPORT_DIR="${REPORT_DIR:-/tmp/cis_report_$TIMESTAMP}"
mkdir -p "$REPORT_DIR"

# Arrays to store results
declare -A BEFORE_RESULTS
declare -A AFTER_RESULTS
declare -A BEFORE_OUTPUT
declare -A AFTER_OUTPUT

TOTAL_RULES=3
RULES_LIST=("3.3.1" "3.3.2" "3.3.3")

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  CIS Benchmark Audit & Remediation Tool${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "Report directory: $REPORT_DIR"
echo "Total rules to check: $TOTAL_RULES"
echo ""

###############################################################################
# PHASE 1: INITIAL AUDIT (BEFORE)
###############################################################################
echo -e "${YELLOW}=== PHASE 1: Initial Audit (BEFORE) ===${NC}"
echo ""



# Audit function for rule 3.3.1
audit_3_3_1() {
    local output
    local exit_code
    
    output=$(
        # CIS 3.3.1 Ensure IP forwarding is disabled

        echo "Checking IP forwarding status..."

        FAIL=0

        # Check IPv4 forwarding
        IPV4_FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
        if [ "$IPV4_FWD" = "0" ]; then
            echo "PASS: net.ipv4.ip_forward = 0"
        else
            echo "FAIL: net.ipv4.ip_forward = $IPV4_FWD (should be 0)"
            FAIL=1
        fi

        # Check IPv6 forwarding (if IPv6 is enabled)
        IPV6_FWD=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)
        if [ -n "$IPV6_FWD" ]; then
            if [ "$IPV6_FWD" = "0" ]; then
                echo "PASS: net.ipv6.conf.all.forwarding = 0"
            else
                echo "FAIL: net.ipv6.conf.all.forwarding = $IPV6_FWD (should be 0)"
                FAIL=1
            fi
        else
            echo "INFO: IPv6 not available, skipping IPv6 forwarding check"
        fi

        # Check persistent configuration
        if grep -rqs "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/; then
            echo "WARNING: IP forwarding may be enabled at boot via sysctl configuration"
        fi

        if [ "$FAIL" -eq 0 ]; then
            echo ""
            echo "AUDIT RESULT: PASS"
            exit 0
        else
            echo ""
            echo "AUDIT RESULT: FAIL"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 3.3.1
remediate_3_3_1() {
    # CIS 3.3.1 Ensure IP forwarding is disabled

    echo "Applying remediation for CIS 3.3.1..."

    # Create sysctl configuration
    cat >> /etc/sysctl.d/60-netipv4_sysctl.conf << 'EOF'
    # CIS 3.3.1 - Disable IP forwarding
    net.ipv4.ip_forward = 0
    EOF

    cat >> /etc/sysctl.d/60-netipv6_sysctl.conf << 'EOF'
    # CIS 3.3.1 - Disable IPv6 forwarding
    net.ipv6.conf.all.forwarding = 0
    EOF

    # Apply settings immediately
    sysctl -w net.ipv4.ip_forward=0 2>/dev/null
    sysctl -w net.ipv6.conf.all.forwarding=0 2>/dev/null
    sysctl -w net.ipv4.route.flush=1 2>/dev/null
    sysctl -w net.ipv6.route.flush=1 2>/dev/null

    echo "IP forwarding disabled"
    echo "Remediation complete for CIS 3.3.1"
}


# Audit function for rule 3.3.2
audit_3_3_2() {
    local output
    local exit_code
    
    output=$(
        # CIS 3.3.2 Ensure packet redirect sending is disabled

        echo "Checking packet redirect sending status..."

        FAIL=0

        ALL_SEND=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null)
        DEFAULT_SEND=$(sysctl -n net.ipv4.conf.default.send_redirects 2>/dev/null)

        if [ "$ALL_SEND" = "0" ]; then
            echo "PASS: net.ipv4.conf.all.send_redirects = 0"
        else
            echo "FAIL: net.ipv4.conf.all.send_redirects = $ALL_SEND (should be 0)"
            FAIL=1
        fi

        if [ "$DEFAULT_SEND" = "0" ]; then
            echo "PASS: net.ipv4.conf.default.send_redirects = 0"
        else
            echo "FAIL: net.ipv4.conf.default.send_redirects = $DEFAULT_SEND (should be 0)"
            FAIL=1
        fi

        if [ "$FAIL" -eq 0 ]; then
            echo ""
            echo "AUDIT RESULT: PASS"
            exit 0
        else
            echo ""
            echo "AUDIT RESULT: FAIL"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 3.3.2
remediate_3_3_2() {
    # CIS 3.3.2 Ensure packet redirect sending is disabled

    echo "Applying remediation for CIS 3.3.2..."

    cat >> /etc/sysctl.d/60-netipv4_sysctl.conf << 'EOF'
    # CIS 3.3.2 - Disable packet redirect sending
    net.ipv4.conf.all.send_redirects = 0
    net.ipv4.conf.default.send_redirects = 0
    EOF

    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.default.send_redirects=0
    sysctl -w net.ipv4.route.flush=1

    echo "Remediation complete for CIS 3.3.2"
}


# Audit function for rule 3.3.3
audit_3_3_3() {
    local output
    local exit_code
    
    output=$(
        # CIS 3.3.3 Ensure bogus ICMP responses are ignored

        echo "Checking bogus ICMP response handling..."

        VALUE=$(sysctl -n net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null)

        if [ "$VALUE" = "1" ]; then
            echo "PASS: net.ipv4.icmp_ignore_bogus_error_responses = 1"
            echo ""
            echo "AUDIT RESULT: PASS"
            exit 0
        else
            echo "FAIL: net.ipv4.icmp_ignore_bogus_error_responses = $VALUE (should be 1)"
            echo ""
            echo "AUDIT RESULT: FAIL"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 3.3.3
remediate_3_3_3() {
    # CIS 3.3.3 Ensure bogus ICMP responses are ignored

    echo "Applying remediation for CIS 3.3.3..."

    cat >> /etc/sysctl.d/60-netipv4_sysctl.conf << 'EOF'
    # CIS 3.3.3 - Ignore bogus ICMP responses
    net.ipv4.icmp_ignore_bogus_error_responses = 1
    EOF

    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
    sysctl -w net.ipv4.route.flush=1

    echo "Remediation complete for CIS 3.3.3"
}


# --- Before Audit: 3.3.1 ---
echo -n "[1/3] Auditing 3.3.1... "
BEFORE_OUTPUT["3.3.1"]=$(audit_3_3_1 2>&1)
BEFORE_RESULTS["3.3.1"]=$?
if [ "${BEFORE_RESULTS["3.3.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi


# --- Before Audit: 3.3.2 ---
echo -n "[2/3] Auditing 3.3.2... "
BEFORE_OUTPUT["3.3.2"]=$(audit_3_3_2 2>&1)
BEFORE_RESULTS["3.3.2"]=$?
if [ "${BEFORE_RESULTS["3.3.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi


# --- Before Audit: 3.3.3 ---
echo -n "[3/3] Auditing 3.3.3... "
BEFORE_OUTPUT["3.3.3"]=$(audit_3_3_3 2>&1)
BEFORE_RESULTS["3.3.3"]=$?
if [ "${BEFORE_RESULTS["3.3.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi


###############################################################################
# PHASE 2: REMEDIATION
###############################################################################
echo ""
echo -e "${YELLOW}=== PHASE 2: Remediation ===${NC}"
echo ""

REMEDIATED_COUNT=0
for rule_id in "${RULES_LIST[@]}"; do
    if [ "${BEFORE_RESULTS[$rule_id]}" -ne 0 ]; then
        echo -e "${BLUE}Remediating $rule_id...${NC}"
        case "$rule_id" in

            "3.3.1")
                remediate_3_3_1
                ;;
            "3.3.2")
                remediate_3_3_2
                ;;
            "3.3.3")
                remediate_3_3_3
                ;;

        esac
        ((REMEDIATED_COUNT++))
    fi
done

if [ "$REMEDIATED_COUNT" -eq 0 ]; then
    echo "No remediation needed - all rules passed!"
else
    echo ""
    echo "Remediated $REMEDIATED_COUNT rule(s)"
fi


###############################################################################
# PHASE 3: FINAL AUDIT (AFTER)
###############################################################################
echo ""
echo -e "${YELLOW}=== PHASE 3: Final Audit (AFTER) ===${NC}"
echo ""



# --- After Audit: 3.3.1 ---
echo -n "[1/3] Re-auditing 3.3.1... "
AFTER_OUTPUT["3.3.1"]=$(audit_3_3_1 2>&1)
AFTER_RESULTS["3.3.1"]=$?
if [ "${AFTER_RESULTS["3.3.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi


# --- After Audit: 3.3.2 ---
echo -n "[2/3] Re-auditing 3.3.2... "
AFTER_OUTPUT["3.3.2"]=$(audit_3_3_2 2>&1)
AFTER_RESULTS["3.3.2"]=$?
if [ "${AFTER_RESULTS["3.3.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi


# --- After Audit: 3.3.3 ---
echo -n "[3/3] Re-auditing 3.3.3... "
AFTER_OUTPUT["3.3.3"]=$(audit_3_3_3 2>&1)
AFTER_RESULTS["3.3.3"]=$?
if [ "${AFTER_RESULTS["3.3.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi


###############################################################################
# PHASE 4: GENERATE HTML REPORT
###############################################################################
echo ""
echo -e "${YELLOW}=== PHASE 4: Generating HTML Report ===${NC}"
echo ""

REPORT_FILE="$REPORT_DIR/cis_report.html"
HOSTNAME=$(hostname)
REPORT_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Count results
BEFORE_PASS=0
BEFORE_FAIL=0
AFTER_PASS=0
AFTER_FAIL=0
FIXED_COUNT=0

for rule_id in "${RULES_LIST[@]}"; do
    if [ "${BEFORE_RESULTS[$rule_id]}" -eq 0 ]; then
        ((BEFORE_PASS++)) || true
    else
        ((BEFORE_FAIL++)) || true
    fi
    if [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
        ((AFTER_PASS++)) || true
    else
        ((AFTER_FAIL++)) || true
    fi
    if [ "${BEFORE_RESULTS[$rule_id]}" -ne 0 ] && [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
        ((FIXED_COUNT++)) || true
    fi
done

cat > "$REPORT_FILE" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Benchmark Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; padding: 20px; color: #eee; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { text-align: center; margin-bottom: 30px; color: #00d4ff; text-shadow: 0 0 20px rgba(0,212,255,0.5); }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); border-radius: 15px; padding: 20px; text-align: center; border: 1px solid rgba(255,255,255,0.2); }
        .card h3 { font-size: 0.9em; color: #aaa; margin-bottom: 10px; text-transform: uppercase; }
        .card .value { font-size: 2.5em; font-weight: bold; }
        .card.pass .value { color: #00ff88; }
        .card.fail .value { color: #ff4757; }
        .card.fixed .value { color: #ffd700; }
        .card.info .value { color: #00d4ff; }
        table { width: 100%; border-collapse: collapse; background: rgba(255,255,255,0.05); border-radius: 10px; overflow: hidden; }
        th { background: rgba(0,212,255,0.2); padding: 15px; text-align: left; font-weight: 600; }
        td { padding: 12px 15px; border-bottom: 1px solid rgba(255,255,255,0.1); }
        tr:hover { background: rgba(255,255,255,0.05); }
        .status { padding: 5px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }
        .status.pass { background: rgba(0,255,136,0.2); color: #00ff88; }
        .status.fail { background: rgba(255,71,87,0.2); color: #ff4757; }
        .status.fixed { background: rgba(255,215,0,0.2); color: #ffd700; }
        .toggle-btn { background: rgba(0,212,255,0.2); border: none; color: #00d4ff; padding: 5px 10px; border-radius: 5px; cursor: pointer; font-size: 0.8em; }
        .toggle-btn:hover { background: rgba(0,212,255,0.4); }
        .output { display: none; background: #0a0a15; padding: 10px; border-radius: 5px; margin-top: 10px; font-family: monospace; font-size: 0.85em; white-space: pre-wrap; max-height: 200px; overflow-y: auto; }
        .output.show { display: block; }
        .section { margin-bottom: 30px; }
        .section h2 { margin-bottom: 15px; color: #00d4ff; border-bottom: 2px solid rgba(0,212,255,0.3); padding-bottom: 10px; }
        .meta { text-align: center; color: #666; margin-bottom: 20px; font-size: 0.9em; }
        .arrow { margin: 0 10px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ CIS Benchmark Report</h1>
        <p class="meta">Host: <strong>HOSTNAME_PLACEHOLDER</strong> | Generated: <strong>DATE_PLACEHOLDER</strong></p>
        
        <div class="summary">
            <div class="card info">
                <h3>Total Rules</h3>
                <div class="value">TOTAL_PLACEHOLDER</div>
            </div>
            <div class="card pass">
                <h3>Before: Pass</h3>
                <div class="value">BEFORE_PASS_PLACEHOLDER</div>
            </div>
            <div class="card fail">
                <h3>Before: Fail</h3>
                <div class="value">BEFORE_FAIL_PLACEHOLDER</div>
            </div>
            <div class="card fixed">
                <h3>Fixed</h3>
                <div class="value">FIXED_PLACEHOLDER</div>
            </div>
            <div class="card pass">
                <h3>After: Pass</h3>
                <div class="value">AFTER_PASS_PLACEHOLDER</div>
            </div>
            <div class="card fail">
                <h3>After: Fail</h3>
                <div class="value">AFTER_FAIL_PLACEHOLDER</div>
            </div>
        </div>

        <div class="section">
            <h2>📋 Detailed Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Before</th>
                        <th></th>
                        <th>After</th>
                        <th>Status</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
HTMLEOF

# Generate table rows
for rule_id in "${RULES_LIST[@]}"; do
    before_status="FAIL"
    before_class="fail"
    after_status="FAIL"
    after_class="fail"
    overall_status="FAIL"
    overall_class="fail"
    
    [ "${BEFORE_RESULTS[$rule_id]}" -eq 0 ] && before_status="PASS" && before_class="pass"
    [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ] && after_status="PASS" && after_class="pass"
    
    if [ "${BEFORE_RESULTS[$rule_id]}" -ne 0 ] && [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
        overall_status="FIXED"
        overall_class="fixed"
    elif [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
        overall_status="PASS"
        overall_class="pass"
    fi
    
    # Escape HTML in output
    before_out=$(echo "${BEFORE_OUTPUT[$rule_id]}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    after_out=$(echo "${AFTER_OUTPUT[$rule_id]}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    
    cat >> "$REPORT_FILE" << ROWEOF
                    <tr>
                        <td><strong>$rule_id</strong></td>
                        <td><span class="status $before_class">$before_status</span></td>
                        <td class="arrow">→</td>
                        <td><span class="status $after_class">$after_status</span></td>
                        <td><span class="status $overall_class">$overall_status</span></td>
                        <td>
                            <button class="toggle-btn" onclick="this.nextElementSibling.classList.toggle('show')">Show Output</button>
                            <div class="output"><strong>Before:</strong>
$before_out

<strong>After:</strong>
$after_out</div>
                        </td>
                    </tr>
ROWEOF
done

cat >> "$REPORT_FILE" << 'HTMLEOF'
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
HTMLEOF

# Replace placeholders
sed -i "s/HOSTNAME_PLACEHOLDER/$HOSTNAME/g" "$REPORT_FILE"
sed -i "s/DATE_PLACEHOLDER/$REPORT_DATE/g" "$REPORT_FILE"
sed -i "s/TOTAL_PLACEHOLDER/$TOTAL_RULES/g" "$REPORT_FILE"
sed -i "s/BEFORE_PASS_PLACEHOLDER/$BEFORE_PASS/g" "$REPORT_FILE"
sed -i "s/BEFORE_FAIL_PLACEHOLDER/$BEFORE_FAIL/g" "$REPORT_FILE"
sed -i "s/AFTER_PASS_PLACEHOLDER/$AFTER_PASS/g" "$REPORT_FILE"
sed -i "s/AFTER_FAIL_PLACEHOLDER/$AFTER_FAIL/g" "$REPORT_FILE"
sed -i "s/FIXED_PLACEHOLDER/$FIXED_COUNT/g" "$REPORT_FILE"

echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}  Report generated successfully!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo "Report location: $REPORT_FILE"
echo ""
echo "Summary:"
echo "  Before: $BEFORE_PASS passed, $BEFORE_FAIL failed"
echo "  After:  $AFTER_PASS passed, $AFTER_FAIL failed"
echo "  Fixed:  $FIXED_COUNT rule(s)"
echo ""
