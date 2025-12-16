#!/usr/bin/env bash
###############################################################################
#
# CIS Benchmark Audit & Remediation Script
#
# Generated on    : 2025-12-16 16:41:44
# Source registry : platforms\linux\ubuntu\desktop\rules\index.json
# Rule count      : 2
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

TOTAL_RULES=2
RULES_LIST=("1.5.1" "1.5.2")

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



# Audit function for rule 1.5.1
audit_1_5_1() {
    local output
    local exit_code
    
    output=$(
        # 1.5.1 Ensure address space layout randomization is enabled (Automated)
        # Description: Address space layout randomization (ASLR) is an exploit mitigation 
        # technique which randomly arranges the address space of key data areas of a process.
        # Rationale: Randomly placing virtual memory regions will make it difficult to write 
        # memory page exploits as the memory placement will be consistently shifting.

        {
            a_output=(); a_output2=(); a_parlist=("kernel.randomize_va_space=2")
            l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"
    
            f_kernel_parameter_chk()
            {
                l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= '{print $2}' | xargs)" # Check running configuration
                if grep -Pq -- '\b'"$l_parameter_value"'\b' <<< "$l_running_parameter_value"; then
                    a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\" in the running configuration")
                else
                    a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\" in the running configuration and should have a value of: \"$l_value_out\"")
                fi
        
                unset A_out; declare -A A_out # Check durable setting (files)
                while read -r l_out; do
                    if [ -n "$l_out" ]; then
                        if [[ $l_out =~ ^\s*# ]]; then
                            l_file="${l_out//# /}"
                        else
                            l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                            [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_file")
                        fi
                    fi
                done < <("$l_systemdsysctl" --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')
        
                if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
                    l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)"
                    l_kpar="${l_kpar//\//.}"
                    [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf")
                fi
        
                if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
                    while IFS="=" read -r l_fkpname l_file_parameter_value; do
                        l_fkpname="${l_fkpname// /}"; l_file_parameter_value="${l_file_parameter_value// /}"
                        if grep -Pq -- '\b'"$l_parameter_value"'\b' <<< "$l_file_parameter_value"; then
                            a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\"")
                        else
                            a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_value_out\"")
                        fi
                    done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}")
                else
                    a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \
                        " ** Note: \"$l_parameter_name\" May be set in a file that's ignored by load procedure **")
                fi
            }
    
            l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)"
            while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters
                l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}"
                l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }"
                l_value_out="$(tr -d '(){}' <<< "$l_value_out")"
                f_kernel_parameter_chk
            done < <(printf '%s\n' "${a_parlist[@]}")
    
            if [ "${#a_output2[@]}" -le 0 ]; then
                printf '%s\n' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" ""
                exit 0
            else
                printf '%s\n' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
                [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
                exit 1
            fi
        }
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.5.1
remediate_1_5_1() {
    # 1.5.1 Ensure address space layout randomization is enabled (Automated)
    # Remediation: Set kernel.randomize_va_space = 2 in sysctl configuration
    # Description: ASLR is an exploit mitigation technique which randomly arranges 
    # the address space of key data areas of a process.

    echo "=== 1.5.1 ASLR Remediation ==="
    echo ""

    SYSCTL_CONF="/etc/sysctl.d/60-kernel_sysctl.conf"
    PARAM_NAME="kernel.randomize_va_space"
    PARAM_VALUE="2"

    echo "Setting $PARAM_NAME = $PARAM_VALUE"
    echo ""

    # Check current running value
    echo "1. Current running configuration:"
    CURRENT_VALUE=$(sysctl -n "$PARAM_NAME" 2>/dev/null)
    echo "   $PARAM_NAME = $CURRENT_VALUE"
    echo ""

    # Set the parameter in configuration file
    echo "2. Setting durable configuration in $SYSCTL_CONF..."

    # Create the file if it doesn't exist, or update if it does
    if [ -f "$SYSCTL_CONF" ]; then
        # Check if the parameter already exists in the file
        if grep -q "^$PARAM_NAME" "$SYSCTL_CONF"; then
            # Update existing parameter
            sed -i "s/^$PARAM_NAME.*/$PARAM_NAME = $PARAM_VALUE/" "$SYSCTL_CONF"
            echo "   [OK] Updated existing parameter in $SYSCTL_CONF"
        else
            # Append the parameter
            printf "%s\n" "$PARAM_NAME = $PARAM_VALUE" >> "$SYSCTL_CONF"
            echo "   [OK] Added parameter to $SYSCTL_CONF"
        fi
    else
        # Create new file with the parameter
        printf "%s\n" "$PARAM_NAME = $PARAM_VALUE" >> "$SYSCTL_CONF"
        echo "   [OK] Created $SYSCTL_CONF with parameter"
    fi

    # Apply the setting to the running kernel
    echo ""
    echo "3. Applying to running kernel..."
    sysctl -w "$PARAM_NAME=$PARAM_VALUE"
    if [ $? -eq 0 ]; then
        echo "   [OK] Applied successfully"
    else
        echo "   [ERROR] Failed to apply kernel parameter"
        exit 1
    fi

    # Verify
    echo ""
    echo "4. Verification:"
    NEW_VALUE=$(sysctl -n "$PARAM_NAME" 2>/dev/null)
    echo "   $PARAM_NAME = $NEW_VALUE"

    if [ "$NEW_VALUE" = "$PARAM_VALUE" ]; then
        echo ""
        echo "[SUCCESS] ASLR is now enabled with value $PARAM_VALUE"
        exit 0
    else
        echo ""
        echo "[ERROR] Failed to set ASLR value"
        exit 1
    fi
}


# Audit function for rule 1.5.2
audit_1_5_2() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.5.2 - Ensure ptrace_scope is restricted (Automated)
        # Profile: Level 1 - Server, Level 1 - Workstation
        #
        # NOTE: Ubuntu ships with /etc/sysctl.d/10-ptrace.conf which sets
        # kernel.yama.ptrace_scope = 1 by default (already CIS compliant)

        audit_ptrace_scope() {
            local l_output=""
            local l_output2=""
            local l_parameter_name="kernel.yama.ptrace_scope"
    
            # Check running configuration
            local l_running_value
            l_running_value="$(sysctl -n "$l_parameter_name" 2>/dev/null)"
    
            if [ -z "$l_running_value" ]; then
                l_output2="$l_output2\n - Unable to read $l_parameter_name from running configuration (Yama LSM may not be enabled)"
            elif [[ "$l_running_value" =~ ^[123]$ ]]; then
                l_output="$l_output\n - \"$l_parameter_name\" is correctly set to \"$l_running_value\" in the running configuration"
            else
                l_output2="$l_output2\n - \"$l_parameter_name\" is incorrectly set to \"$l_running_value\" in the running configuration (should be 1, 2, or 3)"
            fi
    
            # Check durable settings in configuration files
            local l_file_found=false
            local l_file_value=""
            local l_config_file=""
    
            # Check /etc/sysctl.conf and /etc/sysctl.d/*.conf
            # Only match lines that are NOT commented out (no leading #)
            for l_file in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
                if [ -f "$l_file" ]; then
                    # Extract only uncommented lines, get the last occurrence
                    local l_match
                    l_match="$(grep -E "^[^#]*$l_parameter_name\s*=" "$l_file" 2>/dev/null | tail -1)"
                    if [ -n "$l_match" ]; then
                        l_file_value="$(echo "$l_match" | awk -F= '{print $2}' | tr -d ' \t')"
                        if [ -n "$l_file_value" ]; then
                            l_file_found=true
                            l_config_file="$l_file"
                        fi
                    fi
                fi
            done
    
            # Check UFW sysctl file if exists
            if [ -f /etc/default/ufw ]; then
                local l_ufwscf
                l_ufwscf="$(awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw | tr -d '"')"
                if [ -n "$l_ufwscf" ] && [ -f "$l_ufwscf" ]; then
                    local l_match
                    l_match="$(grep -E "^[^#]*$l_parameter_name\s*=" "$l_ufwscf" 2>/dev/null | tail -1)"
                    if [ -n "$l_match" ]; then
                        local l_ufw_value
                        l_ufw_value="$(echo "$l_match" | awk -F= '{print $2}' | tr -d ' \t')"
                        if [ -n "$l_ufw_value" ]; then
                            l_file_found=true
                            l_file_value="$l_ufw_value"
                            l_config_file="$l_ufwscf"
                        fi
                    fi
                fi
            fi
    
            if [ "$l_file_found" = true ]; then
                if [[ "$l_file_value" =~ ^[123]$ ]]; then
                    l_output="$l_output\n - \"$l_parameter_name\" is correctly set to \"$l_file_value\" in \"$l_config_file\""
                else
                    l_output2="$l_output2\n - \"$l_parameter_name\" is incorrectly set to \"$l_file_value\" in \"$l_config_file\" (should be 1, 2, or 3)"
                fi
            else
                l_output2="$l_output2\n - \"$l_parameter_name\" is not set in any sysctl configuration file"
                l_output2="$l_output2\n   (Note: Check if the value is commented out or file is missing)"
            fi
    
            # Output results
            if [ -z "$l_output2" ]; then
                echo -e "\n- Audit Result: ** PASS **"
                echo -e "$l_output\n"
                return 0
            else
                echo -e "\n- Audit Result: ** FAIL **"
                echo -e " - Reason(s) for audit failure:"
                echo -e "$l_output2"
                if [ -n "$l_output" ]; then
                    echo -e "\n- Correctly set:"
                    echo -e "$l_output\n"
                fi
                return 1
            fi
        }

        audit_ptrace_scope
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.5.2
remediate_1_5_2() {
    # CIS Benchmark 1.5.2 - Ensure ptrace_scope is restricted (Automated)
    # Profile: Level 1 - Server, Level 1 - Workstation
    #
    # Remediation: Set kernel.yama.ptrace_scope to 1 (restricted ptrace)
    #
    # NOTE: Ubuntu ships with /etc/sysctl.d/10-ptrace.conf by default.
    # This script uses a dedicated file /etc/sysctl.d/60-ptrace_scope.conf
    # to ensure our setting takes precedence (higher number = loaded later)

    remediate_ptrace_scope() {
        local l_parameter_name="kernel.yama.ptrace_scope"
        local l_parameter_value="1"  # Using restricted mode (value 1) as default
        local l_sysctl_file="/etc/sysctl.d/60-ptrace_scope.conf"
    
        echo "Setting $l_parameter_name to $l_parameter_value..."
    
        # Create directory if it doesn't exist
        if [ ! -d "/etc/sysctl.d" ]; then
            mkdir -p /etc/sysctl.d
        fi
    
        # Comment out (not delete) any existing entries to preserve original config
        for l_file in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
            if [ -f "$l_file" ] && [ "$l_file" != "$l_sysctl_file" ]; then
                # Only modify if there's an uncommented entry
                if grep -Eq "^[^#]*$l_parameter_name\s*=" "$l_file" 2>/dev/null; then
                    echo " - Commenting out existing entry in $l_file"
                    sed -i "s/^\([^#]*$l_parameter_name\s*=\)/# \1/" "$l_file"
                fi
            fi
        done
    
        # Check and update UFW sysctl file if exists
        if [ -f /etc/default/ufw ]; then
            local l_ufwscf
            l_ufwscf="$(awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw | tr -d '"')"
            if [ -n "$l_ufwscf" ] && [ -f "$l_ufwscf" ]; then
                if grep -Eq "^[^#]*$l_parameter_name\s*=" "$l_ufwscf" 2>/dev/null; then
                    echo " - Commenting out existing entry in $l_ufwscf"
                    sed -i "s/^\([^#]*$l_parameter_name\s*=\)/# \1/" "$l_ufwscf"
                fi
            fi
        fi
    
        # Create or overwrite our dedicated configuration file
        echo " - Writing $l_parameter_name=$l_parameter_value to $l_sysctl_file"
        cat > "$l_sysctl_file" << EOF
    # CIS Benchmark 1.5.2 - Ensure ptrace_scope is restricted
    # Generated by remediation script on $(date)
    # Values: 1=restricted, 2=admin-only, 3=no attach (irreversible)
    $l_parameter_name=$l_parameter_value
    EOF
    
        # Set the active kernel parameter
        echo " - Applying to running kernel..."
        if sysctl -w "$l_parameter_name=$l_parameter_value" > /dev/null 2>&1; then
            echo " - Successfully set $l_parameter_name to $l_parameter_value in running configuration"
        else
            echo " - WARNING: Failed to set $l_parameter_name in running configuration"
            echo "   Yama LSM may not be enabled in the kernel"
            return 1
        fi
    
        echo ""
        echo "Remediation complete."
        echo ""
        echo "Configuration saved to: $l_sysctl_file"
        echo ""
        echo "Value meanings:"
        echo "  1 = Restricted ptrace (only descendants can be traced)"
        echo "  2 = Admin-only attach (requires CAP_SYS_PTRACE)"
        echo "  3 = No attach (ptrace completely disabled, irreversible until reboot)"
        echo ""
        echo "If a value of 2 or 3 is required by local site policy,"
        echo "edit $l_sysctl_file and run: sysctl -p $l_sysctl_file"
    
        return 0
    }

    remediate_ptrace_scope
}


# --- Before Audit: 1.5.1 ---
echo -n "[1/2] Auditing 1.5.1... "
BEFORE_OUTPUT["1.5.1"]=$(audit_1_5_1 2>&1)
BEFORE_RESULTS["1.5.1"]=$?
if [ "${BEFORE_RESULTS["1.5.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi


# --- Before Audit: 1.5.2 ---
echo -n "[2/2] Auditing 1.5.2... "
BEFORE_OUTPUT["1.5.2"]=$(audit_1_5_2 2>&1)
BEFORE_RESULTS["1.5.2"]=$?
if [ "${BEFORE_RESULTS["1.5.2"]}" -eq 0 ]; then
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

            "1.5.1")
                remediate_1_5_1
                ;;
            "1.5.2")
                remediate_1_5_2
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



# --- After Audit: 1.5.1 ---
echo -n "[1/2] Re-auditing 1.5.1... "
AFTER_OUTPUT["1.5.1"]=$(audit_1_5_1 2>&1)
AFTER_RESULTS["1.5.1"]=$?
if [ "${AFTER_RESULTS["1.5.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi


# --- After Audit: 1.5.2 ---
echo -n "[2/2] Re-auditing 1.5.2... "
AFTER_OUTPUT["1.5.2"]=$(audit_1_5_2 2>&1)
AFTER_RESULTS["1.5.2"]=$?
if [ "${AFTER_RESULTS["1.5.2"]}" -eq 0 ]; then
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
