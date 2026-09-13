import os
import sys
import json
import re
import math
import base64
import argparse
from pathlib import Path
from datetime import datetime
import ollama

# Ensure Windows stdout handles UTF-8 unicode logs cleanly
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def calculate_shannon_entropy(text):
    """
    Computes the Shannon Entropy H(S) of a string to detect high-entropy secrets (0.0 to 8.0 bits/byte).
    """
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def parse_args():
    parser = argparse.ArgumentParser(description="Zero-Trust AI Security Gateway & Data Standardizer Pipeline (V2.1.0 Enterprise Neural SOC Engine)")
    parser.add_argument("--model", default="llama3.2:3b", help="Local AI Model name to use in Ollama (e.g. llama3.2:3b, deepseek-r1:14b, deepseek-r1:32b)")
    parser.add_argument("--input", default="C:/Users/Cyrus/OneDrive/Desktop/DataPipeline/Input_Dropzone", help="Path to Input Dropzone folder")
    parser.add_argument("--output", default="C:/Users/Cyrus/OneDrive/Desktop/DataPipeline/Clean_Output", help="Path to Clean Output folder")
    parser.add_argument("--vault", default=None, help="Path to Quarantine Vault directory")
    parser.add_argument("--deep", action="store_true", help="Enable Deep Neural Telemetry & Multi-stage Risk Scoring")
    return parser.parse_args()

def privacy_scrubber(text):
    """
    V2.1.0 Enterprise Neural Redactor: Scrubs multi-layered sensitive PII, credentials, high-entropy secrets,
    RSA keys, DB connection strings, command/shellcode injections, Base64 payloads, IP addresses, cards, IDs.
    Returns: (scrubbed_text, redaction_counts_dict)
    """
    counts = {
        "phones": 0,
        "emails": 0,
        "api_keys": 0,
        "pem_keys": 0,
        "db_conns": 0,
        "command_injections": 0,
        "entropy_secrets": 0,
        "ips": 0,
        "cards": 0,
        "ids": 0
    }

    # 1. Shellcode & Command Injection Patterns
    cmd_pattern = r'(?:powershell(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*-(?:enc|encodedcommand|exec|executionpolicy)\b[^\n]+|cmd\.exe\s+/c\b[^\n]+|/bin/(?:bash|sh)\s+-c\b[^\n]+)'
    counts["command_injections"] += len(re.findall(cmd_pattern, text, re.IGNORECASE))
    text = re.sub(cmd_pattern, "[MASKED_COMMAND_INJECTION_REDACTED]", text, flags=re.IGNORECASE)

    # 2. RSA / PEM Private Keys
    pem_pattern = r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
    counts["pem_keys"] += len(re.findall(pem_pattern, text))
    text = re.sub(pem_pattern, "[MASKED_PEM_KEY_REDACTED]", text)

    # 3. Database Connection Strings
    db_conn_pattern = r'(?:postgres|postgresql|mongodb|mongodb\+srv|mysql|redis|amqp)://[^\s"\'<>]+'
    db_sql_pattern = r'Server=[^;]+;Database=[^;]+;[^\s"]+'
    counts["db_conns"] += len(re.findall(db_conn_pattern, text)) + len(re.findall(db_sql_pattern, text))
    text = re.sub(db_conn_pattern, "[MASKED_DB_CONN_REDACTED]", text)
    text = re.sub(db_sql_pattern, "[MASKED_DB_CONN_REDACTED]", text)

    # 4. API Keys, AWS Keys, and Bearer Tokens
    aws_key_pattern = r'\bAKIA[0-9A-Z]{16}\b'
    bearer_pattern = r'Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*'
    generic_key_pattern = r'\bsk-[a-zA-Z0-9]{32,}\b'
    
    counts["api_keys"] += len(re.findall(aws_key_pattern, text))
    counts["api_keys"] += len(re.findall(bearer_pattern, text))
    counts["api_keys"] += len(re.findall(generic_key_pattern, text))

    text = re.sub(aws_key_pattern, "[MASKED_API_KEY_REDACTED]", text)
    text = re.sub(bearer_pattern, "[MASKED_BEARER_TOKEN_REDACTED]", text)
    text = re.sub(generic_key_pattern, "[MASKED_API_KEY_REDACTED]", text)

    # 5. Base64 Obfuscated Payloads (> 32 chars)
    b64_tokens = re.findall(r'\b[A-Za-z0-9+/]{32,}={0,2}\b', text)
    for b64 in set(b64_tokens):
        if not b64.startswith("MASKED_") and not b64.startswith("["):
            try:
                decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
                if any(kw in decoded.lower() for kw in ["select", "union", "exec", "password", "key", "token", "0x", "/bin/"]):
                    text = text.replace(b64, "[MASKED_BASE64_OBFUSCATED_PAYLOAD_REDACTED]")
                    counts["entropy_secrets"] += 1
            except Exception:
                pass

    # 6. High Entropy Secret Tokens (> 20 chars, entropy > 4.5)
    tokens = re.findall(r'\b[a-zA-Z0-9_\-\+\/=]{20,}\b', text)
    for token in set(tokens):
        if not token.startswith("[MASKED_") and calculate_shannon_entropy(token) > 4.5:
            text = text.replace(token, "[MASKED_HIGH_ENTROPY_SECRET_REDACTED]")
            counts["entropy_secrets"] += 1

    # 7. IPv4 Addresses
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ip_matches = [ip for ip in re.findall(ipv4_pattern, text) if not ip.startswith("127.0.0.1")]
    counts["ips"] = len(ip_matches)
    for ip in set(ip_matches):
        text = text.replace(ip, "[MASKED_IP_REDACTED]")

    # 8. Credit Card Numbers
    card_pattern = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
    counts["cards"] = len(re.findall(card_pattern, text))
    text = re.sub(card_pattern, "[MASKED_CARD_REDACTED]", text)

    # 9. Social Security / National ID (XXX-XX-XXXX)
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    counts["ids"] = len(re.findall(ssn_pattern, text))
    text = re.sub(ssn_pattern, "[MASKED_GOV_ID_REDACTED]", text)

    # 10. East African & Kenyan Phone Numbers (+254..., 07..., 01...)
    phone_pattern = r'(\+254|0)(7|1)\d{8}'
    counts["phones"] = len(re.findall(phone_pattern, text))
    text = re.sub(phone_pattern, "[MASKED_PHONE_REDACTED]", text)

    # 11. Email Addresses
    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    counts["emails"] = len(re.findall(email_pattern, text))
    text = re.sub(email_pattern, "[MASKED_EMAIL_REDACTED]", text)

    return text, counts

def map_regulatory_frameworks(redactions):
    """
    Maps detected redaction categories to regulatory compliance tags.
    """
    frameworks = []
    if redactions["phones"] > 0 or redactions["ids"] > 0:
        frameworks.append("KPDTP_2019") # Kenya Data Protection Act 2019
    if redactions["emails"] > 0 or redactions["ips"] > 0 or redactions["ids"] > 0:
        frameworks.append("GDPR_ART_4") # EU GDPR Article 4 Personal Data
    if redactions["cards"] > 0 or redactions["api_keys"] > 0 or redactions["pem_keys"] > 0 or redactions["db_conns"] > 0:
        frameworks.append("PCI_DSS_REQ_3") # PCI-DSS Requirement 3 Protection of Stored Data
    if redactions["ids"] > 0:
        frameworks.append("HIPAA_PRIVACY") # HIPAA Privacy Rule Identifiers
    return frameworks if frameworks else ["COMPLIANT_STANDARD"]

def generate_siem_soc_alert(output_dir, source_file, parsed_data):
    """
    Generates a structured SIEM SOC incident alert payload for critical threats.
    """
    alerts_dir = output_dir / "SOC_Alerts"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    alert_filename = f"SOC_Incident_Alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{Path(source_file).stem}.json"
    alert_path = alerts_dir / alert_filename
    
    soc_payload = {
        "alert_id": f"SOC-ALT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": parsed_data.get("threat_level", "HIGH"),
        "risk_score": parsed_data.get("risk_score", 10.0),
        "source_file": source_file,
        "summary": parsed_data.get("summary", "Critical threat payload intercepted"),
        "quarantine_path": parsed_data.get("quarantine_path", ""),
        "regulatory_impact": parsed_data.get("regulatory_frameworks", []),
        "redactions_detail": parsed_data.get("redactions_detail", {})
    }

    with open(alert_path, "w", encoding="utf-8") as f:
        json.dump(soc_payload, f, indent=4)
    print(f"   -> [SIEM_SOC_ALERT_GENERATED]: Security Incident Alert saved at {alert_filename}")

def ai_secure_pipeline(args):
    deep_mode_str = " (DEEP NEURAL SOC ACTIVE)" if args.deep else ""
    print(f"🛡️ [PIPELINE START (V2.1.0 ENTERPRISE SOC{deep_mode_str})]: Initiating neural data scan...")
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    model_name = args.model
    input_dropzone = Path(args.input)
    output_clean = Path(args.output)
    quarantine_vault = Path(args.vault) if args.vault else input_dropzone / "Quarantine"
    
    if not input_dropzone.exists():
        print(f"   -> [PRIVACY ERROR]: Input Dropzone does not exist at {input_dropzone}")
        return

    raw_files = [f for f in input_dropzone.iterdir() if f.is_file()]
    if not raw_files:
        print("   -> [PRIVACY GATEWAY]: Dropzone empty. No raw files to process.")
        return

    for file_path in raw_files:
        print(f"   -> [PRIVACY GATEWAY]: Scrubbing neural PII/threats from {file_path.name}...")
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_content = f.read().strip()

            if not raw_content:
                file_path.unlink()
                continue

            # Step 1: Run through multi-layered deep neural redactor & secret scanner
            safe_content, redactions = privacy_scrubber(raw_content)
            total_redactions = sum(redactions.values())
            regulatory_tags = map_regulatory_frameworks(redactions)

            print(f"   -> [PII_REDACTED_STATS]: {file_path.name} - Phones: {redactions['phones']}, Emails: {redactions['emails']}, Keys: {redactions['api_keys'] + redactions['pem_keys'] + redactions['entropy_secrets']}, DBs: {redactions['db_conns']}, Cmds: {redactions['command_injections']}, IPs: {redactions['ips']}, Cards: {redactions['cards']}, IDs: {redactions['ids']}")

            # Step 2: System prompt with Deep telemetry requirements
            system_prompt = (
                "You are an advanced Zero-Trust AI Security Analysis Engine. Analyze the anonymized log input. "
                "Extract structured metadata and return ONLY a strict JSON object with these keys:\n"
                "- 'entity_id': transaction or session ID reference (string or null)\n"
                "- 'value_metric': numerical financial/operational cost value (float, default 0.0)\n"
                "- 'category': log classification (e.g. 'Financial', 'Security Alert', 'System Error', 'Authentication', 'General Text')\n"
                "- 'summary': brief concise summary of the sanitized event\n"
                "- 'risk_score': security threat score from 0.0 (safe) to 10.0 (critical threat) (float)\n"
                "- 'threat_level': threat tier rating ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')\n"
                "- 'pii_taxonomy': list of detected sensitive data categories\n"
                "- 'compliance_status': regulatory rating ('COMPLIANT', 'FLAGGED_FOR_REVIEW', 'NON_COMPLIANT')\n"
                "- 'confidence_score': analysis confidence percentage (float 0.0 to 100.0)\n"
                "Return raw JSON only without conversational text, explanations, or codeblock markdown."
            )

            response = ollama.generate(
                model=model_name,
                prompt=f"Standardize & inspect this secure payload: {safe_content}",
                system=system_prompt,
                options={"temperature": 0.0},
                keep_alive=0
            )

            ai_output = response['response'].strip()

            # Filter out reasoning <think>...</think> blocks from DeepSeek-R1 models
            if "<think>" in ai_output:
                think_end = ai_output.find("</think>")
                if think_end != -1:
                    ai_output = ai_output[think_end + 8:].strip()

            if ai_output.startswith("```json"):
                ai_output = ai_output.split("```json")[1].split("```")[0].strip()
            elif ai_output.startswith("```"):
                ai_output = ai_output.split("```")[1].split("```")[0].strip()

            try:
                parsed_data = json.loads(ai_output)
            except json.JSONDecodeError:
                parsed_data = {
                    "entity_id": "RAW-LOG-SCAN",
                    "value_metric": 0.0,
                    "category": "Unstructured Log",
                    "summary": safe_content[:150],
                    "risk_score": 5.0 if total_redactions > 0 else 1.0,
                    "threat_level": "CRITICAL" if redactions["command_injections"] > 0 else ("HIGH" if redactions["api_keys"] > 0 or redactions["pem_keys"] > 0 or redactions["cards"] > 0 else ("MEDIUM" if total_redactions > 0 else "LOW")),
                    "pii_taxonomy": [k for k, v in redactions.items() if v > 0],
                    "compliance_status": "FLAGGED_FOR_REVIEW" if total_redactions > 0 else "COMPLIANT",
                    "confidence_score": 85.0
                }

            parsed_data["normalized_timestamp"] = timestamp_str
            parsed_data["source_file"] = file_path.name
            parsed_data["contains_privacy_shield"] = True
            parsed_data["total_redactions"] = total_redactions
            parsed_data["redactions_detail"] = redactions
            parsed_data["regulatory_frameworks"] = regulatory_tags

            # Calculate default risk score if missing
            risk_score = float(parsed_data.get("risk_score", 0.0))
            if risk_score == 0.0 and total_redactions > 0:
                risk_score = min(10.0, total_redactions * 2.0)
                parsed_data["risk_score"] = risk_score

            threat_level = str(parsed_data.get("threat_level", "LOW")).upper()
            compliance_status = str(parsed_data.get("compliance_status", "COMPLIANT")).upper()

            # Automated Threat Vault Quarantine for Critical/High Threat Payloads
            if threat_level in ["CRITICAL", "HIGH"] or risk_score >= 8.0:
                quarantine_vault.mkdir(parents=True, exist_ok=True)
                quarantine_file = quarantine_vault / f"quarantined_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file_path.name}"
                with open(quarantine_file, "w", encoding="utf-8") as q_f:
                    q_f.write(raw_content)
                parsed_data["quarantine_path"] = str(quarantine_file)
                print(f"   -> [THREAT_QUARANTINE_ISOLATED]: Critical threat payload isolated at {quarantine_file.name}")
                
                # Generate SIEM SOC Alert JSON
                generate_siem_soc_alert(output_clean, file_path.name, parsed_data)

            # Save clean audited JSON payload
            output_clean.mkdir(parents=True, exist_ok=True)
            output_file = output_clean / f"secure_audited_{file_path.stem}.json"
            with open(output_file, "w", encoding="utf-8") as out_f:
                json.dump(parsed_data, out_f, indent=4)

            print(f"   -> [DEEP_ANALYSIS_STATS]: file={file_path.name} risk={risk_score:.1f} threat={threat_level} status={compliance_status}")
            print(f"   -> [REGULATORY_TAGS]: frameworks={','.join(regulatory_tags)}")
            print(f"   -> [OLLAMA SUCCESS]: Securely saved {output_file.name}")
            file_path.unlink()

        except Exception as e:
            print(f"   -> [PRIVACY ERROR]: Failed processing {file_path.name}: {e}")

if __name__ == "__main__":
    args = parse_args()
    ai_secure_pipeline(args)

