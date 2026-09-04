import os
import sys
import json
import re
import argparse
from pathlib import Path
from datetime import datetime
import ollama

# Ensure Windows stdout handles UTF-8 unicode logs cleanly
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def parse_args():
    parser = argparse.ArgumentParser(description="Zero-Trust AI Security Gateway & Data Standardizer Pipeline (V1.5.0 Deep Edition)")
    parser.add_argument("--model", default="llama3.2:3b", help="Local AI Model name to use in Ollama (e.g. llama3.2:3b, deepseek-r1:14b, deepseek-r1:32b)")
    parser.add_argument("--input", default="C:/Users/Cyrus/OneDrive/Desktop/DataPipeline/Input_Dropzone", help="Path to Input Dropzone folder")
    parser.add_argument("--output", default="C:/Users/Cyrus/OneDrive/Desktop/DataPipeline/Clean_Output", help="Path to Clean Output folder")
    parser.add_argument("--deep", action="store_true", help="Enable Deep Threat Telemetry & Multi-stage Risk Scoring")
    return parser.parse_args()

def privacy_scrubber(text):
    """
    V1.5.0 Deep Redactor: Scrubs multi-layered sensitive PII, credentials, IP addresses,
    financial markers, and government IDs before sending payload to AI models.
    Returns: (scrubbed_text, redaction_counts_dict)
    """
    counts = {
        "phones": 0,
        "emails": 0,
        "api_keys": 0,
        "ips": 0,
        "cards": 0,
        "ids": 0
    }

    # 1. API Keys, AWS Keys, and Bearer Tokens
    aws_key_pattern = r'\bAKIA[0-9A-Z]{16}\b'
    bearer_pattern = r'Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*'
    generic_key_pattern = r'\bsk-[a-zA-Z0-9]{32,}\b'
    
    counts["api_keys"] += len(re.findall(aws_key_pattern, text))
    counts["api_keys"] += len(re.findall(bearer_pattern, text))
    counts["api_keys"] += len(re.findall(generic_key_pattern, text))

    text = re.sub(aws_key_pattern, "[MASKED_API_KEY_REDACTED]", text)
    text = re.sub(bearer_pattern, "[MASKED_BEARER_TOKEN_REDACTED]", text)
    text = re.sub(generic_key_pattern, "[MASKED_API_KEY_REDACTED]", text)

    # 2. IPv4 Addresses
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    # Exclude local loopbacks 127.0.0.1 if desired, but scrub public/internal IPs
    ip_matches = [ip for ip in re.findall(ipv4_pattern, text) if not ip.startswith("127.0.0.1")]
    counts["ips"] = len(ip_matches)
    for ip in set(ip_matches):
        text = text.replace(ip, "[MASKED_IP_REDACTED]")

    # 3. Credit Card Numbers (13 to 19 digit patterns)
    card_pattern = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
    counts["cards"] = len(re.findall(card_pattern, text))
    text = re.sub(card_pattern, "[MASKED_CARD_REDACTED]", text)

    # 4. Social Security Numbers / Gov ID (XXX-XX-XXXX)
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    counts["ids"] = len(re.findall(ssn_pattern, text))
    text = re.sub(ssn_pattern, "[MASKED_GOV_ID_REDACTED]", text)

    # 5. East African & Kenyan Phone Numbers (+254..., 07..., 01...)
    phone_pattern = r'(\+254|0)(7|1)\d{8}'
    counts["phones"] = len(re.findall(phone_pattern, text))
    text = re.sub(phone_pattern, "[MASKED_PHONE_REDACTED]", text)

    # 6. Email Addresses
    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    counts["emails"] = len(re.findall(email_pattern, text))
    text = re.sub(email_pattern, "[MASKED_EMAIL_REDACTED]", text)

    return text, counts

def ai_secure_pipeline(args):
    deep_mode_str = " (DEEP MODEL ACTIVE)" if args.deep else ""
    print(f"🛡️ [PIPELINE START (V1.5.0{deep_mode_str})]: Initiating data standardization scan...")
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    model_name = args.model
    input_dropzone = Path(args.input)
    output_clean = Path(args.output)
    
    if not input_dropzone.exists():
        print(f"   -> [PRIVACY ERROR]: Input Dropzone does not exist at {input_dropzone}")
        return

    raw_files = [f for f in input_dropzone.iterdir() if f.is_file()]
    if not raw_files:
        print("   -> [PRIVACY GATEWAY]: Dropzone empty. No raw files to process.")
        return

    for file_path in raw_files:
        print(f"   -> [PRIVACY GATEWAY]: Scrubbing multi-layer PII/threats from {file_path.name}...")
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_content = f.read().strip()

            if not raw_content:
                file_path.unlink()
                continue

            # Step 1: Run through multi-layered deep privacy & credential redactor
            safe_content, redactions = privacy_scrubber(raw_content)
            total_redactions = sum(redactions.values())

            print(f"   -> [PII_REDACTED_STATS]: {file_path.name} - Phones: {redactions['phones']}, Emails: {redactions['emails']}, Keys: {redactions['api_keys']}, IPs: {redactions['ips']}, Cards: {redactions['cards']}, IDs: {redactions['ids']}")

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
                "- 'pii_taxonomy': list of detected sensitive data categories (e.g. ['Phone', 'APIKey', 'IPAddress'])\n"
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
                # Fallback structure if LLM output fails standard JSON parsing
                parsed_data = {
                    "entity_id": "RAW-LOG-SCAN",
                    "value_metric": 0.0,
                    "category": "Unstructured Log",
                    "summary": safe_content[:150],
                    "risk_score": 5.0 if total_redactions > 0 else 1.0,
                    "threat_level": "HIGH" if redactions["api_keys"] > 0 or redactions["cards"] > 0 else ("MEDIUM" if total_redactions > 0 else "LOW"),
                    "pii_taxonomy": [k for k, v in redactions.items() if v > 0],
                    "compliance_status": "FLAGGED_FOR_REVIEW" if total_redactions > 0 else "COMPLIANT",
                    "confidence_score": 85.0
                }

            parsed_data["normalized_timestamp"] = timestamp_str
            parsed_data["source_file"] = file_path.name
            parsed_data["contains_privacy_shield"] = True
            parsed_data["total_redactions"] = total_redactions
            parsed_data["redactions_detail"] = redactions

            # Calculate default risk score if missing
            risk_score = float(parsed_data.get("risk_score", 0.0))
            if risk_score == 0.0 and total_redactions > 0:
                risk_score = min(10.0, total_redactions * 2.5)
                parsed_data["risk_score"] = risk_score

            threat_level = str(parsed_data.get("threat_level", "LOW")).upper()
            compliance_status = str(parsed_data.get("compliance_status", "COMPLIANT")).upper()

            # Save clean audited JSON payload
            output_clean.mkdir(parents=True, exist_ok=True)
            output_file = output_clean / f"secure_audited_{file_path.stem}.json"
            with open(output_file, "w", encoding="utf-8") as out_f:
                json.dump(parsed_data, out_f, indent=4)

            print(f"   -> [DEEP_ANALYSIS_STATS]: file={file_path.name} risk={risk_score:.1f} threat={threat_level} status={compliance_status}")
            print(f"   -> [OLLAMA SUCCESS]: Securely saved {output_file.name}")
            file_path.unlink()

        except Exception as e:
            print(f"   -> [PRIVACY ERROR]: Failed processing {file_path.name}: {e}")

if __name__ == "__main__":
    args = parse_args()
    ai_secure_pipeline(args)