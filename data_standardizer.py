import os
import json
import re
import argparse
from pathlib import Path
from datetime import datetime
import ollama

def parse_args():
    parser = argparse.ArgumentParser(description="Zero-Trust AI Security Gateway & Data Standardizer Pipeline")
    parser.add_argument("--model", default="llama3.2:3b", help="Local AI Model name to use in Ollama")
    parser.add_argument("--input", default="C:/Users/Cyrus/OneDrive/Desktop/DataPipeline/Input_Dropzone", help="Path to Input Dropzone folder")
    parser.add_argument("--output", default="C:/Users/Cyrus/OneDrive/Desktop/DataPipeline/Clean_Output", help="Path to Clean Output folder")
    return parser.parse_args()

def privacy_scrubber(text):
    """
    Scrubs specific PII tracking markers out of the text before the AI handles it.
    Protects phone numbers, specific names, and sensitive formats.
    Returns: (scrubbed_text, phone_redactions_count, email_redactions_count)
    """
    # Match common East African / Kenyan phone number formats (e.g., +254..., 07..., 01...)
    phone_pattern = r'(\+254|0)(7|1)\d{8}'
    phone_matches = len(re.findall(phone_pattern, text))
    text = re.sub(phone_pattern, "[MASKED_PHONE_REDACTED]", text)
    
    # Match email addresses
    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    email_matches = len(re.findall(email_pattern, text))
    text = re.sub(email_pattern, "[MASKED_EMAIL_REDACTED]", text)
    
    return text, phone_matches, email_matches

def ai_secure_pipeline(args):
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
        print(f"   -> [PRIVACY GATEWAY]: Scrubbing PII from {file_path.name}...")
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_content = f.read().strip()

            if not raw_content:
                file_path.unlink()
                continue

            # Step 1: Run the raw data through the local privacy scrubber
            safe_content, phone_redactions, email_redactions = privacy_scrubber(raw_content)
            print(f"   -> [PII_REDACTED_STATS]: {file_path.name} - Phones: {phone_redactions}, Emails: {email_redactions}")

            # Step 2: Pass the scrubbed text to Ollama for structural classification
            system_prompt = (
                "You are a secure data processing engine. Analyze the scrubbed input log. "
                "Extract fields and return ONLY a strict JSON object with these keys: "
                "'entity_id' (transaction reference or ID if found, else null), "
                "'value_metric' (numerical transaction/cost values if found, else 0.0), "
                "'category' (e.g., 'Financial', 'System Error', 'General Text'), "
                "'summary' (a brief explanation of the text)."
                "Do not include conversational filler or markdown markers."
            )

            response = ollama.generate(
                model=model_name,
                prompt=f"Standardize this secure content: {safe_content}",
                system=system_prompt,
                options={"temperature": 0.0},
                keep_alive=0
            )

            ai_output = response['response'].strip()

            # Clean reasoning think blocks if using DeepSeek-R1 reasoning models
            if "<think>" in ai_output:
                think_end = ai_output.find("</think>")
                if think_end != -1:
                    ai_output = ai_output[think_end + 8:].strip()

            if ai_output.startswith("```json"):
                ai_output = ai_output.split("```json")[1].split("```")[0].strip()
            elif ai_output.startswith("```"):
                ai_output = ai_output.split("```")[1].split("```")[0].strip()

            parsed_data = json.loads(ai_output)
            parsed_data["normalized_timestamp"] = timestamp_str
            parsed_data["source_file"] = file_path.name
            parsed_data["contains_privacy_shield"] = True
            parsed_data["redacted_phones"] = phone_redactions
            parsed_data["redacted_emails"] = email_redactions

            # Save clean, anonymous JSON records
            output_clean.mkdir(parents=True, exist_ok=True)
            output_file = output_clean / f"secure_audited_{file_path.stem}.json"
            with open(output_file, "w", encoding="utf-8") as out_f:
                json.dump(parsed_data, out_f, indent=4)

            print(f"   -> [OLLAMA SUCCESS]: Securely saved {output_file.name}")
            file_path.unlink()

        except Exception as e:
            print(f"   -> [PRIVACY ERROR]: Failed processing {file_path.name}: {e}")

if __name__ == "__main__":
    args = parse_args()
    ai_secure_pipeline(args)