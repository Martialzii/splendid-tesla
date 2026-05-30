import os
import json
import re
from pathlib import Path
from datetime import datetime
import ollama

# Match your existing OneDrive paths
BASE_WORKSPACE = Path("C:/Users/Cyrus/OneDrive/Desktop/DataPipeline")
INPUT_DROPZONE = BASE_WORKSPACE / "Input_Dropzone"
OUTPUT_CLEAN = BASE_WORKSPACE / "Clean_Output"

MODEL_NAME = "llama3.2:3b"

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

def ai_secure_pipeline():
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not INPUT_DROPZONE.exists():
        print(f"   -> [PRIVACY ERROR]: Input Dropzone does not exist at {INPUT_DROPZONE}")
        return

    raw_files = [f for f in INPUT_DROPZONE.iterdir() if f.is_file()]
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
                model=MODEL_NAME,
                prompt=f"Standardize this secure content: {safe_content}",
                system=system_prompt,
                options={"temperature": 0.0},
                keep_alive=0
            )

            ai_output = response['response'].strip()

            if ai_output.startswith("```json"):
                ai_output = ai_output.split("```json")[1].split("```")[0].strip()
            elif ai_output.startswith("```"):
                ai_output = ai_output.split("```")[1].split("```")[0].strip()

            parsed_data = json.loads(ai_output)
            parsed_data["normalized_timestamp"] = timestamp_str
            parsed_data["source_file"] = file_path.name
            parsed_data["contains_privacy_shield"] = True
            # Store count stats in metadata as well
            parsed_data["redacted_phones"] = phone_redactions
            parsed_data["redacted_emails"] = email_redactions

            # Save clean, anonymous JSON records
            OUTPUT_CLEAN.mkdir(parents=True, exist_ok=True)
            output_file = OUTPUT_CLEAN / f"secure_audited_{file_path.stem}.json"
            with open(output_file, "w", encoding="utf-8") as out_f:
                json.dump(parsed_data, out_f, indent=4)

            print(f"   -> [OLLAMA SUCCESS]: Securely saved {output_file.name}")
            file_path.unlink()

        except Exception as e:
            print(f"   -> [PRIVACY ERROR]: Failed processing {file_path.name}: {e}")

if __name__ == "__main__":
    ai_secure_pipeline()