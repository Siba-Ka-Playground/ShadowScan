import easyocr
import spacy
import re
import pyap
import os
import pillow_heif
from textblob import TextBlob
from thefuzz import fuzz

# Register HEIC opener to support iPhone photos
pillow_heif.register_heif_opener()

# Initialize NLP model
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("[!] Spacy model not found. Run: python -m spacy download en_core_web_sm")
    nlp = None

class SocialPostAnalyzer:
    """
    Pillar 1 (Advanced): Multi-Modal Analyzer
    Combines OCR (Computer Vision) and NLP to find risks in text and images simultaneously.
    Features: HEIC Support, PII Regex, Behavioral Triggers, India-Optimized Address Detection, and Corporate Entity Extraction.
    """
    def __init__(self):
        print("[*] Initializing Social Intelligence Engine (OCR + NLP)...")
        # Initialize OCR (set gpu=True if you have NVIDIA CUDA)
        self.reader = easyocr.Reader(['en'], gpu=False, verbose=False)
        
        # 1. VISUAL RISK KEYWORDS (Direct Leaks)
        self.sensitive_keywords = [
            "password", "login", "admin", "apikey", "secret", "token",
            "confidential", "internal use only", "finance", "database", "budget", 
            "private key", "ssh-rsa", "db_pass", "staff", "security"
        ]
        
        # 2. CONTEXT PHRASES (Behavioral/Ops Leaks in Caption)
        self.context_triggers = {
            "Insider Threat": ["hate my boss", "stupid company", "underpaid", "stealing", "copying files", "downloading db"],
            "Security Incident": ["server is down", "hacked", "breach", "forgot password", "reset access", "locked out"],
            "Infra Leak": ["migrating to", "aws bucket", "staging server", "prod db", "firewall rule", "version" , "database"],
            "Project Info": ["new project", "launching", "development", "release date", "sprint", "deadline"],
        }

        # 3. EDUCATION & CORPORATE KEYWORDS
        self.edu_keywords = ["university", "college", "school", "academy", "institute", "campus", "class of"]
        self.corp_keywords = ["google", "facebook", "amazon", "microsoft", "openai", "corp", "ltd", "inc", "technologies", "solutions", "private limited"]

        # 4. PII REGEX PATTERNS (Data Leaks)
        self.pii_patterns = {
            "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "Phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
            "IP Address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        }

        # 5. ADDRESS REGEX FALLBACK (India Optimized + No-Number Support)
        # Matches: "Sector 14", "Block B"
        self.regex_sector = r"\b(Sector|Phase|Block)\s\d+\b"
        
        # Matches: "MG Road", "Gandhi Marg", "5th Avenue" (1-4 words before suffix, no starting number required)
        self.regex_street = r"\b([a-zA-Z0-9\.\-]+\s){1,4}(Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Blvd|Way|Marg|Path|Chowk|Nagar|Colony|Salai)\b"

    def analyze_post(self, image_path, caption_text):
        """
        Analyzes Image + Caption to find leaks, location, sentiment, PII, and entities.
        """
        findings = []
        combined_text = ""
        image_text_full = ""

        # --- PHASE 1: VISUAL ANALYSIS (OCR) ---
        if image_path:
            # 1. Robust File Validation
            if not os.path.exists(image_path):
                 return [{"type": "Error", "data": f"File not found: {image_path}", "risk_level": "Info"}]
            
            # 2. Format Warning (HEIC)
            if image_path.lower().endswith('.heic'):
                pass # Supported via pillow_heif

            try:
                # 3. Run OCR
                ocr_results = self.reader.readtext(image_path, detail=0)
                image_text_full = " ".join(ocr_results)
                combined_text += " " + image_text_full
                
                # A. Check for Visual Keyword Leaks
                for word in self.sensitive_keywords:
                    if word in image_text_full.lower():
                        findings.append({
                            "type": "Visual Data Leak",
                            "data": f"Sensitive term '{word}' found inside image.",
                            "risk_level": "CRITICAL"
                        })
                
                # B. Check for PII in Image
                for pii_name, pattern in self.pii_patterns.items():
                    matches = re.findall(pattern, image_text_full)
                    for match in matches:
                        findings.append({
                            "type": "PII Leak", 
                            "data": f"{pii_name} visible in image: {match}", 
                            "risk_level": "High"
                        })

                # C. Detect Signage / Uniforms
                for text_segment in ocr_results:
                    if text_segment.isupper() and len(text_segment) > 4 and " " not in text_segment:
                         findings.append({
                            "type": "Potential Signage/Badge",
                            "data": f"Prominent text detected: '{text_segment}'",
                            "risk_level": "Info"
                        })

            except AttributeError:
                 findings.append({"type": "Error", "data": "Image failed to load. File may be corrupt or unsupported format.", "risk_level": "Low"})
            except Exception as e:
                findings.append({"type": "Error", "data": f"OCR Analysis Failed: {e}", "risk_level": "Low"})

        # --- PHASE 2: CAPTION ANALYSIS (NLP) ---
        if caption_text:
            text_lower = caption_text.lower()
            combined_text += " " + caption_text

            # A. Intent & Behavioral Analysis
            for category, phrases in self.context_triggers.items():
                for phrase in phrases:
                    if phrase in text_lower:
                        findings.append({
                            "type": f"Behavioral Risk ({category})",
                            "data": f"High-risk phrase detected: '{phrase}'",
                            "risk_level": "High" if category == "Insider Threat" else "Medium"
                        })

            # B. Sentiment Analysis
            blob = TextBlob(caption_text)
            polarity = blob.sentiment.polarity
            if polarity < -0.3: 
                level = "Medium"
                if polarity < -0.6: level = "High"
                findings.append({
                    "type": "Sentiment Analysis",
                    "data": f"Negative sentiment detected ({polarity:.2f}). Possible disgruntled user.",
                    "risk_level": level
                })

            # C. Fuzzy Logic on Caption (Typos)
            for word in caption_text.split():
                for target in self.sensitive_keywords:
                    ratio = fuzz.ratio(word.lower(), target)
                    if ratio > 85 and ratio < 100:
                        findings.append({
                            "type": "Fuzzy Pattern Match",
                            "data": f"Potential typo of sensitive word '{target}' found: '{word}'",
                            "risk_level": "Medium"
                        })

        # --- PHASE 3: ENVIRONMENTAL & ADVANCED INTEL (Combined Text) ---
        
        # A. Physical Address Detection (Advanced)
        found_address = False
        
        # Method 1: Strict Library Check (US/GB/CA/IN)
        try:
            for country_code in ['US', 'GB', 'CA', 'IN']:
                addresses = pyap.parse(combined_text, country=country_code)
                for addr in addresses:
                    findings.append({
                        "type": "Physical Location (Strict)", 
                        "data": f"Address found: {addr} ({country_code})", 
                        "risk_level": "CRITICAL"
                    })
                    found_address = True
        except: pass

        # Method 2: Regex Fallback (If strict check fails)
        if not found_address:
            # Check for "Sector/Block" pattern
            for match in re.finditer(self.regex_sector, combined_text, re.IGNORECASE):
                findings.append({
                    "type": "Physical Location (Zone)", 
                    "data": f"Possible Zone Found: {match.group(0)}", 
                    "risk_level": "High"
                })

            # Check for "Street/Road" pattern
            for match in re.finditer(self.regex_street, combined_text, re.IGNORECASE):
                findings.append({
                    "type": "Physical Location (Street)", 
                    "data": f"Possible Street Found: {match.group(0)}", 
                    "risk_level": "High"
                })

        # B. Entity Extraction (Schools + Big Tech)
        if nlp:
            doc = nlp(combined_text)
            
            for ent in doc.ents:
                # Check for Education OR Corporate keywords
                is_edu = any(k in ent.text.lower() for k in self.edu_keywords)
                is_corp = any(k in ent.text.lower() for k in self.corp_keywords)

                if ent.label_ == "ORG" and (is_edu or is_corp):
                    findings.append({
                        "type": "Organizational Intel", 
                        "data": f"Entity identified: {ent.text}", 
                        "risk_level": "High"
                    })

        if not findings:
             findings.append({"type": "Info", "data": "Social analysis clean. No obvious risks found.", "risk_level": "Low"})

        return findings