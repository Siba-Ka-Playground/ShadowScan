# 🕵️ Shadow Scan: Offensive OSINT Framework

**Shadow Scan** is an autonomous intelligence engine designed for authorized Red Teaming. It fuses Computer Vision, NLP, and Static Code Analysis to detect risks in:

- 📸 **Images** (Geolocation, EXIF, Hidden Text)
- 🐙 **Code** (Hardcoded Secrets, API Keys, Vulnerable Configs)
- 🗣️ **Social Media** (Sentiment, Insider Threat, Organizational Intel)

## ⚡ Installation (Kali Linux / Linux)

```bash
# 1. Clone the repository
git clone https://github.com/Siba-Ka-Playground/ShadowScan.git
cd ShadowScan

# 2. Set up Virtual Environment (Recommended)
python3 -m venv venv
source venv/bin/activate

# 3. Install Dependencies
pip install .

# 4. Download NLP Models
python -m spacy download en_core_web_sm
python -m textblob.download_corpora
```
