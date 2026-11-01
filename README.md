https://scamscope-ankita.streamlit.app/


# ScamScope
An AI agent that opens suspicious links in a safe cloud browser and checks if they are scams.

## What it does
- Checks domain age, https, suspicious words and fake brands
- Opens the page in a TinyFish cloud browser and checks if it asks for OTP, UPI PIN, card or Aadhaar
- Shows a 0-100 risk score, red flags and the real site

## How to run
1. pip install -r requirements.txt
2. Add your key in .streamlit/secrets.toml: TINYFISH_API_KEY = "your-key"
3. py -m streamlit run app.py

## Tech stack
Streamlit, TinyFish, python-whoiss
