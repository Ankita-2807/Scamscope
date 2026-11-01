import json
import os
import time
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st
import whois
from tinyfish import TinyFish

st.set_page_config(page_title="ScamScope", page_icon="🛡️", layout="centered")

st.markdown("""
<style>
.hero{background:linear-gradient(135deg,#14213d,#2a9d8f);padding:32px;border-radius:20px;color:white;text-align:center;margin-bottom:20px}
.hero h1{font-size:46px;margin:0;color:white}
.hero p{font-size:18px;margin:8px 0 0 0;color:#e6f2f0}
.score{padding:28px;border-radius:20px;text-align:center;color:white;margin:16px 0}
.score .num{font-size:72px;font-weight:700;line-height:1}
.score .txt{font-size:24px;font-weight:600}
</style>
<div class="hero"><h1>🛡️ ScamScope</h1>
<p>Check before you click: is this link real or a scam?</p></div>
""", unsafe_allow_html=True)

BRANDS = {"sbi": "sbi.co.in", "hdfc": "hdfcbank.com", "icici": "icicibank.com",
          "paytm": "paytm.com", "phonepe": "phonepe.com"}
WORDS = ["kyc", "update", "verify", "bill", "otp", "blocked", "reward", "scholarship"]
BAD_END = (".xyz", ".top", ".click", ".buzz")


ASKS = {"asks_otp": "OTP", "asks_upi_pin": "UPI PIN", "asks_card_details": "card details",
        "asks_aadhaar": "Aadhaar", "asks_password": "password"}

GOAL = ("Open this page and only look at it. Do NOT type anything and do NOT submit any form. "
        "Return JSON with these keys: asks_otp, asks_upi_pin, asks_card_details, asks_aadhaar, "
        "asks_password (each true or false), claims_to_be (brand name it pretends to be, or null), "
        "summary (one short sentence about the page).")


def visit_page(url):
    try:
        try:
            key = st.secrets["TINYFISH_API_KEY"]
        except Exception:
            key = os.environ.get("TINYFISH_API_KEY")
        if not key:
            return None
        if not url.startswith("http"):
            url = "http://" + url
        client = TinyFish(api_key=key)
        resp = client.agent.run(url=url, goal=GOAL)
        res = resp.result
        if isinstance(res, str):
            res = json.loads(res)
        return res if isinstance(res, dict) else None
    except Exception:
        return None


def check(url):
    if not url.startswith("http"):
        url = "http://" + url
    p = urlparse(url)
    host = p.netloc.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    score, flags, official = 0, [], None

    if p.scheme != "https":
        score += 15
        flags.append("Link is not https (not secure)")
    if host.endswith(BAD_END):
        score += 10
        flags.append("Unusual domain ending (like .xyz) that is common in scams")
    for w in WORDS:
        if w in host:
            score += 20
            flags.append(f"Link contains the suspicious word '{w}'")
            break
    for brand, real in BRANDS.items():
        if brand in host and not (host == real or host.endswith("." + real)):
            score += 30
            official = real
            flags.append(f"This looks like {brand.upper()}, but the official site is {real}")
            break
    try:
        created = whois.whois(host).creation_date
        if isinstance(created, list):
            created = created[0]
        days = (datetime.now() - created.replace(tzinfo=None)).days
        if days < 30:
            score += 30
            flags.append(f"Domain is only {days} days old")
    except Exception:
        flags.append("Could not find the domain's age")
    return min(score, 100), flags, official


def set_url(value):
    st.session_state["url"] = value


st.write("**Try an example:**")
c1, c2 = st.columns(2)
c1.button("🚩 Fake link", on_click=set_url, args=("sbi-kyc-update.xyz",), use_container_width=True)
c2.button("✅ Real link", on_click=set_url, args=("google.com",), use_container_width=True)

url = st.text_input("Paste the link here", key="url", placeholder="for example sbi-kyc-update.xyz")

if st.button("🔍 Check now", type="primary", use_container_width=True) and url:
    with st.status("Investigation in progress...", expanded=True) as status:
        st.write("🌐 Reading the link...")
        time.sleep(0.8)
        st.write("📅 Checking how old the domain is...")
        score, flags, official = check(url)
        st.write("☁️ Opening the page in a safe cloud browser (this can take up to a minute)...")
        page = visit_page(url)
        if page:
            for k, label in ASKS.items():
                if page.get(k) is True:
                    score += 20
                    flags.append(f"The page asks for your {label}")
            score = min(score, 100)
            st.write("📝 About this page:", page.get("summary", ""))
        else:
            flags.append("Could not open the page (the site may block bots)")
        st.write("🔎 Looking for suspicious words and fake brands...")
        time.sleep(0.8)
        st.write("📊 Calculating the risk score...")
        time.sleep(0.6)
        status.update(label="Investigation complete", state="complete", expanded=False)

    if score >= 60:
        color, title = "#d62839", "HIGH RISK"
        advice = "This link looks like a scam. Do not enter anything on it: no OTP, PIN, card number or Aadhaar."
    elif score >= 30:
        color, title = "#e09f3e", "SUSPICIOUS LINK"
        advice = "Something looks wrong with this link. Open the real website yourself and check first."
    else:
        color, title = "#2a9d8f", "LOW RISK"
        advice = "No major danger found, but still never share your OTP or PIN with anyone."

    st.markdown(f'<div class="score" style="background:{color}"><div class="num">{score}/100</div>'
                f'<div class="txt">{title}</div></div>', unsafe_allow_html=True)
    st.progress(score / 100)
    st.info(f"🗣️ {advice}")

    if flags:
        st.subheader("🚩 Red flags")
        for f in flags:
            st.error(f)
    if official:
        st.success(f"The real site is: {official}")
        st.link_button("✅ Go to the real site", "https://" + official, use_container_width=True)

    with st.expander("😟 What if I already clicked the link?"):
        st.write("1. Do not share any OTP or PIN with anyone.")
        st.write("2. Call your bank right away and block your card or UPI.")
        st.write("3. Change all your passwords.")
        st.write("4. Call the cyber crime helpline **1930** or report at cybercrime.gov.in.")
        st.caption("Please verify the helpline and website details online before relying on them.")

st.caption("Note: this is a risk estimate, not legal proof. Some scam sites block bots.")