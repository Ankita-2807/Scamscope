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
.score{padding:28px;border-radius:20px;text-align:center;color:white;margin:16px 0}
.score .num{font-size:72px;font-weight:700;line-height:1}
.score .txt{font-size:24px;font-weight:600}
</style>
""", unsafe_allow_html=True)

IMG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "images")


def show(name, container=None, **kw):
    path = os.path.join(IMG_DIR, name)
    if os.path.exists(path):
        (container or st).image(path, **kw)


show("banner.jpg", use_container_width=True)

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
        url = "https://" + url
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

# If the address has ?url=..., fill the box and check it automatically (once)
qp = st.query_params.get("url")
if qp and st.session_state.get("_qp_done") != qp:
    st.session_state["url"] = qp
    st.session_state["auto_check"] = True
    st.session_state["_qp_done"] = qp
url = st.text_input("Paste the link here", key="url", placeholder="for example sbi-kyc-update.xyz")

auto = st.session_state.pop("auto_check", False)
clicked = st.button("🔍 Check now", type="primary", use_container_width=True)

if (clicked or auto) and url:
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
        img = "risk_high.png"
        advice = "This link looks like a scam. Do not enter anything on it: no OTP, PIN, card number or Aadhaar."
    elif score >= 30:
        color, title = "#e09f3e", "SUSPICIOUS LINK"
        img = "risk_medium.png"
        advice = "Something looks wrong with this link. Open the real website yourself and check first."
    else:
        color, title = "#2a9d8f", "LOW RISK"
        img = "risk_low.png"
        advice = "No major danger found, but still never share your OTP or PIN with anyone."

    st.markdown(f'<div class="score" style="background:{color}"><div class="num">{score}/100</div>'
                f'<div class="txt">{title}</div></div>', unsafe_allow_html=True)
    st.progress(score / 100)
    ic, tx = st.columns([1, 3])
    show(img, ic, use_container_width=True)
    tx.info(f"🗣️ {advice}")

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

st.divider()
st.subheader("How it works")
s1, s2, s3 = st.columns(3)
for col, f, title, text in [
    (s1, "step_1.png", "1. Paste", "Paste a suspicious link."),
    (s2, "step_2.png", "2. Investigate", "We check the domain and open the page in a safe cloud browser."),
    (s3, "step_3.png", "3. Get a verdict", "See the risk score, red flags and the real site."),
]:
    show(f, col, width=110)
    col.markdown(f"**{title}**")
    col.write(text)

st.subheader("Scams we help you catch")
k1, k2, k3, k4 = st.columns(4)
for col, f, label in [
    (k1, "scam_kyc.png", "Fake KYC updates"),
    (k2, "scam_power.png", "Electricity threats"),
    (k3, "scam_job.png", "Fake jobs and scholarships"),
    (k4, "scam_clone.png", "Cloned bank and UPI pages"),
]:
    show(f, col, width=90)
    col.caption(label)

st.caption("Note: this is a risk estimate, not legal proof. Some scam sites block bots.")
st.caption("Built by Ankita | Team SOLOSYNTAX | Check before you click")
