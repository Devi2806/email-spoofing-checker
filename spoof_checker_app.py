import streamlit as st
import dns.resolver
import re

# =========================
# Custom CSS Styling (Modern Dark Theme)
# =========================
custom_css = """
<style>
body {
    background-color: #0f0f0f;
    color: #f0f0f0;
}
[data-testid="stAppViewContainer"] {
    background-color: #0f0f0f;
}
h1, h2, h3, h4 {
    color: #00ffff;
}
div.stButton > button {
    background-color: #00bcd4;
    color: black;
    border-radius: 12px;
    padding: 0.6em 1.2em;
    font-weight: bold;
    border: none;
}
input {
    background-color: #1e1e1e;
    color: white;
}
code {
    background-color: #1e1e1e;
    color: #00e5ff;
}
.stTextInput > div > div > input {
    background-color: #1e1e1e;
    color: white;
    border: 2px solid #00bcd4;
    border-radius: 8px;
}
</style>
"""
st.markdown(custom_css, unsafe_allow_html=True)

# =========================
# Email Spoofing Functions
# =========================

def extract_domain(email):
    match = re.search(r'@([\w.-]+)', email)
    return match.group(1) if match else None

def get_spf(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode()
                if decoded.startswith("v=spf1"):
                    return decoded
        return "No SPF record found"
    except Exception as e:
        return f"SPF Error: {str(e)}"

def get_dmarc(domain):
    try:
        dmarc_domain = "_dmarc." + domain
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode()
                if decoded.startswith("v=DMARC1"):
                    return decoded
        return "No DMARC record found"
    except Exception as e:
        return f"DMARC Error: {str(e)}"

def classify_email(spf, dmarc, dkim="pass", header_match=True):
    score = 0
    if "v=spf1" in spf:
        score += 2
    else:
        score -= 2

    if "v=DMARC1" in dmarc:
        score += 2
    else:
        score -= 2

    if dkim == "pass":
        score += 2
    else:
        score -= 2

    if not header_match:
        score -= 3

    if score >= 4:
        return "🟢 Legit"
    elif score >= 1:
        return "🟡 Suspicious"
    else:
        return "🔴 Spoofed"

def get_verdict(spf, dmarc):
    if "v=spf1" in spf and "v=DMARC1" in dmarc:
        return "✅ Legitimate (SPF & DMARC configured)"
    elif "v=spf1" in spf:
        return "⚠️ Partial (Only SPF configured)"
    elif "v=DMARC1" in dmarc:
        return "⚠️ Partial (Only DMARC configured)"
    else:
        return "❌ Possibly Spoofed (No SPF/DMARC found)"

# =========================
# Streamlit UI
# =========================
st.title("💌 Email Spoofing Checker")
st.markdown("Check if an email address is spoofed using SPF & DMARC records.")

email = st.text_input("📥 Enter sender's email address:")

if email:
    domain = extract_domain(email)
    if domain:
        st.markdown(f"🌐 **Extracted Domain:** `{domain}`")
        with st.spinner("🔍 Verifying DNS records..."):
            spf_result = get_spf(domain)
            dmarc_result = get_dmarc(domain)

            # Simulated test values (customize for testing)
            dkim_result = "pass"
            header_match = True

            classification = classify_email(spf_result, dmarc_result, dkim_result, header_match)
            verdict = get_verdict(spf_result, dmarc_result)

        st.subheader("🚦 Final Classification:")
        st.info(classification)

        st.subheader("🧾 SPF Record:")
        st.code(spf_result)

        st.subheader("🧾 DMARC Record:")
        st.code(dmarc_result)

        st.subheader("🔎 Verdict:")
        st.info(verdict)
    else:
        st.error("🚫 Invalid email format")
