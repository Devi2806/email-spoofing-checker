import streamlit as st
import dns.resolver
import re
import streamlit.components.v1 as components


# =========================
# Custom CSS Styling (Modern Dark Theme)
# =========================
custom_css = """
<style>
body {
    background-color: #0f0f0f;
    color: #f0f0f0;
}
.stCodeBlock, .stMarkdown, .stSubheader {
    border: 1px solid #0097a7;
    border-radius: 8px;
    padding: 10px;
    background-color: #121212;
    margin-bottom: 20px;
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
def parse_dmarc_fields(dmarc_record):
    result = {"p": "N/A", "rua": "N/A", "aspf": "N/A", "adkim": "N/A"}
    try:
        fields = dmarc_record.split(";")
        for field in fields:
            field = field.strip()
            if field.startswith("p="):
                result["p"] = field.split("=")[1]
            elif field.startswith("rua="):
                result["rua"] = field.split("=")[1]
            elif field.startswith("aspf="):
                result["aspf"] = field.split("=")[1]
            elif field.startswith("adkim="):
                result["adkim"] = field.split("=")[1]
    except:
        pass
    return result

    # 🔍 Enhanced DMARC Parser - Extracts p=, rua=, aspf=, adkim=
def parse_dmarc_policy(domain):
    try:
        dmarc_domain = "_dmarc." + domain
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode()
                if decoded.startswith("v=DMARC1"):
                    policy_data = decoded.split(';')
                    parsed = {}
                    for item in policy_data:
                        item = item.strip()
                        if "=" in item:
                            key, value = item.split("=", 1)
                            parsed[key] = value
                    return parsed
        return {"error": "DMARC record not found"}
    except Exception as e:
        return {"error": str(e)}
# 🔄 Alignment checker based on DMARC's aspf and adkim settings
def check_alignment(from_domain, spf_domain, dkim_domain, aspf='r', adkim='r'):
    spf_align = (from_domain == spf_domain) if aspf == 's' else (from_domain.endswith(spf_domain))
    dkim_align = (from_domain == dkim_domain) if adkim == 's' else (from_domain.endswith(dkim_domain))
    return spf_align, dkim_align
# ✅ Final policy decision based on alignment and pass/fail
def apply_dmarc_policy(spf_passed, dkim_passed, spf_align, dkim_align, policy='none'):
    if spf_passed and spf_align:
        return "✅ Passed via SPF alignment"
    elif dkim_passed and dkim_align:
        return "✅ Passed via DKIM alignment"
    else:
        if policy == 'reject':
            return "❌ Rejected by DMARC policy"
        elif policy == 'quarantine':
            return "⚠️ Quarantined by DMARC policy"
        else:
            return "✅ Allowed (Policy = none)"


    
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
with st.expander("❓ What do SPF, DKIM, DMARC mean?"):
    st.markdown("""
    - **SPF (Sender Policy Framework):** Validates sending mail servers.
    - **DKIM (DomainKeys Identified Mail):** Adds cryptographic signature.
    - **DMARC (Domain-based Authentication):** Combines SPF and DKIM to determine legitimacy.
    """)


email = st.text_input("📥 Enter sender's email address:")

if email:
    domain = extract_domain(email)
    if domain:
        st.markdown(f"🌐 **Extracted Domain:** `{domain}`")
        with st.spinner("🔍 Verifying DNS records..."):
            spf_result = get_spf(domain)
            dmarc_result = get_dmarc(domain)
            dmarc_fields = parse_dmarc_fields(dmarc_result)


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

         # ✅ Paste this block :
        st.subheader("🔐 DMARC Policy Fields")
        st.write(f"**Policy (p):** `{dmarc_fields['p']}`")
        st.write(f"**Aggregate Reports (rua):** `{dmarc_fields['rua']}`")
        st.write(f"**SPF Alignment Mode (aspf):** `{dmarc_fields['aspf']}`")
        st.write(f"**DKIM Alignment Mode (adkim):** `{dmarc_fields['adkim']}`")

        st.subheader("🔎 Verdict:")
        st.success(verdict)
        
if st.sidebar.button("📘 Open Help Page"):
    with open("help.html", "r", encoding="utf-8") as file:
        help_content = file.read()
    st.subheader("📘 Help Page")
    components.html(help_content, height=800, scrolling=True)
    
