import dns.resolver
import re

# SPF Lookup
def get_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode()
                if decoded.startswith("v=spf1"):
                    return decoded
        return "No SPF found"
    except:
        return "Error retrieving SPF"

# DMARC Lookup
def get_dmarc(domain):
    try:
        dmarc_domain = "_dmarc." + domain
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode()
                if decoded.startswith("v=DMARC1"):
                    return decoded
        return "No DMARC found"
    except:
        return "Error retrieving DMARC"
    
    
# Extract domain from email
def extract_domain(email):
    match = re.search(r'@([\w.-]+)', email)
    if match:
        return match.group(1)
    return None

# Verdict Engine
def get_verdict(spf, dmarc):
    if "v=spf1" in spf and "v=DMARC1" in dmarc:
        return "✅ Legitimate (SPF & DMARC configured)"
    elif "v=spf1" in spf:
        return "⚠️ Partial (Only SPF configured)"
    elif "v=DMARC1" in dmarc:
        return "⚠️ Partial (Only DMARC configured)"
    else:
        return "❌ Possibly Spoofed (No SPF/DMARC found)"

# Main program
sender = input("Enter sender email: ")
domain = extract_domain(sender)

if domain:
    spf_result = get_spf(domain)
    dmarc_result = get_dmarc(domain)
    verdict = get_verdict(spf_result, dmarc_result)

    print("SPF:", spf_result)
    print("DMARC:", dmarc_result)
    print("Verdict:", verdict)
else:
    print("Invalid email format")

st.markdown("---")
# 🧠 Parse DMARC fields for Week 4 Task
dmarc_fields = parse_dmarc_policy(domain)
policy = dmarc_fields.get("p", "none")
aspf = dmarc_fields.get("aspf", "r")
adkim = dmarc_fields.get("adkim", "r")

# 🧪 Simulate DKIM and SPF domains
spf_domain = domain
dkim_domain = domain
from_domain = domain

spf_passed = "v=spf1" in spf_result
dkim_passed = True  # You can simulate this or parse later

# 🔄 Check alignment
spf_align, dkim_align = check_alignment(from_domain, spf_domain, dkim_domain, aspf, adkim)

# ✅ Apply DMARC policy based on alignment
final_dmarc_action = apply_dmarc_policy(spf_passed, dkim_passed, spf_align, dkim_align, policy)

# 🖥️ Display parsed DMARC fields and alignment
st.subheader("📜 Parsed DMARC Policy:")
for key, value in dmarc_fields.items():
    st.markdown(f"- **{key.strip()}**: `{value.strip()}`")

st.subheader("🔧 Alignment Check Results:")
st.markdown(f"- SPF Alignment: {'✅ Yes' if spf_align else '❌ No'}")
st.markdown(f"- DKIM Alignment: {'✅ Yes' if dkim_align else '❌ No'}")

st.subheader("📢 DMARC Policy Verdict:")
st.success(final_dmarc_action)
