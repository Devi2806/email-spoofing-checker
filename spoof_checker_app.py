import dns.resolver
import re

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

def extract_domain(email):
    match = re.search(r'@([\w.-]+)', email)
    if match:
        return match.group(1)
    return None

# Example usage:
sender = input("Enter sender email: ")
domain = extract_domain(sender)
if domain:
    print("SPF:", get_spf(domain))
    print("DMARC:", get_dmarc(domain))
else:
    print("Invalid email format")
