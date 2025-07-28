# 📧 Email Spoofing Checker (Cybersecurity Internship Project)

This project is built to **analyze email spoofing** using DNS-based mechanisms such as **SPF**, **DKIM**, and **DMARC**. It checks whether an email sender’s domain is authenticated properly and classifies it as **Legit**, **Suspicious**, or **Spoofed**.

> ✅ Developed as part of the InternPro Cybersecurity Internship by **Devika Desai**  
> 🔒 Week 1–6 Completed | July 2025

---

## 🚀 Features

- ✅ SPF Record Lookup
- ✅ DMARC Record Lookup
- ✅ DMARC Policy Parsing (`p`, `rua`, `aspf`, `adkim`)
- ✅ Scoring Engine for Email Verdict
- ✅ Streamlit-based Web App with Dark Theme UI
- ✅ Final Classification: 🟢 Legit / 🟡 Suspicious / 🔴 Spoofed
- ✅ 📄 Help Page for Users
- ✅ Tooltip-style SPF/DKIM/DMARC explanation
- ✅ 🐞 Bug Log File
- ✅ 📸 Screenshot & README Documentation

---

## 🖥️ Project Structure

```bash
email_spoofing_checker/
│
├── spoof_checker_app.py        # Main Streamlit Web App
├── spoof_checker.py            # Core logic (verdict engine, DNS fetch)
├── help.html                   # Help instructions (shown in browser/sidebar)
├── README.md                   # Project documentation
├── requirements.txt            # All dependencies
├── bug_log.txt                 # Bug log and fixes
├── Screenshots/
│   ├── app_ui.png              # Screenshot for README
│   └── dmarc_fields_ui.png     # Optional extra screenshot
└── .venv/                      # Virtual environment (not committed)
 Installation Instructions

Clone the Repo
git clone https://github.com/Devi2806/email-spoofing-checker.git
cd email-spoofing-checker
Create a Virtual Environment
python -m venv .venv
source .venv/bin/activate  # Mac/Linux
.venv\Scripts\activate     # Windows
Install Required Libraries
pip install -r requirements.txt
Run the App
streamlit run spoof_checker_app.py
🧪 How to Use

Enter any email address (e.g., someone@gmail.com)
The app will:
Extract the domain (e.g., gmail.com)
Check SPF and DMARC DNS records
Parse DMARC policy fields
Assign scores and classify the result
Get the final verdict as:
🟢 Legit
🟡 Suspicious
🔴 Spoofed


🛡️ Technical Concepts

🔷 What is SPF?
SPF (Sender Policy Framework) is a DNS TXT record that lists authorized mail servers for a domain.
✅ Pass if IP matches.
❌ Fail if spoofed.

🔷 What is DKIM?
DKIM (DomainKeys Identified Mail) uses digital signatures in email headers to ensure message integrity.
→ Currently mocked in this app but will be implemented in advanced versions.

🔷 What is DMARC?
DMARC (Domain-based Message Authentication, Reporting, and Conformance) defines what to do if SPF/DKIM fails.
Key fields:

p= → Policy (none, quarantine, reject)
rua= → Reporting Email
aspf= → SPF alignment (relaxed/strict)
adkim= → DKIM alignment


📊 Scoring Logic

Mechanism	Condition	Score
SPF	Pass	+2
SPF	Fail / Not Found	-2
DMARC	Pass	+2
DMARC	Fail / Not Found	-2
DKIM	Mocked pass	+2
DKIM	Mocked fail	-2
Header Mismatch	Detected	-3
Classification:

🟢 ≥ 4 → Legit
🟡 1 to 3 → Suspicious
🔴 ≤ 0 → Spoofed
📸 Screenshots

Home Page	Results Page
🔍 Sample Test Emails

Email	Expected Result
test@gmail.com	🟢 Legit
admin@yahoo.com	🟡 Suspicious
fake@spoofytest.com	🔴 Spoofed
hello@	❌ Invalid
@domain.com	❌ Invalid
📘 Help Page

You can open the help.html file for:

Definitions of SPF, DKIM, DMARC
Example records and screenshots
How scoring is calculated
How to interpret verdicts
This is also linked in the sidebar of the Streamlit app.
🐞 Bug Log (bug_log.txt)

❌ Malformed email crashes app → ✅ Fixed with regex
❌ Timeout during DMARC lookup → ✅ Handled with try-except
❌ Missing DMARC field causes crash → ✅ Default fields used
❌ SPF field too long → ✅ Wrapped in st.code
❌ Help link was missing → ✅ Added in sidebar
👩‍💻 Author

Devika Desai
Intern @ InternPro (Cybersecurity)
July 2025 | Gujarat, India
🔗 GitHub: Devi2806

📄 License

MIT License


---

### ✅ Instructions:

- Copy the entire above content to your `README.md` file inside your project directory.
- Replace any placeholder paths for screenshots with the actual image filenames if needed.
- Then commit and push everything to GitHub.





