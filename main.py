import re

# Daftar pola regex phishing yang diperbarui
phishing_patterns = [
    r"\burgent\b", 
    r"\bprescription\s*required\b", 
    r"\brequired\s*(!|input)\b", 
    r"\bimmediate downioad\b", 
    r"\bimmediately\s*sell\b", 
    r"\baction\s*may\b", 
    r"\b(before|viagra)\s*action\b", 
    r"\balert\b", 
    r"\bupdate\s*your\s*information\b", 
    r"\bsecurity\s*check\b", 
    r"\bverify\s*your\s*account\b", 
    r"\bconfirm\s*your\s*password\b", 
    r"\bsuspicious\b", 
    r"\bfraudulent\b", 
    r"\bcompromised\b",  
    r"\blogin\b", 
    r"\bclick\s*here\b", 
    r"\b[A-Za-z0-9._%+-]{100,}\b",
    r"\battachment\b", 
    r"\bunauthorized\b", 
    r"\breactivate\b",
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(com|co|org)\b"
    r"\bhttp\b",
    r"\bprovide\s*your\s*credit\s*card\b", 
    r"\bdebit\b", 
    r"\bremove\b",
    r"\bfor\s*free\b",
    r"\bbest\s*deal\b",
    r"\bprize\b",
    r"\bunbelievable\b",
    r"\bspecial\s*promotion\b",
    r"\bporn\b",
    r"\bsex\b",
    r"\bhot\s*girls\b",
    r"\bhorny\b",
    r"\bxxx\b",
    r"\bsign\s*up\b",
    r"\bgrow\s*up\s*to\b",
    r"\bmaillist\s*verify\b", 
    r"\bverify\s*now\b", 
    r"\b(we|combination|intro|final)\s*offer\b", 
    r"\boffer\s*(latest|because|localized|includes|creative|refer|#|fair|going|manager|unsubscribe|only|--)\b",
    r"\b(material|right|running|download|order|filings|logo)\s*now\b", 
    r"\bnow\s*(qualify|deposited|for|furthered)\b",
    r"\b(duty|a|100%|in|obtaining|placing|includes?|hitch)\s*free\b", 
    r"\bfree\s*(zone|trading|zonedubai|bonus|grants?|quote|instant|personal|lifetime|application|goverment|no|quote|shipping|go)\b"
]

# Fungsi untuk mengecek email phishing menggunakan regex
def is_phishing(email_text):
    for pattern in phishing_patterns:
        if re.search(pattern, email_text, re.IGNORECASE):
            return True
    return False

# Main
input_email = input("Masukkan teks email: ")
if is_phishing(input_email):
    print("Hati-hati, email terdeteksi phishing!")
else:
    print("Email aman.")
