import pandas as pd
import re

# Me-load dataset
file_path = 'Phishing_Email.csv'
df = pd.read_csv(file_path)

# Mem-filter dataset
# Mengedrop semua email yang bukan merupakan safe email ataupun phishing email
df_filtered = df[df['Email Type'].isin(["Phishing Email", "Safe Email"])] 
# Mengubah NaN menjadi string kosong 
df_filtered['Email Text'] = df_filtered['Email Text'].fillna('') 

# Membuat list of dictionary dari dataframe
emails = df_filtered.to_dict(orient='records')


def find_sus_phrase(find):

    big_email = []
    safe = []
    for email in emails:
        if email['Email Type'] == "Phishing Email":
            big_email.append(email['Email Text'])
        else:
            safe.append(email['Email Text'])

    words = []
    safe_words = []

    # Split email
    split_phishing_words = []
    split_safe_words = []
    for email_text in big_email:
        split_phishing_words.extend(email_text.split())
    for email_text in safe:
        split_safe_words.extend(email_text.split())

    # Cari frasa di unsafe email
    for i in range(len(split_phishing_words)):
        if split_phishing_words[i].lower() == find:
            if i > 0:
                words.append(split_phishing_words[i-1] + " " + find)
            if i < len(split_phishing_words) - 1:
                words.append(find + " " + split_phishing_words[i+1])

    # Cari frasa di safe email
    for i in range(len(split_safe_words)):
        if split_safe_words[i].lower() == find:
            if i > 0:
                safe_words.append(split_safe_words[i-1] + " " + find)
            if i < len(split_safe_words) - 1:
                safe_words.append(find + " " + split_safe_words[i+1])

    # Cari yang sus
    unique_words = [word for word in words if word not in safe_words]

    # Count
    word_counts = {}
    for word in unique_words:
        if word in word_counts:
            word_counts[word] += 1
        else:
            word_counts[word] = 1

    # Sort 
    sorted_word_counts = sorted(word_counts.items(), key=lambda item: item[1], reverse=True)
    return sorted_word_counts

def find_sus_word(emails):
    big_email = []
    safe = []
    for email in emails:
        if email['Email Type'] == "Phishing Email":
            big_email.append(email['Email Text'])
        else:
            safe.append(email['Email Text'])

    words = []
    safe_words = []

    # Split email texts into words
    split_phishing_words = []
    split_safe_words = []
    for email_text in big_email:
        split_phishing_words.extend(email_text.split())
    for email_text in safe:
        split_safe_words.extend(email_text.split())

    # Find suspicious words (words in phishing emails but not in safe emails)
    unique_words = [word for word in split_phishing_words if word not in split_safe_words]

    # Count occurrences of each unique word
    word_counts = {}
    for word in unique_words:
        if word in word_counts:
            word_counts[word] += 1
        else:
            word_counts[word] = 1

    # Sort the word counts in descending order
    sorted_word_counts = sorted(word_counts.items(), key=lambda item: item[1], reverse=True)
    
    return sorted_word_counts

# result = find_sus_word(emails)
# for word, count in result:
#     print(f"{word}: {count}")

# sorted_word_counts = find_sus_phrase("update")
# for word_pair, count in sorted_word_counts:
#     print(f"{word_pair}: {count}")

# Daftar pola regex phishing
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

word_count = {
    r"\burgent\b" : 0, 
    r"\bprescription\s*required\b" : 0, 
    r"\brequired\s*(!|input)\b" : 0, 
    r"\bimmediate downioad\b" : 0, 
    r"\bimmediately\s*sell\b" : 0, 
    r"\baction\s*may\b" : 0, 
    r"\b(before|viagra)\s*action\b" : 0, 
    r"\balert\b" : 0, 
    r"\bverify\b" : 0, 
    r"\bupdate\s*your\s*information\b" : 0, 
    r"\bsecurity\s*check\b" : 0, 
    r"\bverify\s*your\s*account\b" : 0, 
    r"\bconfirm\s*your\s*password\b" : 0, 
    r"\bsuspicious\b" : 0, 
    r"\bfraudulent\b" : 0, 
    r"\bcompromised\b" : 0, 
    r"\blogin\b" : 0, 
    r"\bclick\s*here\b" : 0, 
    r"\b[A-Za-z0-9._%+-]{100,}\b" : 0, 
    r"\battachment\b" : 0, 
    r"\bunauthorized\b" : 0, 
    r"\breactivate\b" : 0,
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.^(com|co|org)\b" : 0,
    r"\bhttp\b" : 0,
    r"\bprovide\s*your\s*credit\s*card\b" : 0, 
    r"\bdebit\b" : 0, 
    r"\bremove\b" : 0,
    r"\bfor\s*free\b" : 0,
    r"\bbest\s*deal\b" : 0,
    r"\bprize\b" : 0,
    r"\bunbelievable\b" : 0,
    r"\bspecial\s*promotion\b" : 0,
    r"\bporn\b" : 0,
    r"\bsex\b" : 0,
    r"\bhot\s*girls\b" : 0,
    r"\bhorny\b" : 0,
    r"\bxxx\b" : 0,
    r"\bsign\s*up\b" : 0,
    r"\bgrow\s*up\s*to\b" : 0,
    r"\b(we|combination|intro|final)\s*offer\b" : 0, 
    r"\boffer\s*(latest|because|localized|includes|creative|refer|#|fair|going|manager|unsubscribe|only|--)\b" : 0,
    r"\b(material|right|running|download|order|filings|logo)\s*now\b" : 0, 
    r"\bnow\s*(qualify|deposited|for|furthered)\b" : 0,
    r"\bmaillist\s*verify\b" : 0, 
    r"\bverify\s*now\b" : 0,
    r"\b(duty|a|100%|in|obtaining|placing|includes?|hitch)\s*free\b" : 0, 
    r"\bfree\s*(zone|trading|zonedubai|bonus|grants?|quote|instant|personal|lifetime|application|goverment|no|quote|shipping|go)\b" : 0
}

# Fungsi untuk mengecek email phishing menggunakan regex
def is_phishing(email_text):
    sus_word = []
    isPhishing = False
    for pattern in phishing_patterns:
        if re.search(pattern, email_text, re.IGNORECASE):
            sus_word.append(pattern)
            isPhishing = True
    return (isPhishing, sus_word)

# Fungsi untuk memeriksa seluruh email
# Return list of tuple (email text, actual (dari dataset), predicted (dari is_phishing))
def check_email(emails):
    results = []
    for email in emails:
        email_text = email['Email Text']
        actual = email['Email Type']
        is_phishing_flag, sus_word = is_phishing(email_text)
        predicted = "Phishing Email" if is_phishing_flag else "Safe Email"
        results.append({'Email Text': email_text, 'Actual Label': actual, 'Predicted Label': predicted, 'Sus Word': sus_word})
    return results

# Fungsi untuk menghitung akurasi
def calculate_accuracy(results):
    correct_predictions = sum(1 for result in results if result['Actual Label'] == result['Predicted Label'])
    return correct_predictions / len(results)

# Analisis hasil

results = check_email(emails)
count1 = 0
count2 = 0
for i in results:
    if i['Predicted Label'] == "Phishing Email" and i['Actual Label'] == "Safe Email":
        for j in i['Sus Word']:
            word_count[j] += 1
        count1 += 1
    elif i['Predicted Label'] == "Safe Email" and i['Actual Label'] == "Phishing Email":
        count2 += 1

actual_safe_count = sum(1 for email in emails if email['Email Type'] == 'Safe Email')
actual_phishing_count = sum(1 for email in emails if email['Email Type'] == 'Phishing Email')

print()
print("Sebenarnya safe email namun terprediksi phishing:")
print(count1, "/", actual_safe_count)
print("Sebenarnya phishing email namun terprediksi safe:")
print(count2, "/", actual_phishing_count)

print()
print("Akurasi:", calculate_accuracy(results))

