import streamlit as st
from dotenv import load_dotenv
import os

st.title(":blue[Unmasking Phishing: A Research Demo of an Email Scanner with Machine Learning & API Integration]")
load_dotenv()
hunter_api_key = os.getenv("HUNTER_API_KEY")
virus_total_apikey = os.getenv("VIRUSTOTAL_API_KEY")

st.title(":blue[Email Scanner Research Demo]")
st.subheader("By: Daniel Lambo")
st.subheader("Mentor: Dr Ed Pearson III")
#st.subheader("Mentor: Dr Ed Pearson III")\
st.header("PROBLEM:")
st.divider()
intro_statement = '''
Let's be honest, who actually reads every single email these days?
Our research-backed email scanner does the dirty work for you, 
identifying those sneaky phishing attempts that try to trick even the most vigilant email users. 
Because your time is too valuable to waste on suspicious emails.

With powerful algorithms, we:

-Analyze email links to detect and neutralize hidden viruses.

-Verify sender addresses to identify known scam sources.

-Examine email content to flag suspicious patterns and language.

Don’t let cybercriminals outsmart you—empower your inbox with smart, proactive protection!
'''
st.subheader(intro_statement)
st.header("INTRO: ", divider="gray")
st.write("This research paper provides an in-depth exploration of how to effectively identify and combat malicious emails. By leveraging extensive research, we analyze the key characteristics and behavioral patterns of such emails, uncovering the traits that make them deceptive and harmful. The study not only delves into theoretical frameworks but also presents a practical, real-time solution.\n \n Through a detailed code demonstration, we showcase a functional approach to detecting and mitigating these threats as they occur. Our work addresses the problem comprehensively, presenting insights into the challenges of identifying malicious emails and offering a robust, actionable framework for real-world applications.")
st.header("FIRST TELLTALE SIGN OF A SCAM: ", divider="gray")
st.subheader("The Email address itself :")
st.write("The first telltale sign of a scam often lies within the email address itself.\nHere's why:\nSpoofed Addresses: Scammers frequently forge the \"From\" field to mimic legitimate entities. This can involve subtle variations in the domain name, such as replacing letters with similar-looking characters (e.g., \"0\" instead of \"O\") or using homoglyphs (visually similar characters).   \n\n1.) Suspicious Formatting: Unusual characters, excessive length, or misspellings in the email address can also raise red flags. Legitimate organizations typically maintain professional and consistent email addresses.   \n\n2.) By carefully examining the sender's address for inconsistencies and irregularities, individuals can significantly reduce their risk of falling victim to phishing attacks.")
st.write("Citation : [https://hunter.io/api-documentation/v2]")
st.divider()
st.write("I leveraged the Hunter.io API to analyze email addresses for potential security threats.\n\nKey Functionality:\n\nExtracts Data: It queries the Hunter.io API to retrieve key data points about an email address, such as its validity, deliverability, and risk score.\n\nIdentifies Red Flags: The extracted data includes indicators like \"disposable\" emails (often used by spammers), \"accept_all\" servers (prone to spam), and block status (if the email is blacklisted).\n\nProvides Insights: By analyzing these data points, the code helps identify potential scams and fraudulent activities based on email address characteristics.")
import requests
import time

HUNTER_API_URL = "https://api.hunter.io/v2/email-verifier"
API_KEY = "c14d8bd13150d0b13b39a2fdbd1184e7c03f716e"  # Replace with your actual API key

def extract_key_data(email_address):
    # Prepare the request parameters
    params = {
        'email': email_address,
        'api_key': API_KEY
    }

    # Send the GET request to the Hunter.io API
    response = requests.get(HUNTER_API_URL, params=params)

    # Check if the request was successful
    if response.status_code == 200:
        data = response.json().get('data', {})

        # Extract key data points for fraud detection
        extracted_data = {
            'result': data.get('result', None),
            'email format': data.get('regexp', None),
            'mx_records': data.get('mx_records', None),
            'disposable': data.get('disposable', None),
            'smtp_check': data.get('smtp_check', None),
            'accept_all': data.get('accept_all', None),
            'block': data.get('block', None),
            'gibberish': data.get('gibberish', None),
            'score': data.get('score', None),
            'status': data.get('status', None),
            'webmail': data.get('webmail', None),
        }

        return extracted_data
    else:
        return {'error': 'Failed to verify email', 'status_code': response.status_code, 'details': response.text}

email_address=""
st.subheader("DEMO HERE↓")
email_address = st.text_input(":blue[Input Email Address: ]")
if email_address:
    st.write(extract_key_data(email_address))
    time.sleep(2)
    st.write("Note: Risky does not mean definitely Malicious. \n\nCheck the Hunter API documentation for an indepth explanation of all fields here: \n")
    st.write("https://hunter.io/api-documentation/v2#email-verifier")
    st.write("My code for this can be found here: https://github.com/DanielLambo/email-scanner")
else:
    st.write("Input email to start evaluation")
st.write("citation: [https://hunter.io/api-documentation/v2]")
st.divider()
st.write("Email addresses are a primary vector for phishing attacks. A 2023 report by [Source: Insert source here - e.g., Verizon Data Breach Investigations Report] found that phishing accounted for 36% of all data breaches, highlighting its significance.   \n\nKey Statistics:\nSpoofed Addresses: A significant portion of phishing emails utilize spoofed sender addresses, mimicking legitimate entities. The Anti-Phishing Working Group (APWG) reports a high prevalence of spoofed senders in phishing campaigns.   \n\nEmail Address Anomalies: Suspicious email addresses, characterized by unusual characters, excessive length, or misspellings, are often indicative of malicious activity.  ")
st.image("phishing_email.jpg",caption = "https://keepnetlabs.com/blog/10-easy-ways-to-detect-phishing-email", width = 590)
st.divider()
st.header(":blue[Malicious :red[Links?] But how do we even know]")
st.write("Email addresses are a big clue, but links are another major red flag. Let's dive deeper into what makes a link suspicious?")
st.divider()
st.write("Phishing attacks frequently involve emails containing malicious links designed to deceive recipients into divulging sensitive information or installing malware. Notably, 12.3% of employees have clicked on such links within phishing emails.  Additionally, nearly 1.2% of all emails sent are malicious, translating to approximately 3.4 billion phishing emails daily.  Alarmingly, 34% of users have engaged in actions that compromise security, such as clicking on malicious links, underscoring the persistent threat posed by these deceptive tactics. ")
st.divider()
st.write("I've developed a Python script that utilizes regular expressions to extract links from large text blocks and scans them for viruses using the VirusTotal API. This approach enhances email security by identifying and mitigating potential threats embedded within messages. \nFor those interested in implementing a similar solution, here's a basic outline of the process:\n1. **Extract URLs from Text**: Use Python's `re` module to identify and extract URLs from a given text block. Regular expressions can be crafted to match typical URL patterns. \n2. **Scan URLs for Viruses**: Leverage the VirusTotal API to analyze the extracted URLs. By sending these URLs to VirusTotal, you can receive reports indicating whether they are associated with any malicious activity. \nThis method provides an effective way to ensure your emails are free from malicious links, thereby safeguarding your personal information and digital assets.\nFor a practical demonstration of how to implement this, you might find the following video tutorial helpful:\n")
url_finder = '''url_pattern = r'(https?://(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}(?:/[^\\s]*)?)' 
# Find all URLs in the text
urls = re.findall(url_pattern, text)", language="python")
'''
st.code(url_finder, language="python")

st.write("Now, I use VirusTotal to scan extracted URLs for potential viruses. This is a demo of the code in action:\nProvide a block of text with a URL embedded within it (preferably one starting with https)\n\nThe code will extract all URLs from the text\nYou will only be notified if a virus is found in the scanned URLs.\nTo test the output with a malicious link, you can use this Kaggle dataset. Do not open the links from the dataset directly. Instead, copy and input them into the text field and observe the results.\nFor implementation, I utilized the VirusTotal API. You can find the documentation for the API here: [https://docs.virustotal.com/reference/overview].")
st.write(":blue[You can input this sample email message]")
st.write("This is a safe email with a safe link use it as a demo and input it into the text field to check")
benign_email = '''Dear Team,

I hope this email finds you well. 

I’m thrilled to announce the launch of our latest product! 

We've worked hard to ensure it meets the highest standards of quality and innovation.

For more details about the product features and release schedule,

 please visit our official website: https://www.youtube.com/

Your support and feedback are invaluable to us, and we look forward to your thoughts.

 Don’t hesitate to reach out with any questions!'''
st.code(benign_email)

st.write("Now this is a scam email that one may not initially be able to detect without the use of the virus scanner.\n :red[NOTE: DO NOT CLICK ANY OF THESE LINKS IN THE SCAM EMAIL]\n")
scam_mail = '''Subject: Urgent: Confirm Your Account Details Now!

Dear Valued User,

Our system has detected unusual activity on your account, and immediate action is required to secure it. Failure to respond within 24 hours may result in the suspension of your account.

To verify your account and restore full access,

please click on the secure link below and follow the instructions:

http://www.marketingbyinternet.com/mo/e56508df639f6ce7d55c81ee3fcd5ba8/

Please note: If you do not complete this verification, 

we will be forced to deactivate your account permanently.

Thank you for your prompt attention to this matter.

Sincerely,
Account Security Team
[Fake Company Name]

'''

st.code(scam_mail)


st.write(":blue[Input your email Text Here to Scan for Malicious URLs]")



import re
import requests
import base64
import json
# Sample text
import re
import requests
import base64
import json


def scan_url(text):
  """Scans URLs in the provided text for malicious content using VirusTotal API.

  Args:
      text: The text to scan for URLs.

  Prints warnings for malicious or suspicious URLs and analysis details if API request is successful.
  """

  # Updated regular expression to match more URL patterns
  url_pattern = r'(https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?)'

  # Find all URLs in the text
  urls = re.findall(url_pattern, text)

  st.write("Found URLs:", urls)
  if not urls:
    st.write("No URLs found in the text.")
    return

  # Replace with your actual VirusTotal API key
  api_key = "YOUR_API_KEY"

  for inputpayload in urls:
    # VirusTotal URL encoding: the URL needs to be base64-encoded
    encoded_url = base64.urlsafe_b64encode(inputpayload.encode()).decode().strip("=")

    # Prepare the API request
    url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    headers = {
        "accept": "application/json",
        "x-apikey": "99c8d18202fef4f35483fe492ad360d7bb576b34e793db348c9cbdf17001594a"
    }

    # Make a GET request to VirusTotal API
    response = requests.get(url, headers=headers)

    # Check if the response was successful (status code 200)
    if response.status_code == 200:
        data = response.json()  # Convert the JSON response to a Python dictionary

        # Extract relevant information from the response
        analysis_id = data["data"]["id"]
        attributes = data["data"]["attributes"]

        # You can access various details here; for example:
        scan_date = attributes.get("last_analysis_date", "No analysis date available")
        malicious_percentage = attributes.get("last_analysis_stats", {}).get("malicious", 0)
        suspicious_percentage = attributes.get("last_analysis_stats", {}).get("suspicious", 0)
        harmless_percentage = attributes.get("last_analysis_stats", {}).get("harmless", 0)

        st.write(f"Analysis ID: u-{analysis_id}")
        st.write(f"Last analysis date: {scan_date}")
        st.write(f"Malicious detections: {malicious_percentage}%")
        st.write(f"Suspicious detections: {suspicious_percentage}%")
        st.write(f"Harmless detections: {harmless_percentage}%")

        if malicious_percentage > 4:
          st.write(':red[Incoming email has malicious content !]')
          st.write(f'WARNING DO NOT OPEN THE LINK {inputpayload[:10]}*** ! MAlICIOUS CONTENT HAS BEEN DETECTED\n')
        elif suspicious_percentage > 4:
          st.write(f'Incoming email has suspicious content : {text}\n')
          st.write(f'WARNING verify sender and other details before opening{inputpayload[:11]}*** !')

    else:
        st.write(f"Error: {response.status_code}, {response.text}")



url_email = ""
url_email = st.text_input("")

if url_email:
    scan_url(url_email)
else:
    st.write("Input Email with URL here")
st.divider()
malicious_text ='''Malicious URLs in emails are a major cyb
ersecurity threat. 

According to a 2023 Verizon Data Breach Investigations Report, 

**36% of all data breaches** involved phishing, often leveraging malicious links. Such links can lead to financial loss, identity theft, or ransomware attacks, costing businesses an average of **$4.35 million per breach** globally (IBM Cost of a Data Breach Report, 2022).  

Learn more here: [Phishing and Email Security Insights](https://www.csoonline.com/article/3610271/phishing-statistics.html).  '''
st.write(malicious_text)
st.image("Example-of-malicious-URL (1).png", caption = "https://experteq.com/what-is-a-malicious-url-and-how-do-we-protect-against-them/")
st.image("Don&#039;t Click Poster.png", width = 598,caption="https://www.kent.edu/secureit/malicious-links")

st.divider()
st.header(":blue[Malicious Email :red[Content?] But how do we even know]")
st.write("Email addresses can provide significant clues, with links serving as another major red flag. Ultimately, leveraging machine learning to analyze email content is crucial for effectively identifying spam.")
st.divider()
st.write("We will begin by training a machine learning model using scikit-learn and a dataset categorized into two classes: phishing and non-phishing. The dataset is available at the following link.")
st.write("https://drive.google.com/file/d/1f-qsFeoXt0i0H4yUbQuX5-oLcD_swzIY/view?usp=sharing")
st.write("")
st.write("We employ resampling techniques, such as decreasing the number of instances in the majority class, to address class imbalance.")
resampling = '''# We will use undersapling technique 
Safe_Email = df[df["Email Type"]== "Safe Email"]
Phishing_Email = df[df["Email Type"]== "Phishing Email"]
Safe_Email = Safe_Email.sample(Phishing_Email.shape[0])'''
st.code(resampling, language = "python")
learning_method = '''I experimented with two different machine learning models: the Random Forest Classifier and the Support Vector Machine (SVM). The performance of these models yielded contrasting results:

Random Forest Classifier:

Accuracy: 0.931
The Random Forest Classifier achieved impressive results with an accuracy of 0.931.
It demonstrated a great ability to accurately classify both legitimate and phishing emails. 
The precision, recall, and F1 score provide additional insights into the model's performance on the various classes, which can be crucial for understanding the trade-offs involved.

Support Vector Machine (SVM):

Accuracy: 0.499
In contrast, the Support Vector Machine (SVM) exhibited significantly lower performance, with an accuracy of only 0.499. 
This suggests that the SVM model struggled to  differentiate between real and phishing emails in our dataset.

So I would proceed using the random forest classifier 
with an accuracy score of 0.931 compared to the accuracy score of the SVm which is 0.499

A better explanation of the code can be provided here:

https://colab.research.google.com/drive/1cPsis3TST5oWq-ecM8vH7w6VTJBfdWf2#scrollTo=38q6Hp1eEoJ9


'''
st.write(learning_method)


#https://www.kaggle.com/code/elnahas/phishing-email-detection-using-svm-rfc/notebook
import pandas as pd
import numpy as np
df= pd.read_csv("Phishing_Email.csv")
df.isna().sum()

df = df.dropna()
email_type_counts = df['Email Type'].value_counts()
Safe_Email = df[df["Email Type"]== "Safe Email"]
Phishing_Email = df[df["Email Type"]== "Phishing Email"]
Safe_Email = Safe_Email.sample(Phishing_Email.shape[0])
Data= pd.concat([Safe_Email, Phishing_Email], ignore_index = True)
# split the data into a metrix of features X and Dependent Variable y
X = Data["Email Text"].values
y = Data["Email Type"].values
# lets splitting Our Data
from sklearn.model_selection import train_test_split
X_train,x_test,y_train,y_test = train_test_split(X, y, test_size = 0.3, random_state = 0)

#Random Forest likely performed better because it is more suited to handling complex, noisy, and imbalanced data typical of phishing email datasets.
# Importing Libraries for the model ,Tfidf and Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline

# define the Classifier
classifier = Pipeline([("tfidf",TfidfVectorizer() ),("classifier",RandomForestClassifier(n_estimators=10))])# add another hyperparamters as U want

classifier.fit(X_train,y_train)
email = st.text_input("Enter an email to classify: \n")
if email:
# Predict the type of email (Safe or Phishing)
    prediction = classifier.predict([email])
    if prediction[0] == "Safe Email":
        st.write("The email is classified as: Safe Email")
    else:
        st.write("The email is classified as: Phishing Email")
    st.write("citing: https://www.kaggle.com/code/elnahas/phishing-email-detection-using-svm-rfc/notebook")



conclusion = '''
Here's a conclusion you can use for the website:  

---

### Conclusion: Staying Ahead of Malicious Threats  
In today's digital landscape, where cyber threats are evolving at an unprecedented rate, understanding and combating malicious emails is crucial for both individuals and organizations. Through this research demo, we explored multiple facets of email security:  

- **Email Address Analysis**: Leveraging tools like Hunter.io to identify suspicious patterns and anomalies in email addresses.  
- **Malicious Link Detection**: Using techniques such as regular expressions and VirusTotal API to identify and assess risky URLs within email content.  
- **Content-Based Machine Learning**: Training robust machine learning models to classify emails as phishing or safe, with tools like Random Forest Classifier yielding high accuracy.  

This comprehensive approach demonstrates that a combination of research, practical tools, and machine learning models can significantly mitigate the risks associated with phishing and other email-based attacks.  

As cyber threats continue to evolve, staying informed, vigilant, and equipped with the right tools is the best defense. By adopting these strategies and tools, you can take proactive steps to secure your digital environment and protect sensitive information.  

Thank you for exploring this research demo. We hope it inspires further innovation and collaboration in the field of cybersecurity.
'''
st.write(conclusion)
st.divider()
st.subheader("Future Improvements")
future_work = '''

Sophisticated Sentiment Analysis:

--Move beyond basic positive/negative sentiment.
Analyze for nuanced emotions like urgency, threats, and manipulative tactics (fear, greed, authority) within the email text.
Enhanced Contextual Awareness:

--Improve the model's understanding of the email's context by considering factors like sender-recipient relationships and past communication history.
User-Friendly Browser Extension:

--Develop a convenient browser extension for seamless integration into users' email workflows.
Model Training with URL & Address Data:

--Transition from relying solely on external APIs for URL and address scanning to incorporating these attributes as valuable features directly within the model's training process.
'''
st.write(future_work)
st.caption("Contact daniellambo77@gmail.com for further questions and inquiries")
