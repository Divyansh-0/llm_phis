import socket
from datetime import datetime

import OpenSSL
import requests
import whois
from bs4 import BeautifulSoup

import re
import pandas as pd
from joblib import load

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.schema import HumanMessage
import json

VOC = ['com', 'https:', 'www', 'html', 'http:', 'org', 'net', 'cn', 'php', 'index']

def check_url_exists(domain):
    
    model = load("decision_tree_model.pkl")
    dom = preprocess_dataset(domain)
    
    prediction = model.predict(dom.values)[0]
    return "phish" if prediction == 1 else "normal"


    
def fetch_tls_certificate(host, port=443):
    try:
        conn = socket.create_connection((host, port))
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
        sock = OpenSSL.SSL.Connection(context, conn)
        sock.set_connect_state()
        sock.set_tlsext_host_name(host.encode())
        sock.do_handshake()
        cert = sock.get_peer_certificate()
        cert_details = {
            "issuer": cert.get_issuer().get_components(),
            "subject": cert.get_subject().get_components(),
            "expiration_date": cert.get_notAfter().decode("ascii"),
        }
        sock.close()
        conn.close()
        return cert_details, None
    except Exception as e:
        if "getaddrinfo failed" in str(e) and not host.startswith("www."):
            return fetch_tls_certificate("www." + host, port)
        return None, str(e)
    except Exception as e:
        return None, str(e)
       

def analyze_whois(domain):
    analysis = {}
    try:
        w = whois.whois(domain)
        
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            
            if isinstance(creation_date, datetime):
                age = (datetime.now() - creation_date).days
                analysis['Domain_Age_In_Days'] = age
            else:
                analysis['Error_Message'] = "Invalid creation date format"
        
        if w.registrar:
            analysis['Domain_Registrar'] = w.registrar
        
        if w.country:
            analysis['Domain_Registered_Country'] = w.country

    except Exception as e:
        analysis['Error_Message'] = str(e)
        
    return analysis

def extract_elements(url):

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        forms_and_actions = []
        for form in soup.find_all('form'):
            forms_and_actions.append({
                "formHTML": str(form),
                "actionURL": form.get("action")
            })

        links = [a.get('href') for a in soup.find_all('a', href=True)]
        scripts = [str(script) for script in soup.find_all('script')]
        meta_info = ["{}={}".format(m.get('name'), m.get('content')) for m in soup.find_all('meta') if m.get('name')]
        title = soup.title.string if soup.title else ''
        text_content = soup.get_text()

        return {
            "title": title,
            "text_content": text_content,
            "forms_and_actions": forms_and_actions,
            "links": links,
            "meta_info": meta_info,
            "scripts": scripts
        }
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


from sklearn.feature_extraction.text import CountVectorizer

def num_digits(text) -> int:
    return len(re.findall('\d', text))

def num_dots(text) -> int:
    return len(re.findall('\.', text))

def num_bar(text) -> int:
    return len(re.findall('/', text))


def preprocess_dataset(url: str):
    tokens = url.replace('.', ' ').replace('/', ' ')
    

    vectorizer = load("vectorizer.pkl")
    row_vec = vectorizer.transform([tokens])
    row_df = pd.DataFrame(row_vec.toarray(), columns=VOC)
    row_df['dots'] = [num_dots(url)]
    row_df['bar'] = [num_bar(url)]
    row_df['len'] = [len(tokens)]
    row_df['digits'] = [num_digits(tokens)]
   

    return row_df


def llm_content_check(url):
    api_key = ""
    if not api_key:
        raise ValueError("GOOGLE_API_KEY environment variable is not set.")

    website_content = extract_elements(url)
    if not website_content:
        print("Failed to extract website content.")
        return

    llm = ChatGoogleGenerativeAI(model="gemini-pro", api_key=api_key)

    message = HumanMessage(
        content=(
            "You are acting as a Website Validator. "
            "You are acting as a Website Validator. Your task is to analyze the content of the provided website and determine whether it is legitimate or a scam.\n\n"
            '''Instructions:
               1. Carefully review the website content provided below, including its title, text content, links, forms, meta information, and scripts.
               2. Evaluate the legitimacy of the website based on these factors:
                  - Professional appearance and structure.
                  - Informative and relevant content.'''
            '''Provide the output strictly in JSON format with the following structure:
                {
                    "Result": "Scam or Legitimate",
                    "Reasons": [
                        "Reason 1",
                        "Reason 2",
                        "Reason 3",
                        "Reason 4",
                        "Reason 5"
                    ],
                    "Conclusion": "A one-liner conclusion summarizing your evaluation"
                }'''

            f"Website Content:\n{website_content}"
        )
    )

    response = llm.invoke([message])
    response = response.content
    print(response)

    if response.startswith("```json"):
        response = response[7:]
    if response.endswith("```"):
        response = response[:-3]
    parsed = json.loads(response)
    parsed = json.dumps(parsed, indent=4)
    return parsed
