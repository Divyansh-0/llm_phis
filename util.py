import socket
from datetime import datetime
import dns.resolver
import OpenSSL
import requests
import whois
from bs4 import BeautifulSoup
from pyppeteer import launch
import asyncio
from joblib import load

def check_url_exists(domain):
    
    model = load("decision_tree_model.pkl")
    # Simple placeholder feature: domain length
    features = [len(domain)]
    
    prediction = model.predict([features])[0]
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
