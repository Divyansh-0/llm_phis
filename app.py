import streamlit as st
import tldextract

from util import check_url_exists,fetch_tls_certificate, analyze_whois, extract_elements


def analyze_link(link: str) -> str:
    if not link.startswith(("http://", "https://")):
        return "Invalid URL. Please include http:// or https://"
    return f"Analysis result for {link}"

st.title("FraudLLM - Link Analysis")

link = st.text_input("Enter the website link:")
if st.button("Analyze"):
    result = analyze_link(link)
    st.write(result)
    extracted = tldextract.extract(link)

    domain = f"{extracted.domain}.{extracted.suffix}"
    print(domain)
    st.write("URL Exists:", check_url_exists(domain))
   
    cert_details, cert_error = fetch_tls_certificate(domain)
    if cert_error:
        st.write("TLS Certificate Error:", cert_error)
    else:
        st.write("TLS Certificate Details:", cert_details)
    st.write("WHOIS Analysis:", analyze_whois(link))
  
    st.write("Website Content:", extract_elements(link))
