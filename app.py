import streamlit as st
import tldextract

from util import check_url_exists, fetch_tls_certificate, analyze_whois, llm_content_check

# Set page config
st.set_page_config(
    page_title="FraudLLM - Link Analysis",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Add a header and subtle styling
st.markdown("<h2 style='text-align: center;'>FraudLLM - Link Analysis</h2>", unsafe_allow_html=True)
st.write("Enter a website link to check its validity, TLS certificate details, and WHOIS information.")

link = st.text_input("Website Link (include http:// or https://)")

if st.button("Analyze"):
    if not link.startswith(("http://", "https://")):
        st.error("Invalid URL. Please include http:// or https://")
    else:
        with st.spinner("Analyzing..."):
            extracted = tldextract.extract(link)
            domain = f"{extracted.domain}.{extracted.suffix}"

            # Check URL existence
            url_exists = check_url_exists(domain)
            st.write("• URL Exists:", url_exists)

            # Fetch TLS certificate details
            cert_details, cert_error = fetch_tls_certificate(domain)
            if cert_error:
                st.write("• TLS Certificate Error:", cert_error)
            else:
                st.write("• TLS Certificate Details:", cert_details)

            # WHOIS
            whois_result = analyze_whois(link)
            st.write("• WHOIS Analysis:", whois_result)

            # Website content
            content_check = llm_content_check(link)
            st.write("• Website Content Analysis:", content_check)
