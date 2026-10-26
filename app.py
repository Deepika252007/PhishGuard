import streamlit as st
from scanner import analyze_url

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="centered")

st.title("🛡️ PhishGuard")
st.subheader("Phishing URL Risk Analyzer")
st.write(
    "Enter a URL as text. PhishGuard checks for common suspicious patterns "
    "without visiting, fetching, or executing the submitted address."
)

with st.form("url_form"):
    url_text = st.text_input(
        "Website URL",
        placeholder="example.com or https://example.org/account",
        help="Use a URL you want to inspect. This app analyzes the text only.",
    )
    submitted = st.form_submit_button("Analyze URL")

if submitted:
    try:
        result = analyze_url(url_text)
        st.markdown(f"### Risk level: {result['risk']}")
        st.metric("Heuristic risk score", f"{result['score']} / 100")
        st.progress(result["score"])
        st.write("**Hostname:**", result["host"])
        st.write("**Normalized URL:**", result["normalized_url"])
        st.write("**Reasons:**")
        for reason in result["reasons"]:
            st.write(f"- {reason}")
    except (ValueError, TypeError) as exc:
        st.error(str(exc))

st.divider()
st.caption(
    "Educational tool only. A Low score does not prove a site is safe, "
    "and a High score does not prove it is malicious. Heuristic rules can "
    "produce false positives and false negatives."
)
