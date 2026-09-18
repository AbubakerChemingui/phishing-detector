"""
app.py - Streamlit web interface for Phishing Email Detection.
"""

import streamlit as st
import os
import sys

# Add the current directory to the path to import core
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core import (
    load_artifacts,
    analyze_email,
    MODEL,
    VECTORIZER
)

# Set page config
st.set_page_config(
    page_title="Phishing Email Detector",
    page_icon="🛡️",
    layout="centered"
)

# Load model and vectorizer (cached)
@st.cache_resource
def load_models():
    load_artifacts()
    return MODEL, VECTORIZER

# Load models
try:
    model, vectorizer = load_models()
    models_loaded = True
except Exception as e:
    st.error(f"Failed to load model artifacts: {e}")
    models_loaded = False

# App title and description
st.title("🛡️ Phishing Email Detector")
st.markdown(
    """
    This tool analyzes email content to detect phishing attempts.
    Paste an email below and click **Analyze** to get a prediction.
    """
)

# Sidebar for options
st.sidebar.header("Options")
harden = st.sidebar.checkbox(
    "Enable Hardening",
    value=False,
    help="Apply NFKC normalization, homoglyph replacement, leet-speak decode, and zero-width character stripping."
)
med_thresh = st.sidebar.slider(
    "Medium Threshold",
    min_value=0.0,
    max_value=1.0,
    value=0.65,
    step=0.01,
    help="Confidence threshold for medium risk alerts."
)
high_thresh = st.sidebar.slider(
    "High Threshold",
    min_value=0.0,
    max_value=1.0,
    value=0.85,
    step=0.01,
    help="Confidence threshold for high risk alerts."
)

# Text input
email_text = st.text_area(
    "Email Content",
    height=200,
    placeholder="Paste the full email here (including headers if available)..."
)

# Analyze button
if st.button("Analyze Email", type="primary"):
    if not models_loaded:
        st.error("Models are not loaded. Please check the console for errors.")
    elif not email_text.strip():
        st.warning("Please enter email content to analyze.")
    else:
        with st.spinner("Analyzing..."):
            try:
                result = analyze_email(
                    email_text,
                    med_thresh=med_thresh,
                    high_thresh=high_thresh,
                    harden_first=harden
                )
                
                # Display results
                st.subheader("Analysis Result")
                
                # Prediction and confidence
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Prediction", result["prediction"])
                with col2:
                    st.metric("Confidence", result["confidence_str"])
                
                # Alert tier
                st.info(f"**Alert Tier:** {result['alert']}")
                
                # Top contributing words
                if result["top_words"]:
                    st.subheader("Top Contributing Words")
                    for word, score in result["top_words"]:
                        st.text(f"{word}: {score:.5f}")
                else:
                    st.info("No top contributing words found.")
                    
            except Exception as e:
                st.error(f"Error during analysis: {e}")

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center'>
        <p>Phishing Email Detector • Built with Streamlit</p>
    </div>
    """,
    unsafe_allow_html=True
)