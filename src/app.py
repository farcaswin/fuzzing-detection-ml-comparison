import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os

# Page configuration
st.set_page_config(page_title="Network Analyzer", layout="centered")

def load_resource(name):
    # Load serialized models or scalers using absolute paths
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base_path, "models", name)
    if os.path.exists(path):
        return joblib.load(path)
    return None

def preprocess_data(df, model_name, scaler, encoders):
    # Precise feature order extracted from trained model
    feature_cols = [
        'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 
        'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 
        'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 
        'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len', 
        'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 
        'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 
        'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
    ]
    
    # Create a copy to avoid modifying original dataframe
    X = df.copy()

    # Apply Label Encoding for categorical columns
    if encoders:
        for col in ['proto', 'service', 'state']:
            if col in X.columns and col in encoders:
                le = encoders[col]
                # Map unseen labels to -1 (similar to training logic)
                X[col] = X[col].astype(str).apply(lambda x: le.transform([x])[0] if x in le.classes_ else -1)

    # Align input with exact expected features and order
    X = X.reindex(columns=feature_cols, fill_value=0)
    
    # Handle infinite and missing values
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    
    # Apply scaling only for Logistic Regression
    if model_name == "logistic_regression" and scaler is not None:
        X = scaler.transform(X)
        
    return X

st.header("Network Traffic Analysis")
st.subheader("Fuzzer Attack Detection System")

# Sidebar configuration
st.sidebar.header("Settings")
model_option = st.sidebar.selectbox(
    "Select Model",
    ["Random Forest", "Logistic Regression", "Decision Tree", "XGBoost"]
)

# Map UI selection to filenames
model_map = {
    "Random Forest": "random_forest.joblib",
    "Logistic Regression": "logistic_regression.joblib",
    "Decision Tree": "decision_tree.joblib",
    "XGBoost": "xgboost.joblib"
}

# File upload handling
uploaded_file = st.file_uploader("Upload network traffic data (CSV format)", type="csv")

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    
    st.text("Input Data Preview:")
    st.dataframe(df.head(5))

    if st.button("Run Analysis"):
        model_file = model_map[model_option]
        model = load_resource(model_file)
        scaler = load_resource("scaler.joblib")
        encoders = load_resource("encoders.joblib")
        
        if model:
            # Execute preprocessing
            X_processed = preprocess_data(df, model_file.replace(".joblib", ""), scaler, encoders)
            
            # Perform inference
            predictions = model.predict(X_processed)
            probabilities = model.predict_proba(X_processed)[:, 1]
            
            # Display results for the first record in the batch
            is_attack = predictions[0] == 1
            confidence = probabilities[0] if is_attack else (1 - probabilities[0])
            
            st.divider()
            if is_attack:
                st.error("Status: Fuzzer Attack Detected")
                st.text(f"Confidence Level: {confidence:.2%}")
                st.text("Recommendation: Immediate source IP isolation required.")
            else:
                st.success("Status: Normal Traffic")
                st.text(f"Confidence Level: {confidence:.2%}")
        else:
            st.error(f"Model file {model_file} not found in models/ directory.")

else:
    st.info("Please upload a CSV file to begin the analysis process.")

st.sidebar.divider()
st.sidebar.caption("Trained on UNSW-NB15 Dataset")
st.sidebar.caption("Binary Classification: Normal vs Fuzzers")
