import streamlit as st
import joblib
import numpy as np
import json
import pandas as pd
import time
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# Import the scanners
try:
    from wifi_scanner import WiFiScanner
except ImportError:
    st.error("⚠️ wifi_scanner.py not found. Please ensure it's in the same directory.")
    st.stop()

try:
    from preconnect_scanner import PreConnectWiFiScanner
except ImportError:
    st.warning("⚠️ preconnect_scanner.py not found. Pre-connect features will be disabled.")
    PreConnectWiFiScanner = None

# ---------------------------
# Page Configuration
# ---------------------------
st.set_page_config(
    page_title="WiFi Security Analyzer Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------
# Custom CSS for Modern UI
# ---------------------------
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    }
    
    .main-header h1 {
        margin: 0;
        font-size: 2.5rem;
        font-weight: 700;
    }
    
    .main-header p {
        margin: 0.5rem 0 0 0;
        font-size: 1.1rem;
        opacity: 0.9;
    }
    
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        border-left: 4px solid #667eea;
        margin-bottom: 1rem;
        transition: transform 0.2s;
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 6px 20px rgba(0,0,0,0.15);
    }
    
    .network-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #e8ecf1 100%);
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        transition: all 0.3s;
    }
    
    .stButton>button {
        border-radius: 10px;
        font-weight: 600;
        transition: all 0.3s;
        border: none;
        padding: 0.75rem 2rem;
    }
    
    .stButton>button:hover {
        transform: scale(1.05);
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
    
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------
# Helper Functions
# ---------------------------
def safe_load_model(uploaded_file, path):
    """Load model from file or path."""
    try:
        if uploaded_file is not None:
            model = joblib.load(uploaded_file)
            return model, None
        if path:
            model = joblib.load(path)
            return model, None
    except Exception as e:
        return None, str(e)
    return None, "No model provided."

def fill_scan_defaults(scan):
    """Fill default values for scan results."""
    defaults = {
        "Signal_Strength_dBm": -60.0,
        "Encryption_Type": "WPA2",
        "ARP_Anomalies": 0,
        "TLS_Cert_Validity": 1,
        "Captive_Portal": 0,
        "DNS_Latency_ms": 50.0,
        "Packet_Loss_%": 0.0,
        "Data_Leak_Attempts": 0
    }
    if scan is None:
        return defaults.copy()
    out = defaults.copy()
    for k in defaults:
        if k in scan and scan[k] is not None:
            out[k] = scan[k]
    return out

def build_feature_vector(scan_dict, model_feature_names=None):
    """Build feature vector for model prediction."""
    base = {
        "Signal_Strength_dBm": float(scan_dict.get("Signal_Strength_dBm", -60.0)),
        "ARP_Anomalies": int(scan_dict.get("ARP_Anomalies", 0)),
        "DNS_Latency_ms": float(scan_dict.get("DNS_Latency_ms", 50.0)),
        "Packet_Loss_%": float(scan_dict.get("Packet_Loss_%", 0.0)),
        "Data_Leak_Attempts": int(scan_dict.get("Data_Leak_Attempts", 0)),
        "Captive_Portal": int(scan_dict.get("Captive_Portal", 0))
    }
    
    enc = str(scan_dict.get("Encryption_Type", "WPA2")).upper()
    enc_dummies = {
        "Encryption_Type_OPEN": 1 if enc == "OPEN" else 0,
        "Encryption_Type_WEP": 1 if enc == "WEP" else 0,
        "Encryption_Type_WPA": 1 if enc == "WPA" else 0,
        "Encryption_Type_WPA2": 1 if enc == "WPA2" else 0,
        "Encryption_Type_WPA3": 1 if enc == "WPA3" else 0
    }
    
    tls_valid = 1 if int(scan_dict.get("TLS_Cert_Validity", 1)) == 1 else 0
    tls_invalid = 0 if tls_valid == 1 else 1
    tls_dummies = {"TLS_Valid": tls_valid, "TLS_Invalid": tls_invalid}
    
    merged = {}
    merged.update(base)
    merged.update(enc_dummies)
    merged.update(tls_dummies)
    
    if model_feature_names is not None:
        vec = []
        for feat in model_feature_names:
            val = merged.get(feat, merged.get(feat.replace("-", "_"), 0))
            vec.append(float(val))
        return np.array([vec])
    else:
        ordered = [
            base["Signal_Strength_dBm"], base["ARP_Anomalies"], base["DNS_Latency_ms"],
            base["Packet_Loss_%"], base["Data_Leak_Attempts"],
            enc_dummies["Encryption_Type_WEP"], enc_dummies["Encryption_Type_WPA"],
            enc_dummies["Encryption_Type_WPA2"], enc_dummies["Encryption_Type_WPA3"],
            tls_invalid, tls_valid, merged["Captive_Portal"]
        ]
        return np.array([ordered])

def create_gauge_chart(value, title):
    """Create a modern gauge chart."""
    if value >= 70:
        color = "#FF6B6B"
    elif value >= 40:
        color = "#FFD93D"
    else:
        color = "#6BCF7F"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': title, 'font': {'size': 20, 'color': '#333'}},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkgray"},
            'bar': {'color': color},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 40], 'color': '#E8F5E9'},
                {'range': [40, 70], 'color': '#FFF9C4'},
                {'range': [70, 100], 'color': '#FFEBEE'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 80
            }
        }
    ))
    
    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=50, b=20),
        paper_bgcolor='rgba(0,0,0,0)',
        font={'color': "#333", 'family': "Arial"}
    )
    
    return fig

def create_radar_chart(scan_data):
    """Create radar chart for network metrics."""
    categories = ['Signal', 'Encryption', 'Latency', 'Packet Loss', 'Security']
    
    signal_score = min(100, max(0, (scan_data.get('Signal_Strength_dBm', -70) + 90) * 1.67))
    
    enc = scan_data.get('Encryption_Type', 'WPA2').upper()
    enc_scores = {"WPA3": 100, "WPA2": 80, "WPA": 50, "WEP": 20, "OPEN": 0}
    encryption_score = enc_scores.get(enc, 60)
    
    latency_score = max(0, 100 - (scan_data.get('DNS_Latency_ms', 50) / 5))
    packet_loss_score = max(0, 100 - (scan_data.get('Packet_Loss_%', 0) * 10))
    
    security_score = 100
    if scan_data.get('ARP_Anomalies', 0) > 0:
        security_score -= 30
    if scan_data.get('TLS_Cert_Validity', 1) == 0:
        security_score -= 30
    if scan_data.get('Captive_Portal', 0) == 1:
        security_score -= 20
    
    values = [signal_score, encryption_score, latency_score, packet_loss_score, security_score]
    
    fig = go.Figure(data=go.Scatterpolar(
        r=values + [values[0]],
        theta=categories + [categories[0]],
        fill='toself',
        fillcolor='rgba(102, 126, 234, 0.3)',
        line=dict(color='#667eea', width=3)
    ))
    
    fig.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
        showlegend=False,
        height=400,
        margin=dict(l=80, r=80, t=40, b=40),
        paper_bgcolor='rgba(0,0,0,0)'
    )
    
    return fig

# ---------------------------
# Header
# ---------------------------
st.markdown("""
<div class="main-header">
    <h1>🛡️ WiFi Security Analyzer Pro</h1>
    <p>Advanced Network Security Assessment & Threat Detection System</p>
</div>
""", unsafe_allow_html=True)

# ---------------------------
# Sidebar
# ---------------------------
with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    
    st.markdown("---")
    st.markdown("#### 🤖 Post-Connect Model")
    
    model_source = st.radio("Load model from:", ("Local path", "Upload .pkl"), index=0)
    uploaded_model = None
    model_path = None
    
    if model_source == "Upload .pkl":
        uploaded_model = st.file_uploader("Upload ML model", type=["pkl"])
    else:
        model_path = st.text_input("Model path", value="postconnect_model.pkl")
    
    st.markdown("---")
    st.markdown("#### 🔧 Scan Parameters")
    
    with st.expander("🎯 Advanced Settings", expanded=False):
        arp_timeout = st.slider("ARP timeout (s)", 1, 10, 3)
        dns_tests = st.slider("DNS tests", 1, 5, 3)
        ping_count = st.slider("Ping count", 1, 20, 5)
    
    st.markdown("---")
    st.markdown("#### 📊 Statistics")
    col1, col2 = st.columns(2)
    with col1:
        total_scans = st.session_state.get('total_scans', 0)
        st.metric("Total Scans", total_scans)
    with col2:
        threats = st.session_state.get('threats_detected', 0)
        st.metric("Threats", threats)
    
    st.markdown("---")
    st.info("💡 **Tip:** Always use a VPN when connecting to public WiFi networks.")

# ---------------------------
# Main Content - Tabs
# ---------------------------
if PreConnectWiFiScanner is not None:
    tab1, tab2, tab3 = st.tabs(["🔍 Pre-Connect Scan", "📡 Post-Connect Analysis", "📈 Reports & History"])
else:
    tab2, tab3 = st.tabs(["📡 Post-Connect Analysis", "📈 Reports & History"])
    tab1 = None

# ---------------------------
# TAB 1: Pre-Connect Scan
# ---------------------------
if tab1 is not None:
    with tab1:
        st.markdown("## 🔍 Pre-Connection Network Scanner")
        st.markdown("Scan available WiFi networks **before connecting** to identify potential security risks.")
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            if st.button("🚀 Scan Available Networks", use_container_width=True, type="primary"):
                with st.spinner("🔎 Scanning for WiFi networks..."):
                    try:
                        scanner = PreConnectWiFiScanner()
                        networks = scanner.scan_and_analyze_all()
                        st.session_state['preconnect_results'] = networks
                        st.session_state['total_scans'] = st.session_state.get('total_scans', 0) + 1
                        
                        if networks:
                            st.success(f"✅ Found {len(networks)} networks!")
                            time.sleep(0.5)
                            st.rerun()
                        else:
                            st.warning("⚠️ No networks found. Please check your WiFi adapter.")
                    except Exception as e:
                        st.error(f"❌ Scan failed: {e}")
        
        with col2:
            if st.button("🔄 Refresh", use_container_width=True):
                if 'preconnect_results' in st.session_state:
                    del st.session_state['preconnect_results']
                st.rerun()
        
        with col3:
            if 'preconnect_results' in st.session_state and st.session_state['preconnect_results']:
                networks_data = st.session_state['preconnect_results']
                df = pd.DataFrame(networks_data)
                csv = df.to_csv(index=False)
                st.download_button("📥 Export", data=csv, file_name="preconnect_scan.csv", mime="text/csv")
        
        st.markdown("---")
        
        if 'preconnect_results' in st.session_state and st.session_state['preconnect_results']:
            networks = st.session_state['preconnect_results']
            
            # Summary metrics
            st.markdown("### 📊 Scan Summary")
            col1, col2, col3, col4 = st.columns(4)
            
            high_risk = sum(1 for n in networks if n['risk_level'] == 'HIGH')
            medium_risk = sum(1 for n in networks if n['risk_level'] == 'MEDIUM')
            low_risk = sum(1 for n in networks if n['risk_level'] == 'LOW')
            
            with col1:
                st.metric("🔴 High Risk", high_risk)
            with col2:
                st.metric("🟡 Medium Risk", medium_risk)
            with col3:
                st.metric("🟢 Low Risk", low_risk)
            with col4:
                st.metric("📡 Total Networks", len(networks))
            
            st.markdown("---")
            
            # Network cards
            st.markdown("### 🌐 Detected Networks")
            
            for network in networks:
                risk_color = {
                    'HIGH': '#ff6b6b',
                    'MEDIUM': '#ffd93d',
                    'LOW': '#6bcf7f'
                }[network['risk_level']]
                
                with st.container():
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.markdown(f"""
                        <div style="background: linear-gradient(135deg, #f5f7fa 0%, #e8ecf1 100%); 
                                    padding: 1.5rem; border-radius: 12px; margin: 1rem 0; 
                                    border-left: 5px solid {risk_color};">
                            <h3 style="margin: 0; color: #333;">📶 {network['ssid']}</h3>
                            <p style="color: #666; margin: 0.5rem 0 0 0;">
                                <strong>Signal:</strong> {network['signal_strength']:.1f} dBm | 
                                <strong>Encryption:</strong> {network['encryption']} | 
                                <strong>Channel:</strong> {network.get('channel', 'N/A')}
                            </p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.markdown("**⚠️ Risk Factors:**")
                        for factor in network['risk_factors']:
                            st.markdown(f"- {factor}")
                        
                        st.info(network['recommendation'])
                    
                    with col2:
                        fig = create_gauge_chart(network['risk_score'], "Risk Score")
                        st.plotly_chart(fig, use_container_width=True)
                    
                    st.markdown("---")

# ---------------------------
# TAB 2: Post-Connect Analysis
# ---------------------------
with tab2:
    st.markdown("## 📡 Post-Connection Deep Analysis")
    st.markdown("Perform comprehensive security analysis of your **currently connected** network using ML.")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        if st.button("🔬 Analyze Current Network", use_container_width=True, type="primary"):
            # Load model
            model, err = safe_load_model(uploaded_model, model_path)
            if err:
                st.error(f"❌ Model load error: {err}")
                st.stop()
            if model is None:
                st.error("⚠️ No model loaded. Please configure model in sidebar.")
                st.stop()
            
            scanner = WiFiScanner()
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                status_text.info("🔍 Scanning network...")
                progress_bar.progress(20)
                raw_scan = scanner.scan_full_network()
                
                status_text.info("🔧 Processing data...")
                progress_bar.progress(50)
                scan = fill_scan_defaults(raw_scan)
                
                model_feature_names = None
                if hasattr(model, "feature_names_in_"):
                    model_feature_names = list(model.feature_names_in_)
                
                status_text.info("🤖 Running ML analysis...")
                progress_bar.progress(70)
                
                feature_vector = build_feature_vector(scan, model_feature_names=model_feature_names)
                probs = model.predict_proba(feature_vector)[0]
                preds = model.predict(feature_vector)[0]
                
                labels = model.classes_ if hasattr(model, "classes_") else np.array([0, 1])
                if 1 in labels:
                    suspicious_idx = int(np.where(labels == 1)[0][0])
                else:
                    suspicious_idx = 1 if len(probs) > 1 else 0
                
                risk_score = float(probs[suspicious_idx]) * 100.0
                
                progress_bar.progress(100)
                status_text.success("✅ Analysis complete!")
                time.sleep(0.5)
                
                st.session_state['scan'] = scan
                st.session_state['pred'] = int(preds)
                st.session_state['risk_score'] = risk_score
                st.session_state['probs'] = probs
                st.session_state['scan_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                st.session_state['total_scans'] = st.session_state.get('total_scans', 0) + 1
                
                if int(preds) == 1:
                    st.session_state['threats_detected'] = st.session_state.get('threats_detected', 0) + 1
                
                progress_bar.empty()
                status_text.empty()
                st.rerun()
                
            except Exception as e:
                st.error(f"❌ Analysis failed: {e}")
    
    with col2:
        if st.button("🔄 Clear Results", use_container_width=True):
            keys_to_remove = ['scan', 'pred', 'risk_score', 'probs', 'scan_time']
            for key in keys_to_remove:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()
    
    st.markdown("---")
    
    # Display results
    if 'scan' in st.session_state:
        scan = st.session_state['scan']
        risk_score = st.session_state['risk_score']
        pred = st.session_state['pred']
        scan_time = st.session_state.get('scan_time', 'N/A')
        
        # Risk assessment header
        if pred == 1 and risk_score > 50:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%); 
                        padding: 2rem; border-radius: 15px; color: white; text-align: center; margin: 2rem 0;">
                <h2 style="margin: 0;">⚠️ SUSPICIOUS NETWORK DETECTED</h2>
                <p style="font-size: 1.3rem; margin: 0.5rem 0;">Risk Level: {risk_score:.1f}%</p>
                <p style="margin: 0;">Scan Time: {scan_time}</p>
            </div>
            """, unsafe_allow_html=True)
        elif 25 < risk_score <= 50:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, #ffd93d 0%, #f6c744 100%); 
                        padding: 2rem; border-radius: 15px; color: #333; text-align: center; margin: 2rem 0;">
                <h2 style="margin: 0;">⚠️ POTENTIALLY RISKY NETWORK</h2>
                <p style="font-size: 1.3rem; margin: 0.5rem 0;">Risk Level: {risk_score:.1f}%</p>
                <p style="margin: 0;">Scan Time: {scan_time}</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, #6bcf7f 0%, #51cf66 100%); 
                        padding: 2rem; border-radius: 15px; color: white; text-align: center; margin: 2rem 0;">
                <h2 style="margin: 0;">✅ NETWORK APPEARS SAFE</h2>
                <p style="font-size: 1.3rem; margin: 0.5rem 0;">Risk Level: {risk_score:.1f}%</p>
                <p style="margin: 0;">Scan Time: {scan_time}</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Visualizations
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🎯 Risk Assessment")
            fig_gauge = create_gauge_chart(risk_score, "Overall Risk Score")
            st.plotly_chart(fig_gauge, use_container_width=True)
        
        with col2:
            st.markdown("### 📊 Network Profile")
            fig_radar = create_radar_chart(scan)
            st.plotly_chart(fig_radar, use_container_width=True)
        
        st.markdown("---")
        
        # Detailed metrics
        st.markdown("### 📋 Detailed Metrics")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("📶 Signal Strength", f"{scan['Signal_Strength_dBm']:.1f} dBm")
            st.metric("🔐 Encryption", scan["Encryption_Type"])
        with col2:
            st.metric("🌐 DNS Latency", f"{scan['DNS_Latency_ms']:.1f} ms")
            st.metric("📉 Packet Loss", f"{scan['Packet_Loss_%']:.1f}%")
        with col3:
            st.metric("🚨 ARP Anomalies", scan["ARP_Anomalies"])
            st.metric("💾 Data Leaks", scan["Data_Leak_Attempts"])
        with col4:
            tls_text = "✅ Valid" if int(scan.get("TLS_Cert_Validity", 1)) == 1 else "❌ Invalid"
            st.metric("🔒 TLS Certs", tls_text)
            portal_text = "⚠️ Yes" if int(scan.get("Captive_Portal", 0)) == 1 else "✅ No"
            st.metric("🌐 Captive Portal", portal_text)
        
        st.markdown("---")
        
        # Security recommendations
        st.markdown("### 🛡️ Security Analysis & Recommendations")
        
        reasons = []
        recommendations = []
        
        enc = scan.get("Encryption_Type", "WPA2").upper()
        if enc in ("OPEN", "WEP"):
            reasons.append("🔓 Weak or no encryption detected")
            recommendations.append("Avoid transmitting sensitive data. Use VPN.")
        
        if scan.get("ARP_Anomalies", 0) > 0:
            reasons.append("🚨 ARP spoofing detected (possible MITM attack)")
            recommendations.append("Disconnect immediately. Network may be compromised.")
        
        if int(scan.get("TLS_Cert_Validity", 1)) == 0:
            reasons.append("🔒 Invalid TLS certificates detected")
            recommendations.append("SSL/TLS interception possible. Avoid sensitive transactions.")
        
        if int(scan.get("Captive_Portal", 0)) == 1:
            reasons.append("🌐 Captive portal present")
            recommendations.append("Traffic may be monitored. Use encrypted connections.")
        
        if float(scan.get("Packet_Loss_%", 0)) > 5.0:
            reasons.append(f"📉 High packet loss ({scan.get('Packet_Loss_%', 0):.1f}%)")
            recommendations.append("Network instability detected. May indicate interference or attack.")
        
        if float(scan.get("DNS_Latency_ms", 0)) > 200:
            reasons.append(f"🐌 High DNS latency ({scan.get('DNS_Latency_ms', 0):.1f} ms)")
            recommendations.append("Slow DNS resolution. Possible DNS hijacking or poor network.")
        
        if int(scan.get("Data_Leak_Attempts", 0)) > 0:
            reasons.append("📤 Unencrypted data transmission detected")
            recommendations.append("Enable HTTPS-only mode in browser. Use encrypted protocols.")
        
        if not reasons:
            reasons.append("✅ No major security issues detected")
            recommendations.append("Network appears secure. Continue with normal security practices.")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🔍 Issues Found")
            for reason in reasons:
                st.markdown(f"- {reason}")
        
        with col2:
            st.markdown("#### 💡 Recommendations")
            for rec in recommendations:
                st.markdown(f"- {rec}")
        
        st.markdown("---")
        
        # Export options
        st.markdown("### 📥 Export Results")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            csv_data = pd.DataFrame([scan]).to_csv(index=False)
            st.download_button(
                "📊 Download CSV",
                data=csv_data,
                file_name=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        with col2:
            json_data = json.dumps({
                "scan_time": scan_time,
                "scan_data": scan,
                "is_suspicious": bool(pred),
                "risk_score": risk_score,
                "risk_factors": reasons,
                "recommendations": recommendations
            }, indent=4)
            st.download_button(
                "📄 Download JSON",
                data=json_data,
                file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
        
        with col3:
            report = f"""WiFi Security Analysis Report
{'='*50}

Scan Time: {scan_time}
Risk Score: {risk_score:.1f}%
Classification: {"SUSPICIOUS" if pred == 1 else "SAFE"}

Network Details:
- Signal Strength: {scan['Signal_Strength_dBm']:.1f} dBm
- Encryption: {scan['Encryption_Type']}
- DNS Latency: {scan['DNS_Latency_ms']:.1f} ms
- Packet Loss: {scan['Packet_Loss_%']:.1f}%
- ARP Anomalies: {scan['ARP_Anomalies']}
- TLS Validity: {"Valid" if scan.get('TLS_Cert_Validity', 1) == 1 else "Invalid"}
- Captive Portal: {"Yes" if scan.get('Captive_Portal', 0) == 1 else "No"}
- Data Leak Attempts: {scan['Data_Leak_Attempts']}

Security Issues:
{chr(10).join(f"- {r}" for r in reasons)}

Recommendations:
{chr(10).join(f"- {r}" for r in recommendations)}

{'='*50}
Generated by WiFi Security Analyzer Pro
            """
            st.download_button(
                "📝 Download Report",
                data=report,
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True
            )

# ---------------------------
# TAB 3: Reports & History
# ---------------------------
with tab3:
    st.markdown("## 📈 Analysis Reports & History")
    
    # Initialize history if not exists
    if 'scan_history' not in st.session_state:
        st.session_state['scan_history'] = []
    
    # Save current scan to history
    if 'scan' in st.session_state and st.session_state.get('save_to_history', False):
        history_entry = {
            'timestamp': st.session_state.get('scan_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            'risk_score': st.session_state['risk_score'],
            'is_suspicious': bool(st.session_state['pred']),
            'encryption': st.session_state['scan']['Encryption_Type'],
            'signal': st.session_state['scan']['Signal_Strength_dBm']
        }
        st.session_state['scan_history'].append(history_entry)
        st.session_state['save_to_history'] = False
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown("### 📊 Scan Statistics")
    
    with col2:
        if st.button("🗑️ Clear History", use_container_width=True):
            st.session_state['scan_history'] = []
            st.rerun()
    
    if st.session_state['scan_history']:
        history_df = pd.DataFrame(st.session_state['scan_history'])
        
        # Summary cards
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Scans", len(history_df))
        with col2:
            suspicious_count = history_df['is_suspicious'].sum()
            st.metric("Suspicious Networks", suspicious_count)
        with col3:
            avg_risk = history_df['risk_score'].mean()
            st.metric("Avg Risk Score", f"{avg_risk:.1f}%")
        with col4:
            safe_count = len(history_df) - suspicious_count
            st.metric("Safe Networks", safe_count)
        
        st.markdown("---")
        
        # Risk trend chart
        st.markdown("### 📈 Risk Score Trend")
        fig_trend = px.line(history_df, x='timestamp', y='risk_score',
                            markers=True,
                            labels={'timestamp': 'Scan Time', 'risk_score': 'Risk Score (%)'},
                            color_discrete_sequence=['#667eea'])
        fig_trend.add_hline(y=70, line_dash="dash", line_color="red", 
                           annotation_text="High Risk Threshold")
        fig_trend.add_hline(y=40, line_dash="dash", line_color="orange", 
                           annotation_text="Medium Risk Threshold")
        fig_trend.update_layout(
            height=400,
            margin=dict(l=20, r=20, t=20, b=20),
            paper_bgcolor='rgba(0,0,0,0)'
        )
        st.plotly_chart(fig_trend, use_container_width=True)
        
        st.markdown("---")
        
        # Distribution charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🔐 Encryption Distribution")
            enc_counts = history_df['encryption'].value_counts()
            fig_enc = px.pie(values=enc_counts.values, names=enc_counts.index,
                            color_discrete_sequence=px.colors.qualitative.Set3)
            fig_enc.update_layout(
                height=300,
                margin=dict(l=20, r=20, t=20, b=20),
                paper_bgcolor='rgba(0,0,0,0)'
            )
            st.plotly_chart(fig_enc, use_container_width=True)
        
        with col2:
            st.markdown("### ⚠️ Risk Level Distribution")
            risk_levels = history_df['risk_score'].apply(
                lambda x: 'High' if x >= 70 else ('Medium' if x >= 40 else 'Low')
            )
            risk_counts = risk_levels.value_counts()
            colors = {'High': '#FF6B6B', 'Medium': '#FFD93D', 'Low': '#6BCF7F'}
            fig_risk = px.bar(x=risk_counts.index, y=risk_counts.values,
                             labels={'x': 'Risk Level', 'y': 'Count'},
                             color=risk_counts.index,
                             color_discrete_map=colors)
            fig_risk.update_layout(
                height=300,
                showlegend=False,
                margin=dict(l=20, r=20, t=20, b=20),
                paper_bgcolor='rgba(0,0,0,0)'
            )
            st.plotly_chart(fig_risk, use_container_width=True)
        
        st.markdown("---")
        
        # History table
        st.markdown("### 📋 Scan History")
        
        display_df = history_df.copy()
        display_df['risk_score'] = display_df['risk_score'].apply(lambda x: f"{x:.1f}%")
        display_df['signal'] = display_df['signal'].apply(lambda x: f"{x:.1f} dBm")
        display_df['status'] = display_df['is_suspicious'].apply(lambda x: "⚠️ Suspicious" if x else "✅ Safe")
        display_df = display_df[['timestamp', 'status', 'risk_score', 'encryption', 'signal']]
        display_df.columns = ['Timestamp', 'Status', 'Risk Score', 'Encryption', 'Signal']
        
        st.dataframe(display_df, use_container_width=True, hide_index=True)
        
        # Export history
        st.markdown("---")
        csv_history = history_df.to_csv(index=False)
        st.download_button(
            "📥 Export Complete History",
            data=csv_history,
            file_name=f"scan_history_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=False
        )
    else:
        st.info("📊 No scan history available yet. Perform some scans to see statistics and trends here.")
        st.markdown("""
        <div style="text-align: center; padding: 3rem; color: #999;">
            <h3>🔍 Start scanning networks to build your history!</h3>
            <p>Your scan results will appear here with detailed analytics and trends.</p>
        </div>
        """, unsafe_allow_html=True)

# ---------------------------
# Footer
# ---------------------------
st.markdown("---")
st.markdown("""
<div style="text-align: center; padding: 2rem; color: #666;">
    <p style="margin: 0;">🛡️ <strong>WiFi Security Analyzer Pro</strong> v2.0</p>
    <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem;">
        Powered by Machine Learning | Real-time Threat Detection | Advanced Network Analysis
    </p>
    <p style="margin: 0.5rem 0 0 0; font-size: 0.8rem; color: #999;">
        ⚠️ Always use VPN on public networks | Keep your devices updated | Be security conscious
    </p>
</div>
""", unsafe_allow_html=True)

# Auto-save to history when new scan is completed
if 'scan' in st.session_state and 'last_saved_scan' not in st.session_state:
    st.session_state['save_to_history'] = True
    st.session_state['last_saved_scan'] = st.session_state.get('scan_time', '')
elif 'scan' in st.session_state and st.session_state.get('last_saved_scan') != st.session_state.get('scan_time'):
    st.session_state['save_to_history'] = True
    st.session_state['last_saved_scan'] = st.session_state.get('scan_time', '')