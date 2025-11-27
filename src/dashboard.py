import streamlit as st
import os
import tempfile
from pathlib import Path
from visualizer import BinaryVisualizer
from binary_parser import BinaryParser


def apply_custom_theme():
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
        
        :root {
            --primary-purple: #a78bfa;
            --primary-blue: #60a5fa;
            --accent-pink: #f472b6;
            --accent-cyan: #22d3ee;
            --bg-dark: #0f0f23;
            --bg-card: #1a1a2e;
            --bg-secondary: #16213e;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --border-color: #2d3748;
            --glow-purple: rgba(167, 139, 250, 0.3);
            --glow-blue: rgba(96, 165, 250, 0.3);
        }
        
        .stApp {
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
            font-family: 'Space Grotesk', sans-serif;
        }
        
        h1, h2, h3 {
            font-family: 'Space Grotesk', sans-serif !important;
            background: linear-gradient(135deg, var(--primary-purple) 0%, var(--primary-blue) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700 !important;
        }
        
        .main-title {
            font-size: 3rem;
            text-align: center;
            margin-bottom: 0.5rem;
            letter-spacing: 3px;
            filter: drop-shadow(0 0 20px var(--glow-purple));
        }
        
        .subtitle {
            text-align: center;
            color: var(--text-secondary);
            font-size: 1.1rem;
            margin-bottom: 2rem;
            font-weight: 400;
        }
        
        .stButton > button {
            background: linear-gradient(135deg, var(--primary-purple) 0%, var(--primary-blue) 100%);
            color: white;
            border: none;
            border-radius: 12px;
            padding: 0.75rem 2rem;
            font-weight: 600;
            font-family: 'Space Grotesk', sans-serif;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 20px var(--glow-purple);
        }
        
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px var(--glow-blue);
            background: linear-gradient(135deg, var(--primary-blue) 0%, var(--accent-cyan) 100%);
        }
        
        .uploadedFile {
            background: var(--bg-card);
            border: 2px solid var(--border-color);
            border-radius: 12px;
            padding: 1rem;
        }
        
        .stSelectbox > div > div {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            border-radius: 8px;
        }
        
        .stMetric {
            background: var(--bg-card);
            padding: 1.5rem;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        }
        
        .stMetric label {
            color: var(--text-secondary) !important;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stMetric [data-testid="stMetricValue"] {
            background: linear-gradient(135deg, var(--primary-purple) 0%, var(--primary-blue) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-family: 'Space Grotesk', monospace;
            font-weight: 700;
            font-size: 2rem;
        }
        
        .info-box {
            background: linear-gradient(135deg, rgba(167, 139, 250, 0.1) 0%, rgba(96, 165, 250, 0.1) 100%);
            border-left: 4px solid var(--primary-purple);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            margin: 1rem 0;
            color: var(--text-primary);
        }
        
        .success-box {
            background: linear-gradient(135deg, rgba(167, 139, 250, 0.15) 0%, rgba(96, 165, 250, 0.15) 100%);
            border: 2px solid var(--primary-purple);
            border-radius: 12px;
            padding: 1rem;
            color: var(--primary-purple);
            font-family: 'JetBrains Mono', monospace;
            font-weight: 500;
        }
        
        .metadata-table {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            border: 1px solid var(--border-color);
        }
        
        .stExpander {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
        }
        
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, var(--bg-dark) 0%, var(--bg-secondary) 100%);
            border-right: 1px solid var(--border-color);
        }
        
        .stDownloadButton > button {
            background: var(--bg-secondary);
            border: 2px solid var(--primary-blue);
            color: var(--primary-blue);
            font-family: 'Space Grotesk', sans-serif;
            font-weight: 600;
            border-radius: 10px;
            transition: all 0.3s ease;
        }
        
        .stDownloadButton > button:hover {
            background: linear-gradient(135deg, var(--primary-blue) 0%, var(--accent-cyan) 100%);
            color: white;
            box-shadow: 0 4px 20px var(--glow-blue);
        }
        
        code {
            background: var(--bg-secondary);
            color: var(--accent-cyan);
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
        }
        
        .terminal-text {
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-primary);
            background: var(--bg-dark);
            padding: 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            border: 1px solid var(--border-color);
        }
        
        .stFileUploader {
            background: var(--bg-card);
            border-radius: 12px;
            border: 2px dashed var(--border-color);
            transition: all 0.3s ease;
        }
        
        .stFileUploader:hover {
            border-color: var(--primary-purple);
        }
        
        .stSlider > div > div > div {
            background: linear-gradient(90deg, var(--primary-purple) 0%, var(--primary-blue) 100%);
        }
        
        .stCheckbox > label {
            color: var(--text-primary) !important;
        }
        </style>
    """, unsafe_allow_html=True)


def main():
    st.set_page_config(
        page_title="Binartia - Binary Visualizer",
        page_icon="🔬",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    apply_custom_theme()
    st.markdown('<h1 class="main-title">🔬 BINARTIA</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Binary Decompiler Visualizer - Transform executables into visual fingerprints</p>', unsafe_allow_html=True)
    st.sidebar.markdown("### ⚙️ Configuration")
    curve_type = st.sidebar.selectbox(
        "Curve Algorithm",
        options=['hilbert', 'spiral', 'grid', 'random_walk', 'radial'],
        help="Space-filling curve for coordinate mapping"
    )
    color_mode = st.sidebar.selectbox(
        "Color Mode",
        options=['hsv', 'heatmap', 'grayscale', 'opcode'],
        help="Color mapping strategy"
    )
    use_entropy = st.sidebar.checkbox(
        "Entropy-based Brightness",
        value=True,
        help="Adjust brightness based on local entropy"
    )
    show_entropy_overlay = st.sidebar.checkbox(
        "Entropy Hotspot Overlay",
        value=False,
        help="Highlight high-entropy regions"
    )
    scale = st.sidebar.slider(
        "Pixel Scale",
        min_value=1,
        max_value=5,
        value=1,
        help="Scaling factor for output image"
    )
    section = st.sidebar.selectbox(
        "Section",
        options=['text', 'all'],
        help="Binary section to visualize"
    )
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📚 About")
    st.sidebar.markdown("Transform binary executables into unique visual art using space-filling curves and entropy analysis.")
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🤖 AI Classifier")
    
    model_files = list(Path('models').glob('*.h5')) if Path('models').exists() else []
    if model_files:
        model_path = st.sidebar.selectbox(
            "Select Model",
            options=[str(m) for m in model_files],
            help="Choose a trained model for classification"
        )
        enable_classifier = st.sidebar.checkbox("Enable Classification", value=False)
    else:
        st.sidebar.info("No trained models found in models/ directory")
        enable_classifier = False
        model_path = None
    
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("### 📁 Upload Binary")
        uploaded_file = st.file_uploader(
            "Choose an executable file",
            type=['exe', 'dll', 'so', 'elf', 'bin', 'out'],
            help="Supports ELF, PE, and Mach-O formats"
        )
        if uploaded_file is not None:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp_file:
                tmp_file.write(uploaded_file.read())
                tmp_path = tmp_file.name
            try:
                st.markdown(f'<div class="success-box">✓ Loaded: {uploaded_file.name}</div>', unsafe_allow_html=True)
                with st.spinner("Parsing binary..."):
                    parser = BinaryParser(tmp_path)
                    metadata = parser.get_metadata()
                st.markdown("#### 📊 Binary Metadata")
                st.markdown('<div class="metadata-table">', unsafe_allow_html=True)
                for key, value in metadata.items():
                    st.text(f"{key:15s}: {value}")
                st.markdown('</div>', unsafe_allow_html=True)
                if st.button("🎨 GENERATE VISUALIZATION", type="primary"):
                    with st.spinner("Generating visualization..."):
                        visualizer = BinaryVisualizer(
                            curve_type=curve_type,
                            use_entropy=use_entropy,
                            color_mode=color_mode,
                            scale=scale,
                            show_entropy_overlay=show_entropy_overlay
                        )
                        output_path = tempfile.mktemp(suffix='.png')
                        width, height = visualizer.visualize(
                            tmp_path,
                            output_path,
                            section=section
                        )
                        stats = visualizer.get_statistics(tmp_path)
                        st.session_state['output_path'] = output_path
                        st.session_state['stats'] = stats
                        st.session_state['dimensions'] = (width, height)
                        if enable_classifier and model_path:
                            try:
                                from ai_classifier import MalwareClassifier
                                classifier = MalwareClassifier(model_path)
                                label, confidence = classifier.predict(output_path)
                                st.session_state['classification'] = {
                                    'label': label,
                                    'confidence': confidence
                                }
                            except Exception as e:
                                st.session_state['classification'] = {
                                    'error': str(e)
                                }
                        
                        st.rerun()
            except Exception as e:
                st.error(f"Error processing binary: {e}")
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
    with col2:
        st.markdown("### Visualization")
        if 'output_path' in st.session_state:
            output_path = st.session_state['output_path']
            if os.path.exists(output_path):
                st.image(output_path, caption="Binary Visualization", use_container_width=True)
                st.markdown("#### 📈 Statistics")
                stats = st.session_state.get('stats', {})
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    st.metric("Bytes", f"{stats.get('bytes', 0):,}")
                with col_b:
                    st.metric("Entropy", f"{stats.get('entropy', 0):.2f}")
                with col_c:
                    st.metric("Unique", stats.get('unique_bytes', 'N/A'))
                st.markdown('<div class="terminal-text">', unsafe_allow_html=True)
                st.text(f"Dimensions: {stats.get('dimensions', 'N/A')}")
                st.text(f"Algorithm: {stats.get('curve_type', 'N/A')}")
                st.markdown('</div>', unsafe_allow_html=True)
                
                if 'classification' in st.session_state:
                    classification = st.session_state['classification']
                    st.markdown("#### 🤖 AI Classification")
                    if 'error' in classification:
                        st.error(f"Classification error: {classification['error']}")
                    else:
                        label = classification['label']
                        confidence = classification['confidence']
                        if label == "Malware":
                            st.markdown(f'<div style="background: rgba(255, 100, 100, 0.2); border: 2px solid #ff6464; border-radius: 12px; padding: 1rem; text-align: center;">'
                                      f'<h3 style="color: #ff6464; margin: 0;">⚠️ {label}</h3>'
                                      f'<p style="color: #e2e8f0; margin: 0.5rem 0 0 0;">Confidence: {confidence:.1%}</p>'
                                      f'</div>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div style="background: rgba(100, 255, 150, 0.2); border: 2px solid #64ffa0; border-radius: 12px; padding: 1rem; text-align: center;">'
                                      f'<h3 style="color: #64ffa0; margin: 0;">✓ {label}</h3>'
                                      f'<p style="color: #e2e8f0; margin: 0.5rem 0 0 0;">Confidence: {confidence:.1%}</p>'
                                      f'</div>', unsafe_allow_html=True)

                with open(output_path, 'rb') as f:
                    st.download_button(
                        label="⬇️ DOWNLOAD",
                        data=f,
                        file_name=f"binartia_{curve_type}.png",
                        mime="image/png"
                    )
        else:
            st.markdown('<div class="info-box">Upload a binary file and generate visualization</div>', unsafe_allow_html=True)
    st.markdown("---")
    with st.expander("💡 How It Works"):
        st.markdown("""
        **Pipeline:**
        1. Parse binary and extract executable code
        2. Map bytes to visual features (hue, brightness, saturation)
        3. Apply space-filling curve algorithm
        4. Render PNG image
        
        **Use Cases:**
        - Malware analysis and fingerprinting
        - Binary comparison and diffing
        - Identifying packed or obfuscated code
        """)
    with st.expander("📐 Curve Algorithms"):
        st.markdown("""
        - **Hilbert**: Space-filling fractal preserving locality
        - **Spiral**: Outward pattern from center
        - **Grid**: Simple left-to-right layout
        """)


if __name__ == '__main__':
    main()
