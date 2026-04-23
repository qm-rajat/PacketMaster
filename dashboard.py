from flask import Flask, render_template, jsonify, request, send_file, Response
import json
import os
import glob
import uuid
import time
from datetime import datetime
from threading import Thread
from packetmaster import PacketMaster
import plotly.graph_objs as go
import plotly.utils
import pandas as pd
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

# Global state
analysis_jobs = {}  # job_id -> status
analysis_results = {}  # filename -> analysis data
uploaded_files = {}  # filename -> filepath

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file upload and start analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.lower().endswith('.pcap'):
        return jsonify({'error': 'Only .pcap files are supported'}), 400

    # Generate unique filename
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

    try:
        file.save(filepath)
        uploaded_files[unique_filename] = filepath

        # Start analysis in background
        job_id = str(uuid.uuid4())
        analysis_jobs[job_id] = {
            'status': 'running',
            'filename': unique_filename,
            'original_name': filename,
            'progress': 0,
            'start_time': time.time()
        }

        # Start analysis thread
        thread = Thread(target=analyze_file_background, args=(job_id, filepath, unique_filename))
        thread.daemon = True
        thread.start()

        return jsonify({
            'success': True,
            'job_id': job_id,
            'filename': unique_filename,
            'original_name': filename
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/job/<job_id>')
def get_job_status(job_id):
    """Get analysis job status"""
    if job_id not in analysis_jobs:
        return jsonify({'error': 'Job not found'}), 404

    job = analysis_jobs[job_id]
    return jsonify(job)

@app.route('/api/analysis/<filename>')
def get_analysis(filename):
    """Get analysis results for a file"""
    if filename not in analysis_results:
        return jsonify({'error': 'Analysis not found'}), 404

    return jsonify(analysis_results[filename])

@app.route('/api/filter/<filename>', methods=['POST'])
def apply_filter(filename):
    """Apply filter to analysis results"""
    if filename not in uploaded_files:
        return jsonify({'error': 'File not found'}), 404

    filter_expr = request.json.get('filter', '')
    if not filter_expr:
        return jsonify({'error': 'No filter provided'}), 400

    try:
        analyzer = PacketMaster(uploaded_files[filename])
        analyzer.filter_packets(filter_expr)

        # Run analysis on filtered packets
        analyzer.basic_stats()
        analyzer.protocol_breakdown()
        analyzer.top_talkers()
        analyzer.tcp_analysis()
        analyzer.security_scan()

        return jsonify({
            'success': True,
            'analysis': analyzer.analysis,
            'filtered_count': len(analyzer.filtered_packets)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/<filename>/<format>')
def export_analysis(filename, format):
    """Export analysis results"""
    if filename not in analysis_results:
        return jsonify({'error': 'Analysis not found'}), 404

    analysis = analysis_results[filename]

    if format == 'json':
        return Response(
            json.dumps(analysis, indent=2, default=str),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename={filename}_analysis.json'}
        )
    elif format == 'csv':
        # Create CSV from packet data if available
        return jsonify({'error': 'CSV export not implemented yet'}), 501
    else:
        return jsonify({'error': 'Unsupported format'}), 400

@app.route('/api/reports')
def list_reports():
    """List all analysis reports"""
    reports = []
    for filename, analysis in analysis_results.items():
        reports.append({
            'filename': filename,
            'original_name': analysis.get('original_name', filename),
            'timestamp': analysis.get('timestamp', 'Unknown'),
            'packet_count': analysis.get('basic', {}).get('total_packets', 0),
            'duration': analysis.get('basic', {}).get('duration', 0),
            'alerts': len(analysis.get('security', {}).get('alerts', []))
        })

    return jsonify(reports)

@app.route('/dashboard/<filename>')
def dashboard(filename):
    """Main dashboard view"""
    if filename not in analysis_results:
        return "Analysis not found", 404

    analysis = analysis_results[filename]
    return render_template('dashboard.html',
                         filename=filename,
                         analysis=analysis,
                         charts=create_charts(analysis))

def analyze_file_background(job_id, filepath, filename):
    """Background analysis function"""
    try:
        analysis_jobs[job_id]['progress'] = 10
        analyzer = PacketMaster(filepath)

        analysis_jobs[job_id]['progress'] = 30
        analyzer.basic_stats()

        analysis_jobs[job_id]['progress'] = 50
        analyzer.protocol_breakdown()

        analysis_jobs[job_id]['progress'] = 60
        analyzer.top_talkers()

        analysis_jobs[job_id]['progress'] = 70
        analyzer.tcp_analysis()

        analysis_jobs[job_id]['progress'] = 80
        analyzer.security_scan()

        analysis_jobs[job_id]['progress'] = 90
        if analyzer.config.get('enable_ml', True):
            analyzer.detect_anomalies()

        analysis_jobs[job_id]['progress'] = 100

        # Store results
        analyzer.analysis['timestamp'] = datetime.now().isoformat()
        analyzer.analysis['original_name'] = analysis_jobs[job_id]['original_name']
        analysis_results[filename] = analyzer.analysis

        analysis_jobs[job_id]['status'] = 'completed'
        analysis_jobs[job_id]['end_time'] = time.time()

    except Exception as e:
        analysis_jobs[job_id]['status'] = 'failed'
        analysis_jobs[job_id]['error'] = str(e)
        analysis_jobs[job_id]['end_time'] = time.time()

def create_charts(analysis):
    """Create interactive charts for dashboard"""
    charts = {}

    # Protocol breakdown pie chart
    if 'protocols' in analysis:
        protocols = analysis['protocols']
        fig = go.Figure(data=[go.Pie(
            labels=list(protocols.keys()),
            values=list(protocols.values()),
            hole=0.4,
            marker_colors=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD']
        )])
        fig.update_layout(
            title="Protocol Distribution",
            font=dict(size=14),
            showlegend=True
        )
        charts['protocol_pie'] = plotly.utils.PlotlyJSONEncoder().encode(fig)

    # Packet size distribution histogram
    if 'basic' in analysis and 'size_stats' in analysis['basic']:
        # This would need actual packet sizes - placeholder for now
        pass

    # TCP flags chart
    if 'tcp' in analysis:
        tcp_data = analysis['tcp']
        flags_data = [
            ('SYN', tcp_data.get('syn', 0)),
            ('FIN', tcp_data.get('fin', 0)),
            ('RST', tcp_data.get('rst', 0))
        ]

        fig = go.Figure(data=[go.Bar(
            x=[item[0] for item in flags_data],
            y=[item[1] for item in flags_data],
            marker_color=['#FF6B6B', '#4ECDC4', '#45B7D1']
        )])
        fig.update_layout(
            title="TCP Control Flags",
            xaxis_title="Flag Type",
            yaxis_title="Count"
        )
        charts['tcp_flags'] = plotly.utils.PlotlyJSONEncoder().encode(fig)

    return charts

if __name__ == '__main__':
    # Create templates directory and files
    create_templates()
    app.run(debug=True, host='0.0.0.0', port=5001, threaded=True)

def create_templates():
    """Create HTML templates"""
    templates_dir = 'templates'
    os.makedirs(templates_dir, exist_ok=True)

    # Create main index.html
    with open(f'{templates_dir}/index.html', 'w') as f:
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚀 PacketMaster Pro - Advanced Network Analysis</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.plotly.com/plotly-latest.min.js"></script>
    <style>
        :root {
            --primary: #6366f1;
            --secondary: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #1f2937;
            --light: #f9fafb;
        }

        body {
            background: linear-gradient(135deg, var(--light) 0%, #e5e7eb 100%);
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
        }

        .navbar {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(0,0,0,0.1);
        }

        .hero-section {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 80px 0;
            border-radius: 0 0 50px 50px;
        }

        .upload-zone {
            border: 3px dashed var(--primary);
            border-radius: 20px;
            padding: 60px;
            text-align: center;
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            margin: 40px 0;
        }

        .upload-zone:hover {
            border-color: var(--secondary);
            background: rgba(255, 255, 255, 1);
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }

        .upload-zone.dragover {
            border-color: var(--success);
            background: rgba(16, 185, 129, 0.1);
        }

        .feature-card {
            background: white;
            border-radius: 20px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            border: 1px solid rgba(0,0,0,0.05);
        }

        .feature-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
        }

        .feature-icon {
            font-size: 3rem;
            margin-bottom: 20px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .progress-card {
            background: white;
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            display: none;
        }

        .analysis-list {
            max-height: 400px;
            overflow-y: auto;
        }

        .analysis-item {
            background: white;
            border-radius: 15px;
            padding: 20px;
            margin: 10px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            border-left: 5px solid var(--primary);
            transition: all 0.3s ease;
        }

        .analysis-item:hover {
            transform: translateX(10px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }

        .btn-analyze {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border: none;
            border-radius: 50px;
            padding: 15px 40px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s ease;
        }

        .btn-analyze:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 25px rgba(99, 102, 241, 0.4);
        }

        .stats-card {
            background: linear-gradient(135deg, var(--success), #34d399);
            color: white;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }

        .pulse {
            animation: pulse 2s infinite;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-light">
        <div class="container">
            <a class="navbar-brand fw-bold" href="#">
                <i class="fas fa-network-wired me-2"></i>
                PacketMaster Pro
            </a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="#features">Features</a>
                <a class="nav-link" href="#about">About</a>
                <a class="nav-link" href="#contact">Contact</a>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <section class="hero-section">
        <div class="container text-center">
            <h1 class="display-4 fw-bold mb-4">
                🚀 Advanced Network Packet Analysis
            </h1>
            <p class="lead mb-4">
                Everything Wireshark does + AI-Powered Analysis + Real-time Monitoring + Professional Reports
            </p>
            <div class="row justify-content-center">
                <div class="col-md-3">
                    <div class="stats-card">
                        <h3>100%</h3>
                        <p>Automated</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card">
                        <h3>AI</h3>
                        <p>Powered</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card">
                        <h3>Real-time</h3>
                        <p>Analysis</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <div class="container my-5">
        <!-- Upload Section -->
        <div class="row justify-content-center">
            <div class="col-lg-8">
                <div class="upload-zone" id="uploadZone">
                    <i class="fas fa-cloud-upload-alt fa-4x mb-4 text-primary"></i>
                    <h3 class="mb-3">Upload Your PCAP File</h3>
                    <p class="mb-4 text-muted">Drag & drop your packet capture file here or click to browse</p>
                    <input type="file" id="fileInput" accept=".pcap" class="d-none">
                    <button class="btn btn-analyze btn-lg" onclick="document.getElementById('fileInput').click()">
                        <i class="fas fa-folder-open me-2"></i>Choose File
                    </button>
                    <p class="mt-3 small text-muted">Maximum file size: 500MB</p>
                </div>

                <!-- Progress Card -->
                <div class="progress-card" id="progressCard">
                    <h4 class="mb-3">
                        <i class="fas fa-cog fa-spin me-2"></i>
                        Analyzing <span id="analyzingFile"></span>
                    </h4>
                    <div class="progress mb-3">
                        <div class="progress-bar progress-bar-striped progress-bar-animated"
                             id="progressBar" style="width: 0%"></div>
                    </div>
                    <p class="text-center text-muted" id="progressText">Initializing analysis...</p>
                </div>
            </div>
        </div>

        <!-- Features Section -->
        <div id="features" class="row mt-5">
            <div class="col-12 text-center mb-5">
                <h2 class="fw-bold">🔥 Powerful Features</h2>
                <p class="text-muted">Everything you need for comprehensive network analysis</p>
            </div>

            <div class="col-md-4 mb-4">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-brain"></i>
                    </div>
                    <h5>AI-Powered Analysis</h5>
                    <p>Machine learning algorithms detect anomalies, classify traffic, and identify security threats automatically.</p>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <h5>Advanced Security</h5>
                    <p>Comprehensive threat detection including port scans, spoofing, tunneling, and DDoS attacks.</p>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-chart-line"></i>
                    </div>
                    <h5>Real-time Dashboards</h5>
                    <p>Interactive visualizations with detailed packet analysis, protocol breakdowns, and performance metrics.</p>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-filter"></i>
                    </div>
                    <h5>Advanced Filtering</h5>
                    <p>Wireshark-style packet filtering with real-time application and instant results.</p>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-file-export"></i>
                    </div>
                    <h5>Professional Reports</h5>
                    <p>Export comprehensive analysis reports in JSON, CSV, and interactive HTML formats.</p>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-clock"></i>
                    </div>
                    <h5>Automated Monitoring</h5>
                    <p>Scheduled analysis, email alerts, and continuous monitoring of network traffic.</p>
                </div>
            </div>
        </div>

        <!-- Analysis History -->
        <div class="row mt-5">
            <div class="col-12">
                <h3 class="text-center mb-4">
                    <i class="fas fa-history me-2"></i>
                    Recent Analyses
                </h3>
                <div class="analysis-list" id="analysisList">
                    <p class="text-center text-muted">No analyses yet. Upload a PCAP file to get started!</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-dark text-light py-4 mt-5">
        <div class="container text-center">
            <p>&copy; 2024 PacketMaster Pro. Built for network analysts and security professionals.</p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentJobId = null;
        let progressInterval = null;

        // Drag and drop functionality
        const uploadZone = document.getElementById('uploadZone');
        const fileInput = document.getElementById('fileInput');
        const progressCard = document.getElementById('progressCard');
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const analyzingFile = document.getElementById('analyzingFile');

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadZone.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            uploadZone.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            uploadZone.addEventListener(eventName, unhighlight, false);
        });

        function highlight(e) {
            uploadZone.classList.add('dragover');
        }

        function unhighlight(e) {
            uploadZone.classList.remove('dragover');
        }

        uploadZone.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            handleFiles(files);
        }

        fileInput.addEventListener('change', function(e) {
            handleFiles(e.target.files);
        });

        function handleFiles(files) {
            if (files.length > 0) {
                uploadFile(files[0]);
            }
        }

        async function uploadFile(file) {
            const formData = new FormData();
            formData.append('file', file);

            uploadZone.style.display = 'none';
            progressCard.style.display = 'block';
            analyzingFile.textContent = file.name;
            progressBar.style.width = '0%';
            progressText.textContent = 'Uploading file...';

            try {
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    currentJobId = result.job_id;
                    progressText.textContent = 'File uploaded. Starting analysis...';
                    monitorProgress();
                } else {
                    throw new Error(result.error);
                }
            } catch (error) {
                progressText.textContent = `Error: ${error.message}`;
                progressBar.classList.add('bg-danger');
                setTimeout(() => {
                    uploadZone.style.display = 'block';
                    progressCard.style.display = 'none';
                }, 3000);
            }
        }

        function monitorProgress() {
            progressInterval = setInterval(async () => {
                try {
                    const response = await fetch(`/api/job/${currentJobId}`);
                    const job = await response.json();

                    progressBar.style.width = `${job.progress}%`;
                    progressText.textContent = getProgressText(job.progress);

                    if (job.status === 'completed') {
                        clearInterval(progressInterval);
                        progressText.textContent = 'Analysis completed!';
                        progressBar.classList.remove('progress-bar-animated');
                        progressBar.classList.add('bg-success');

                        setTimeout(() => {
                            window.location.href = `/dashboard/${job.filename}`;
                        }, 1000);
                    } else if (job.status === 'failed') {
                        clearInterval(progressInterval);
                        progressText.textContent = `Analysis failed: ${job.error}`;
                        progressBar.classList.add('bg-danger');
                        setTimeout(() => {
                            uploadZone.style.display = 'block';
                            progressCard.style.display = 'none';
                        }, 3000);
                    }
                } catch (error) {
                    console.error('Progress monitoring error:', error);
                }
            }, 1000);
        }

        function getProgressText(progress) {
            if (progress < 30) return 'Loading packets...';
            if (progress < 50) return 'Analyzing protocols...';
            if (progress < 70) return 'Checking security...';
            if (progress < 90) return 'Running AI analysis...';
            return 'Finalizing report...';
        }

        // Load analysis history
        async function loadAnalysisHistory() {
            try {
                const response = await fetch('/api/reports');
                const reports = await response.json();

                const analysisList = document.getElementById('analysisList');
                if (reports.length === 0) return;

                analysisList.innerHTML = reports.map(report => `
                    <div class="analysis-item">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h5 class="mb-1">${report.original_name}</h5>
                                <p class="text-muted mb-2">${new Date(report.timestamp).toLocaleString()}</p>
                                <div class="row text-center">
                                    <div class="col-4">
                                        <strong>${report.packet_count.toLocaleString()}</strong>
                                        <br><small>Packets</small>
                                    </div>
                                    <div class="col-4">
                                        <strong>${report.duration.toFixed(2)}s</strong>
                                        <br><small>Duration</small>
                                    </div>
                                    <div class="col-4">
                                        <strong>${report.alerts}</strong>
                                        <br><small>Alerts</small>
                                    </div>
                                </div>
                            </div>
                            <a href="/dashboard/${report.filename}" class="btn btn-primary btn-sm">
                                <i class="fas fa-eye me-1"></i>View
                            </a>
                        </div>
                    </div>
                `).join('');
            } catch (error) {
                console.error('Error loading analysis history:', error);
            }
        }

        // Load history on page load
        loadAnalysisHistory();

        // Refresh history every 30 seconds
        setInterval(loadAnalysisHistory, 30000);
    </script>
</body>
</html>""")

    # Create dashboard.html
    with open(f'{templates_dir}/dashboard.html', 'w') as f:
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analysis Dashboard - PacketMaster Pro</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.plotly.com/plotly-latest.min.js"></script>
    <style>
        :root {
            --primary: #6366f1;
            --secondary: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #1f2937;
            --light: #f9fafb;
        }

        body {
            background: var(--light);
            font-family: 'Inter', sans-serif;
        }

        .navbar {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(0,0,0,0.1);
        }

        .dashboard-header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 40px 0;
            margin-bottom: 30px;
        }

        .metric-card {
            background: white;
            border-radius: 20px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            border: 1px solid rgba(0,0,0,0.05);
            transition: all 0.3s ease;
        }

        .metric-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.15);
        }

        .metric-value {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .metric-label {
            color: #6b7280;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .chart-container {
            background: white;
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        .filter-section {
            background: white;
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        .alert-card {
            border-radius: 15px;
            padding: 20px;
            margin: 10px 0;
            border-left: 5px solid;
        }

        .alert-high { border-left-color: var(--danger); background: rgba(239, 68, 68, 0.1); }
        .alert-medium { border-left-color: var(--warning); background: rgba(245, 158, 11, 0.1); }
        .alert-low { border-left-color: var(--primary); background: rgba(99, 102, 241, 0.1); }

        .tab-content {
            background: white;
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }

        .btn-export {
            background: linear-gradient(135deg, var(--success), #34d399);
            border: none;
            border-radius: 50px;
            padding: 12px 30px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s ease;
        }

        .btn-export:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(16, 185, 129, 0.4);
        }

        .protocol-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            margin: 2px;
        }

        .table-responsive {
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }

        .table thead th {
            background: var(--primary);
            color: white;
            border: none;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .table tbody tr:hover {
            background: rgba(99, 102, 241, 0.05);
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-light">
        <div class="container">
            <a class="navbar-brand fw-bold" href="/">
                <i class="fas fa-network-wired me-2"></i>
                PacketMaster Pro
            </a>
            <div class="navbar-nav ms-auto">
                <button class="btn btn-export me-2" onclick="exportAnalysis('json')">
                    <i class="fas fa-download me-1"></i>Export JSON
                </button>
                <button class="btn btn-export" onclick="exportAnalysis('csv')">
                    <i class="fas fa-file-csv me-1"></i>Export CSV
                </button>
            </div>
        </div>
    </nav>

    <!-- Dashboard Header -->
    <section class="dashboard-header">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-lg-8">
                    <h1 class="display-5 fw-bold mb-3">
                        <i class="fas fa-chart-line me-3"></i>
                        Analysis Dashboard
                    </h1>
                    <p class="lead mb-0">File: <strong>{{ analysis.get('original_name', filename) }}</strong></p>
                    <p class="mb-0">Analyzed: <strong>{{ analysis.get('timestamp', 'Unknown') }}</strong></p>
                </div>
                <div class="col-lg-4 text-end">
                    <div class="d-flex justify-content-end gap-2">
                        <button class="btn btn-light" onclick="window.history.back()">
                            <i class="fas fa-arrow-left me-1"></i>Back
                        </button>
                        <button class="btn btn-primary" onclick="location.reload()">
                            <i class="fas fa-sync me-1"></i>Refresh
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <div class="container">
        <!-- Key Metrics -->
        <div class="row mb-4">
            {% set basic = analysis.get('basic', {}) %}
            <div class="col-md-3 mb-3">
                <div class="metric-card">
                    <div class="metric-value text-primary">{{ basic.get('total_packets', 0) | int }}</div>
                    <div class="metric-label">Total Packets</div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="metric-card">
                    <div class="metric-value text-success">{{ "%.2f"|format(basic.get('duration', 0)) }}</div>
                    <div class="metric-label">Duration (sec)</div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="metric-card">
                    <div class="metric-value text-warning">{{ "%.1f"|format(basic.get('pps', 0)) }}</div>
                    <div class="metric-label">Packets/sec</div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="metric-card">
                    <div class="metric-value text-info">{{ "%.2f"|format(basic.get('throughput_mbps', 0)) }}</div>
                    <div class="metric-label">Throughput (Mbps)</div>
                </div>
            </div>
        </div>

        <!-- Filter Section -->
        <div class="filter-section">
            <h4 class="mb-3">
                <i class="fas fa-filter me-2"></i>
                Apply Packet Filter
            </h4>
            <div class="row">
                <div class="col-md-8">
                    <input type="text" class="form-control form-control-lg" id="filterInput"
                           placeholder="e.g., tcp port 80, ip src 192.168.1.1, dns">
                </div>
                <div class="col-md-4">
                    <button class="btn btn-primary btn-lg w-100" onclick="applyFilter()">
                        <i class="fas fa-search me-2"></i>Apply Filter
                    </button>
                </div>
            </div>
            <div class="mt-3">
                <small class="text-muted">
                    <strong>Examples:</strong> tcp, udp, ip src 192.168.1.1, port 80, dns, http
                </small>
            </div>
            <div id="filterStatus" class="mt-2"></div>
        </div>

        <!-- Main Content Tabs -->
        <ul class="nav nav-tabs nav-fill mb-4" id="dashboardTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="overview-tab" data-bs-toggle="tab" data-bs-target="#overview" type="button" role="tab">
                    <i class="fas fa-tachometer-alt me-2"></i>Overview
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="protocols-tab" data-bs-toggle="tab" data-bs-target="#protocols" type="button" role="tab">
                    <i class="fas fa-layer-group me-2"></i>Protocols
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="security-tab" data-bs-toggle="tab" data-bs-target="#security" type="button" role="tab">
                    <i class="fas fa-shield-alt me-2"></i>Security
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="performance-tab" data-bs-toggle="tab" data-bs-target="#performance" type="button" role="tab">
                    <i class="fas fa-chart-bar me-2"></i>Performance
                </button>
            </li>
        </ul>

        <div class="tab-content" id="dashboardTabsContent">
            <!-- Overview Tab -->
            <div class="tab-pane fade show active" id="overview" role="tabpanel">
                <div class="row">
                    <div class="col-lg-6">
                        <div class="chart-container">
                            <h5 class="mb-3">
                                <i class="fas fa-chart-pie me-2"></i>
                                Protocol Distribution
                            </h5>
                            <div id="protocolChart" style="height: 400px;"></div>
                        </div>
                    </div>
                    <div class="col-lg-6">
                        <div class="chart-container">
                            <h5 class="mb-3">
                                <i class="fas fa-network-wired me-2"></i>
                                Network Summary
                            </h5>
                            <div class="row text-center">
                                {% set size_stats = basic.get('size_stats', {}) %}
                                <div class="col-6 mb-3">
                                    <div class="p-3 bg-light rounded">
                                        <div class="h4 text-primary">{{ size_stats.get('min', 0) }}</div>
                                        <small class="text-muted">Min Size</small>
                                    </div>
                                </div>
                                <div class="col-6 mb-3">
                                    <div class="p-3 bg-light rounded">
                                        <div class="h4 text-success">{{ size_stats.get('max', 0) }}</div>
                                        <small class="text-muted">Max Size</small>
                                    </div>
                                </div>
                                <div class="col-6 mb-3">
                                    <div class="p-3 bg-light rounded">
                                        <div class="h4 text-warning">{{ "%.0f"|format(size_stats.get('median', 0)) }}</div>
                                        <small class="text-muted">Median Size</small>
                                    </div>
                                </div>
                                <div class="col-6 mb-3">
                                    <div class="p-3 bg-light rounded">
                                        <div class="h4 text-info">{{ "%.1f"|format(size_stats.get('std', 0)) }}</div>
                                        <small class="text-muted">Std Dev</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Protocols Tab -->
            <div class="tab-pane fade" id="protocols" role="tabpanel">
                <div class="row">
                    <div class="col-lg-8">
                        <div class="chart-container">
                            <h5 class="mb-3">
                                <i class="fas fa-layer-group me-2"></i>
                                Detailed Protocol Breakdown
                            </h5>
                            <div id="detailedProtocolChart" style="height: 500px;"></div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="chart-container">
                            <h5 class="mb-3">
                                <i class="fas fa-list me-2"></i>
                                Protocol List
                            </h5>
                            <div style="max-height: 500px; overflow-y: auto;">
                                {% for protocol, count in analysis.get('protocols', {}).items() %}
                                <div class="d-flex justify-content-between align-items-center mb-2">
                                    <span class="badge bg-primary">{{ protocol }}</span>
                                    <span class="fw-bold">{{ count | int }}</span>
                                </div>
                                {% endfor %}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Security Tab -->
            <div class="tab-pane fade" id="security" role="tabpanel">
                <div class="row">
                    <div class="col-lg-6">
                        <div class="chart-container">
                            <h5 class="mb-3">
                                <i class="fas fa-shield-alt me-2"></i>
                                Security Alerts
                            </h5>
                            {% set security = analysis.get('security', {}) %}
                            {% set alerts = security.get('alerts', []) %}
                            {% if alerts %}
                                {% for alert in alerts %}
                                <div class="alert-card alert-{{ alert.get('severity', 'low') }}">
                                    <div class="d-flex justify-content-between align-items-start">
                                        <div>
                                            <h6 class="mb-1">
                                                <i class="fas fa-exclamation-triangle me-2"></i>
                                                {{ alert.get('type', 'Unknown').upper() }}
                                            </h6>
                                            <p class="mb-0">{{ alert.get('message', '') }}</p>
                                        </div>
                                        <span class="badge bg-{{ 'danger' if alert.get('severity') == 'high' else 'warning' if alert.get('severity') == 'medium' else 'primary' }}">
                                            {{ alert.get('severity', 'low').upper() }}
                                        </span>
                                    </div>
                                </div>
                                {% endfor %}
                            {% else %}
                                <div class="alert alert-success">
                                    <i class="fas fa-check-circle me-2"></i>
                                    No security alerts detected
                                </div>
                            {% endif %}
                        </div>
                    </div>
                    <div class="col-lg-6">
                        <div class="chart-container">
                            <h5 class="mb-3">
                                <i class="fas fa-chart-bar me-2"></i>
                                Security Statistics
                            </h5>
                            {% set scan_stats = security.get('scan_stats', {}) %}
                            <div class="row text-center">
                                <div class="col-6 mb-3">
                                    <div class="p-3 bg-light rounded">
                                        <div class="h4 text-danger">{{ scan_stats.get('low_ttl_count', 0) }}</div>
                                        <small class="text-muted">Low TTL</small>
                                    </div>
                                </div>
                                <div class="col-6 mb-3">
                                    <div class="p-3 bg-light rounded">
                                        <div class="h4 text-warning">{{ scan_stats.get('dns_long_queries', 0) }}</div>
                                        <small class="text-muted">DNS Tunneling</small>
                                    </div>
                                </div>
                                <div class="col-6 mb-3">
                                    <div class="p-3 bg-light rounded">
                                        <div class="h4 text-info">{{ scan_stats.get('icmp_count', 0) }}</div>
                                        <small class="text-muted">ICMP Packets</small>
                                    </div>
                                </div>
                                <div class="col-6 mb-3">
                                    <div class="p-3 bg-light rounded">
                                        <div class="h4 text-secondary">{{ scan_stats.get('arp_count', 0) }}</div>
                                        <small class="text-muted">ARP Packets</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Performance Tab -->
            <div class="tab-pane fade" id="performance" role="tabpanel">
                <div class="row">
                    <div class="col-lg-6">
                        <div class="chart-container">
                            <h5 class="mb-3">
                                <i class="fas fa-chart-line me-2"></i>
                                TCP Performance
                            </h5>
                            <div id="tcpChart" style="height: 400px;"></div>
                        </div>
                    </div>
                    <div class="col-lg-6">
                        <div class="chart-container">
                            <h5 class="mb-3">
                                <i class="fas fa-users me-2"></i>
                                Top Talkers
                            </h5>
                            {% set top_src = analysis.get('top_src', []) %}
                            {% set top_dst = analysis.get('top_dst', []) %}
                            <div class="row">
                                <div class="col-6">
                                    <h6>Source IPs</h6>
                                    {% for ip, count in top_src[:5] %}
                                    <div class="d-flex justify-content-between mb-2">
                                        <code>{{ ip[0] }}</code>
                                        <span>{{ ip[1] }}</span>
                                    </div>
                                    {% endfor %}
                                </div>
                                <div class="col-6">
                                    <h6>Destination IPs</h6>
                                    {% for ip, count in top_dst[:5] %}
                                    <div class="d-flex justify-content-between mb-2">
                                        <code>{{ ip[0] }}</code>
                                        <span>{{ ip[1] }}</span>
                                    </div>
                                    {% endfor %}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const filename = '{{ filename }}';
        let charts = {{ charts | tojson }};

        // Initialize charts
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
        });

        function initializeCharts() {
            // Protocol distribution chart
            if (charts.protocol_pie) {
                Plotly.newPlot('protocolChart', JSON.parse(charts.protocol_pie).data,
                              JSON.parse(charts.protocol_pie).layout);
            }

            // TCP chart
            if (charts.tcp_flags) {
                Plotly.newPlot('tcpChart', JSON.parse(charts.tcp_flags).data,
                              JSON.parse(charts.tcp_flags).layout);
            }

            // Detailed protocol chart (same as overview for now)
            if (charts.protocol_pie) {
                Plotly.newPlot('detailedProtocolChart', JSON.parse(charts.protocol_pie).data,
                              JSON.parse(charts.protocol_pie).layout);
            }
        }

        async function applyFilter() {
            const filterExpr = document.getElementById('filterInput').value.trim();
            if (!filterExpr) {
                alert('Please enter a filter expression');
                return;
            }

            const filterStatus = document.getElementById('filterStatus');
            filterStatus.innerHTML = '<div class="spinner-border spinner-border-sm me-2" role="status"></div>Applying filter...';

            try {
                const response = await fetch(`/api/filter/${filename}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ filter: filterExpr })
                });

                const result = await response.json();

                if (result.success) {
                    filterStatus.innerHTML = `<div class="alert alert-success">Filter applied! ${result.filtered_count} packets match.</div>`;
                    // Update charts with filtered data
                    updateChartsWithFilteredData(result.analysis);
                } else {
                    filterStatus.innerHTML = `<div class="alert alert-danger">Filter error: ${result.error}</div>`;
                }
            } catch (error) {
                filterStatus.innerHTML = `<div class="alert alert-danger">Error applying filter: ${error.message}</div>`;
            }
        }

        function updateChartsWithFilteredData(analysis) {
            // Update protocol chart
            if (analysis.protocols) {
                const protocolData = {
                    type: 'pie',
                    labels: Object.keys(analysis.protocols),
                    values: Object.values(analysis.protocols),
                    hole: 0.4
                };
                Plotly.react('protocolChart', [protocolData]);
                Plotly.react('detailedProtocolChart', [protocolData]);
            }
        }

        function exportAnalysis(format) {
            window.open(`/api/export/${filename}/${format}`, '_blank');
        }

        // Make functions global
        window.applyFilter = applyFilter;
        window.exportAnalysis = exportAnalysis;
    </script>
</body>
</html>""")
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.endswith('.pcap'):
        return jsonify({'error': 'Only .pcap files are supported'}), 400

    # Save uploaded file
    upload_dir = 'uploads'
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, file.filename)
    file.save(filepath)

    # Analyze the file
    try:
        analyzer = PacketMaster(filepath)
        analyzer.run_full_analysis()
        analysis_results[file.filename] = analyzer.analysis
        uploaded_files[file.filename] = filepath

        return jsonify({
            'success': True,
            'filename': file.filename,
            'packet_count': analyzer.analysis.get('basic', {}).get('total_packets', 0)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analysis/<filename>')
def get_analysis(filename):
    if filename not in analysis_results:
        return jsonify({'error': 'Analysis not found'}), 404

    return jsonify(analysis_results[filename])

@app.route('/dashboard/<filename>')
def dashboard(filename):
    if filename not in analysis_results:
        return "Analysis not found", 404

    analysis = analysis_results[filename]

    # Create charts
    charts = {}

    # Protocol breakdown pie chart
    if 'protocols' in analysis:
        protocols = analysis['protocols']
        charts['protocol_pie'] = create_pie_chart(protocols, "Protocol Distribution")

    # Basic stats
    basic_stats = analysis.get('basic', {})

    return render_template('dashboard.html',
                         filename=filename,
                         analysis=analysis,
                         charts=charts,
                         basic_stats=basic_stats)

@app.route('/reports')
def list_reports():
    report_dir = 'report'
    if not os.path.exists(report_dir):
        return jsonify([])

    reports = []
    for file in glob.glob(f'{report_dir}/*.json'):
        filename = os.path.basename(file)
        reports.append({
            'filename': filename,
            'path': file,
            'size': os.path.getsize(file),
            'modified': datetime.fromtimestamp(os.path.getmtime(file)).strftime('%Y-%m-%d %H:%M:%S')
        })

    return jsonify(reports)

@app.route('/download/<path:filename>')
def download_report(filename):
    return send_file(filename, as_attachment=True)

def create_pie_chart(data, title):
    """Create a Plotly pie chart"""
    fig = go.Figure(data=[go.Pie(
        labels=list(data.keys()),
        values=list(data.values()),
        title=title
    )])

    return plotly.utils.PlotlyJSONEncoder().encode(fig)

if __name__ == '__main__':
    # Create templates directory and files
    os.makedirs('templates', exist_ok=True)

    # Create index.html
    with open('templates/index.html', 'w') as f:
        f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>PacketMaster Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .upload-area { border: 2px dashed #ccc; padding: 20px; text-align: center; margin: 20px 0; }
        .file-list { margin: 20px 0; }
        .file-item { padding: 10px; border: 1px solid #ddd; margin: 5px 0; }
    </style>
</head>
<body>
    <h1>🚀 PacketMaster Web Dashboard</h1>

    <div class="upload-area">
        <h3>Upload PCAP File</h3>
        <form id="uploadForm" enctype="multipart/form-data">
            <input type="file" id="fileInput" accept=".pcap" required>
            <br><br>
            <button type="submit">Analyze File</button>
        </form>
        <div id="uploadStatus"></div>
    </div>

    <div class="file-list">
        <h3>Analyzed Files</h3>
        <div id="fileList"></div>
    </div>

    <script>
        document.getElementById('uploadForm').onsubmit = async (e) => {
            e.preventDefault();
            const formData = new FormData();
            formData.append('file', document.getElementById('fileInput').files[0]);

            const response = await fetch('/upload', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();
            document.getElementById('uploadStatus').innerHTML =
                result.success ? `✅ ${result.filename} analyzed successfully!` : `❌ ${result.error}`;

            if (result.success) {
                loadFileList();
            }
        };

        async function loadFileList() {
            const response = await fetch('/reports');
            const reports = await response.json();

            const fileList = document.getElementById('fileList');
            fileList.innerHTML = reports.map(report =>
                `<div class="file-item">
                    <strong>${report.filename}</strong>
                    <br>Modified: ${report.modified} | Size: ${report.size} bytes
                    <br><a href="/dashboard/${report.filename.replace('.json', '')}">View Dashboard</a>
                    <a href="/download/report/${report.filename}" style="margin-left: 10px;">Download</a>
                </div>`
            ).join('');
        }

        loadFileList();
    </script>
</body>
</html>
        """)

    # Create dashboard.html
    with open('templates/dashboard.html', 'w') as f:
        f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>PacketMaster Analysis Dashboard</title>
    <script src="https://cdn.plotly.com/plotly-latest.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .stats { display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0; }
        .stat-card { border: 1px solid #ddd; padding: 15px; border-radius: 5px; min-width: 200px; }
        .chart { margin: 20px 0; }
        .alerts { margin: 20px 0; }
        .alert { padding: 10px; margin: 5px 0; border-radius: 3px; }
        .alert-high { background: #ffdddd; border-left: 5px solid #ff0000; }
        .alert-medium { background: #ffffdd; border-left: 5px solid #ffaa00; }
        .alert-low { background: #ddffdd; border-left: 5px solid #00aa00; }
    </style>
</head>
<body>
    <h1>📊 PacketMaster Analysis: {{ filename }}</h1>
    <a href="/">← Back to Home</a>

    <div class="stats">
        <div class="stat-card">
            <h3>Total Packets</h3>
            <p>{{ basic_stats.total_packets | default(0) }}</p>
        </div>
        <div class="stat-card">
            <h3>Duration</h3>
            <p>{{ "%.2f"|format(basic_stats.duration | default(0)) }} sec</p>
        </div>
        <div class="stat-card">
            <h3>Packets/sec</h3>
            <p>{{ "%.1f"|format(basic_stats.pps | default(0)) }}</p>
        </div>
        <div class="stat-card">
            <h3>Throughput</h3>
            <p>{{ "%.2f"|format(basic_stats.throughput_mbps | default(0)) }} Mbps</p>
        </div>
    </div>

    <div class="chart">
        <h2>Protocol Distribution</h2>
        <div id="protocolChart"></div>
    </div>

    <div class="alerts">
        <h2>🛡️ Security Alerts</h2>
        {% if analysis.security and analysis.security.alerts %}
            {% for alert in analysis.security.alerts %}
                <div class="alert alert-{{ alert.severity | default('low') }}">
                    <strong>{{ alert.type | upper }}</strong>: {{ alert.message | default('') }}
                </div>
            {% endfor %}
        {% else %}
            <p>✅ No security alerts</p>
        {% endif %}
    </div>

    <script>
        // Load protocol chart
        fetch(`/analysis/{{ filename }}`)
            .then(response => response.json())
            .then(data => {
                if (data.protocols) {
                    const protocolData = {
                        type: 'pie',
                        labels: Object.keys(data.protocols),
                        values: Object.values(data.protocols)
                    };
                    Plotly.newPlot('protocolChart', [protocolData]);
                }
            });
    </script>
</body>
</html>
        """)

    app.run(debug=True, host='0.0.0.0', port=5001)