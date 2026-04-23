from flask import Flask, render_template, jsonify, request, send_file
import json
import os
import glob
from datetime import datetime
from packetmaster import PacketMaster
import plotly.graph_objs as go
import plotly.utils
import pandas as pd

app = Flask(__name__)

# Global state for uploaded files
uploaded_files = {}
analysis_results = {}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
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