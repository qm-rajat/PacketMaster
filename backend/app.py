"""
PacketMaster Advanced - Enhanced Flask Application
Integrates unified analyzer with modern API
"""
from flask import Flask, render_template, jsonify, request, send_file
import logging
import os
from datetime import datetime
from threading import Thread
import uuid

from backend.analyzer.core import UnifiedAnalyzer, auto_analyze
from backend.models.database import AnalysisRecord, ResultRecord, AlertRecord, init_db
from backend.api.analysis import analysis_bp
from backend.cache.cache import default_cache

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('PacketMasterApp')

# Create Flask app
app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max
app.config['UPLOAD_FOLDER'] = 'uploads'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
init_db()

# Register API blueprint
app.register_blueprint(analysis_bp)

# Global state for background jobs
analysis_jobs = {}


def analyze_background(analysis_id: str, filepath: str, filename: str):
    """Run analysis in background"""
    try:
        record = AnalysisRecord.get(analysis_id)
        record.status = 'running'
        record.save()
        
        logger.info(f"Starting analysis for {filename}...")
        
        # Run unified analysis
        try:
            analyzer = UnifiedAnalyzer(filepath)
            results, exec_time = analyzer.analyze()
            
            # Store results
            for key, value in results.items():
                result_record = ResultRecord(
                    str(uuid.uuid4()),
                    analysis_id,
                    key,
                    value
                )
                result_record.save()
            
            # Store security alerts
            if 'security' in results:
                for alert_data in results['security'].get('alerts', []):
                    alert = AlertRecord(
                        str(uuid.uuid4()),
                        analysis_id,
                        alert_data.get('type'),
                        alert_data.get('severity'),
                        alert_data.get('description')
                    )
                    alert.save()
            
            # Update record
            record = AnalysisRecord.get(analysis_id)
            record.status = 'complete'
            record.execution_time_seconds = exec_time
            record.packet_count = len(analyzer.packets)
            if 'security' in results:
                record.threat_score = results['security'].get('threat_score', 0)
            record.completed_at = datetime.now()
            record.save()
            
            # Cache results
            cache_data = {
                'analysis_id': analysis_id,
                'results': results,
                'timestamp': datetime.now().isoformat()
            }
            default_cache.set(filepath, cache_data)
            
            logger.info(f"✅ Analysis complete: {analysis_id}")
            analysis_jobs[analysis_id]['status'] = 'complete'
        
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            record = AnalysisRecord.get(analysis_id)
            record.status = 'error'
            record.save()
            analysis_jobs[analysis_id]['status'] = 'error'
            analysis_jobs[analysis_id]['error'] = str(e)
    
    except Exception as e:
        logger.error(f"Background analysis error: {e}")


@app.route('/')
def home():
    """Home page"""
    return render_template('index.html')


@app.route('/api/v1/upload', methods=['POST'])
def upload_file_v1():
    """Legacy upload endpoint (v1)"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if not file.filename.endswith('.pcap'):
            return jsonify({'error': 'Only .pcap files supported'}), 400
        
        # Save file
        filename = f"{uuid.uuid4()}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Create analysis record
        analysis_id = str(uuid.uuid4())
        record = AnalysisRecord(analysis_id, filename)
        record.pcap_size = os.path.getsize(filepath)
        record.save()
        
        # Start background analysis
        analysis_jobs[analysis_id] = {
            'status': 'running',
            'created_at': datetime.now().isoformat()
        }
        
        thread = Thread(
            target=analyze_background,
            args=(analysis_id, filepath, filename),
            daemon=True
        )
        thread.start()
        
        logger.info(f"File uploaded: {filename}, analysis_id: {analysis_id}")
        
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'filename': filename
        }), 202
    
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/status/<analysis_id>', methods=['GET'])
def get_status_v1(analysis_id):
    """Get analysis status (v1)"""
    try:
        record = AnalysisRecord.get(analysis_id)
        if not record:
            return jsonify({'error': 'Analysis not found'}), 404
        
        return jsonify({
            'analysis_id': analysis_id,
            'status': record.status,
            'threat_score': record.threat_score,
            'created_at': str(record.created_at),
            'completed_at': str(record.completed_at) if record.completed_at else None
        }), 200
    
    except Exception as e:
        logger.error(f"Status error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/results/<analysis_id>', methods=['GET'])
def get_results_v1(analysis_id):
    """Get analysis results (v1)"""
    try:
        results = ResultRecord.get_by_analysis(analysis_id)
        if not results:
            return jsonify({'error': 'Results not found'}), 404
        
        return jsonify(results), 200
    
    except Exception as e:
        logger.error(f"Results error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'version': '2.0',
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/dashboard', methods=['GET'])
def dashboard_data():
    """Dashboard data endpoint"""
    try:
        analyses = AnalysisRecord.get_all(10)
        
        # Calculate statistics
        total_analyses = len(analyses)
        avg_threat_score = sum(a.threat_score or 0 for a in analyses) / max(1, total_analyses)
        
        return jsonify({
            'statistics': {
                'total_analyses': total_analyses,
                'average_threat_score': round(avg_threat_score, 2),
                'completed': len([a for a in analyses if a.status == 'complete']),
                'running': len([a for a in analyses if a.status == 'running'])
            },
            'recent_analyses': [
                {
                    'id': a.id,
                    'filename': a.filename,
                    'status': a.status,
                    'threat_score': a.threat_score,
                    'created_at': str(a.created_at)
                }
                for a in analyses
            ]
        }), 200
    
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    logger.info("🚀 PacketMaster Advanced v2.0 starting...")
    app.run(debug=True, host='0.0.0.0', port=5001)
