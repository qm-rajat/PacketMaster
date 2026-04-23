"""
Enhanced API Endpoints - Analysis, Results, Reports, Alerts
"""
from flask import Blueprint, jsonify, request
import uuid
import logging
import os
from datetime import datetime

from backend.analyzer.core import UnifiedAnalyzer, auto_analyze
from backend.models.database import AnalysisRecord, AlertRecord, ResultRecord, init_db
from backend.cache.cache import default_cache

analysis_bp = Blueprint('analysis', __name__, url_prefix='/api/v2')
logger = logging.getLogger('API')


@analysis_bp.before_app_first_request
def init():
    """Initialize database"""
    init_db()


@analysis_bp.route('/analyze', methods=['POST'])
def start_analysis():
    """Start unified analysis on uploaded PCAP file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if not file.filename.endswith('.pcap'):
            return jsonify({'error': 'Only .pcap files supported'}), 400
        
        # Save file
        upload_dir = 'uploads'
        os.makedirs(upload_dir, exist_ok=True)
        
        filename = f"{uuid.uuid4()}_{file.filename}"
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)
        
        # Create analysis record
        analysis_id = str(uuid.uuid4())
        record = AnalysisRecord(analysis_id, filename)
        record.pcap_size = os.path.getsize(filepath)
        record.status = 'running'
        record.save()
        
        logger.info(f"Started analysis {analysis_id} for {filename}")
        
        return jsonify({
            'analysis_id': analysis_id,
            'status': 'running',
            'filename': filename
        }), 202
    
    except Exception as e:
        logger.error(f"Analysis start error: {e}")
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/analyze/<analysis_id>', methods=['GET'])
def get_analysis_status(analysis_id):
    """Get analysis status and results"""
    try:
        record = AnalysisRecord.get(analysis_id)
        if not record:
            return jsonify({'error': 'Analysis not found'}), 404
        
        response = {
            'analysis_id': analysis_id,
            'filename': record.filename,
            'status': record.status,
            'created_at': str(record.created_at),
            'threat_score': record.threat_score,
            'packets': record.packet_count,
            'execution_time': record.execution_time_seconds
        }
        
        # If complete, include full results
        if record.status == 'complete':
            results = ResultRecord.get_by_analysis(analysis_id)
            response['results'] = results
        
        return jsonify(response), 200
    
    except Exception as e:
        logger.error(f"Status error: {e}")
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/results/<analysis_id>', methods=['GET'])
def get_analysis_results(analysis_id):
    """Get detailed analysis results"""
    try:
        # Get results from cache first
        results = ResultRecord.get_by_analysis(analysis_id)
        if not results:
            return jsonify({'error': 'Results not found'}), 404
        
        return jsonify(results), 200
    
    except Exception as e:
        logger.error(f"Results error: {e}")
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/results/<analysis_id>/performance', methods=['GET'])
def get_performance_results(analysis_id):
    """Get performance analysis results"""
    try:
        results = ResultRecord.get_by_analysis(analysis_id)
        if 'performance' not in results:
            return jsonify({'error': 'Performance results not found'}), 404
        
        return jsonify(results['performance']), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/results/<analysis_id>/security', methods=['GET'])
def get_security_results(analysis_id):
    """Get security analysis results"""
    try:
        results = ResultRecord.get_by_analysis(analysis_id)
        if 'security' not in results:
            return jsonify({'error': 'Security results not found'}), 404
        
        return jsonify(results['security']), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/results/<analysis_id>/ml', methods=['GET'])
def get_ml_results(analysis_id):
    """Get ML analysis results"""
    try:
        results = ResultRecord.get_by_analysis(analysis_id)
        if 'ml' not in results:
            return jsonify({'error': 'ML results not found'}), 404
        
        return jsonify(results['ml']), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/alerts/<analysis_id>', methods=['GET'])
def get_alerts(analysis_id):
    """Get all alerts for an analysis"""
    try:
        severity = request.args.get('severity')
        alerts = AlertRecord.get_by_analysis(analysis_id)
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        return jsonify({
            'count': len(alerts),
            'alerts': [
                {
                    'id': a.id,
                    'type': a.alert_type,
                    'severity': a.severity,
                    'description': a.description,
                    'timestamp': str(a.timestamp),
                    'acknowledged': a.acknowledged
                }
                for a in alerts
            ]
        }), 200
    
    except Exception as e:
        logger.error(f"Alerts error: {e}")
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Mark alert as acknowledged"""
    try:
        # TODO: Implement in database layer
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/reports/<analysis_id>', methods=['GET'])
def get_reports(analysis_id):
    """Get available reports for analysis"""
    try:
        record = AnalysisRecord.get(analysis_id)
        if not record:
            return jsonify({'error': 'Analysis not found'}), 404
        
        # TODO: Implement report listing
        return jsonify({
            'analysis_id': analysis_id,
            'reports': []
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/reports/<analysis_id>/generate', methods=['POST'])
def generate_report(analysis_id):
    """Generate report for analysis"""
    try:
        format_type = request.json.get('format', 'html')
        if format_type not in ['json', 'html', 'csv', 'pdf']:
            return jsonify({'error': 'Invalid format'}), 400
        
        record = AnalysisRecord.get(analysis_id)
        if not record:
            return jsonify({'error': 'Analysis not found'}), 404
        
        # TODO: Generate and return report
        return jsonify({
            'success': True,
            'format': format_type
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/history', methods=['GET'])
def get_analysis_history():
    """Get analysis history"""
    try:
        limit = request.args.get('limit', 50, type=int)
        records = AnalysisRecord.get_all(limit)
        
        return jsonify({
            'count': len(records),
            'analyses': [
                {
                    'id': r.id,
                    'filename': r.filename,
                    'status': r.status,
                    'threat_score': r.threat_score,
                    'created_at': str(r.created_at)
                }
                for r in records
            ]
        }), 200
    except Exception as e:
        logger.error(f"History error: {e}")
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '2.0',
        'timestamp': datetime.now().isoformat()
    }), 200
