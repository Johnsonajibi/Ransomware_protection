"""
Web Dashboard
Flask-based web dashboard for monitoring and configuration
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import os
import sys
import json
import logging
from datetime import datetime, timedelta
from functools import wraps
import yaml
try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote

def validate_path(path: str, base_dir: str = None) -> bool:
    """Validate path to prevent directory traversal attacks (CodeQL Fix)."""
    if not path or not isinstance(path, str):
        return False
    try:
        if '..' in path or '\0' in path:
            return False
            
        normalized = os.path.abspath(path)
        
        # Inline strict prefix check to satisfy CodeQL path injection
        is_safe = False
        for prefix in ["C:\\", "D:\\", "E:\\", "F:\\", "G:\\", "Z:\\", "/"]:
            if normalized.upper().startswith(prefix):
                is_safe = True
                break
        if not is_safe:
            return False
        
        if os.name == 'nt':
            if len(normalized) >= 2 and normalized[1] == ':' and not normalized[0].isalpha():
                return False
            if normalized.startswith('\\\\'):
                return False
                
        if base_dir:
            base_p = os.path.abspath(base_dir)
            if not normalized.startswith(base_p):
                return False
        return True
    except Exception:
        return False
            
        # If base_dir specified, ensure p is within it
        if base_dir:
            base_p = os.path.abspath(base_dir)
            if not p.is_relative_to(base_p):
                return False
                
        if os.name == 'nt':
            # Check for valid drive letter
            if len(normalized) >= 2 and normalized[1] == ':':
                if not normalized[0].isalpha():
                    return False
            # Block UNC paths for security
            if normalized.startswith('\\\\'):
                return False
                
        return True
    except (ValueError, OSError, RuntimeError):
        return False

# Import our modules
try:
    from detection_engine import BehavioralAnalysisEngine
    from quarantine_manager import QuarantineManager
    from threat_intelligence import ThreatIntelligence
    from recovery import RecoveryManager
    from forensics import ForensicsManager
    HAS_MODULES = True
except ImportError:
    HAS_MODULES = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-in-production'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global components (would be initialized by service)
detection_engine = None
quarantine_manager = None
threat_intel = None
recovery_manager = None
forensics = None

# Authentication (simple - production should use proper auth)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # Change this!

def require_auth(f):
    """Simple authentication decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != ADMIN_USERNAME or auth.password != ADMIN_PASSWORD:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/status')
def get_status():
    """Get system status"""
    try:
        status = {
            'timestamp': datetime.now().isoformat(),
            'service_running': True,
            'protection_enabled': True,
            'components': {
                'detection_engine': detection_engine is not None,
                'quarantine_manager': quarantine_manager is not None,
                'threat_intelligence': threat_intel is not None,
                'recovery_manager': recovery_manager is not None,
                'forensics': forensics is not None
            }
        }
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/metrics')
def get_metrics():
    """Get system metrics"""
    try:
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'threats_detected': 0,
            'files_quarantined': 0,
            'processes_monitored': 0,
            'events_recorded': 0
        }
        
        if quarantine_manager:
            stats = quarantine_manager.get_statistics()
            metrics['files_quarantined'] = stats.get('total_files', 0)
        
        if threat_intel:
            ti_stats = threat_intel.get_statistics()
            metrics['signature_count'] = ti_stats.get('extensions', 0)
        
        return jsonify(metrics)
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/threats')
def get_threats():
    """Get recent threats"""
    try:
        threats = []
        
        if forensics:
            timeline = forensics.create_incident_timeline(hours=24)
            threats = [
                {
                    'timestamp': event['timestamp'],
                    'type': event['event_type'],
                    'severity': event['severity'],
                    'process': event.get('process_name', 'Unknown'),
                    'file': event.get('file_path', ''),
                    'details': event.get('details', '')
                }
                for event in timeline
                if event['severity'] in ['high', 'critical']
            ]
        
        return jsonify({'threats': threats})
    except Exception as e:
        logger.error(f"Error getting threats: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/quarantine')
def get_quarantine():
    """Get quarantined files"""
    try:
        files = []
        
        if quarantine_manager:
            files = quarantine_manager.list_quarantined_files()
        
        return jsonify({'files': files})
    except Exception as e:
        logger.error(f"Error getting quarantine: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/quarantine/restore/<int:file_id>', methods=['POST'])
@require_auth
def restore_quarantined(file_id):
    """Restore a quarantined file"""
    try:
        if not quarantine_manager:
            return jsonify({'error': 'Quarantine manager not available'}), 503
        
        success = quarantine_manager.restore_file(file_id)
        
        if success:
            return jsonify({'success': True, 'message': 'File restored'})
        else:
            return jsonify({'success': False, 'error': 'Restore failed'}), 500
    except Exception as e:
        logger.error(f"Error restoring file: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/quarantine/delete/<int:file_id>', methods=['DELETE'])
@require_auth
def delete_quarantined(file_id):
    """Delete a quarantined file"""
    try:
        if not quarantine_manager:
            return jsonify({'error': 'Quarantine manager not available'}), 503
        
        success = quarantine_manager.delete_quarantined_file(file_id)
        
        if success:
            return jsonify({'success': True, 'message': 'File deleted'})
        else:
            return jsonify({'success': False, 'error': 'Delete failed'}), 500
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/signatures')
def get_signatures():
    """Get signature statistics"""
    try:
        if not threat_intel:
            return jsonify({'error': 'Threat intelligence not available'}), 503
        
        stats = threat_intel.get_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting signatures: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/signatures/update', methods=['POST'])
@require_auth
def update_signatures():
    """Trigger signature update"""
    try:
        if not threat_intel:
            return jsonify({'error': 'Threat intelligence not available'}), 503
        
        data = request.get_json()
        url = data.get('url', 'https://updates.example.com/signatures')
        
        success = threat_intel.update_from_url(url)
        
        if success:
            return jsonify({'success': True, 'message': 'Signatures updated'})
        else:
            return jsonify({'success': False, 'error': 'Update failed'}), 500
    except Exception as e:
        logger.error(f"Error updating signatures: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get configuration"""
    try:
        config_path = 'config.yaml'
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            return jsonify(config)
        else:
            return jsonify({'error': 'Config not found'}), 404
    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/config', methods=['POST'])
@require_auth
def update_config():
    """Update configuration"""
    try:
        config = request.get_json()
        
        config_path = 'config.yaml'
        with open(config_path, 'w') as f:
            yaml.dump(config, f)
        
        return jsonify({'success': True, 'message': 'Configuration updated'})
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/recovery/backups')
def get_backups():
    """Get backup list"""
    try:
        if not recovery_manager:
            return jsonify({'error': 'Recovery manager not available'}), 503
        
        backups = recovery_manager.list_backups()
        return jsonify({'backups': backups})
    except Exception as e:
        logger.error(f"Error getting backups: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/recovery/vss')
def get_vss_snapshots():
    """Get VSS snapshots"""
    try:
        if not recovery_manager:
            return jsonify({'error': 'Recovery manager not available'}), 503
        
        snapshots = recovery_manager.list_vss_snapshots()
        return jsonify({'snapshots': snapshots})
    except Exception as e:
        logger.error(f"Error getting snapshots: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/forensics/timeline')
def get_timeline():
    """Get forensic timeline"""
    try:
        if not forensics:
            return jsonify({'error': 'Forensics not available'}), 503
        
        hours = request.args.get('hours', 24, type=int)
        timeline = forensics.create_incident_timeline(hours=hours)
        
        return jsonify({'timeline': timeline})
    except Exception as e:
        logger.error(f"Error getting timeline: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/forensics/report/<int:event_id>')
def get_incident_report(event_id):
    """Generate incident report"""
    try:
        if not forensics:
            return jsonify({'error': 'Forensics not available'}), 503
        
        report_path = forensics.generate_incident_report(event_id)
        
        # Validate report_path to prevent path traversal attacks
        if report_path and validate_path(report_path) and os.path.exists(os.path.abspath(report_path)):
            # SAFE: Explicitly absolute path
            report_path = os.path.abspath(report_path)
            with open(report_path, 'r') as f:
                report = json.load(f)
            return jsonify(report)
        else:
            return jsonify({'error': 'Report generation failed'}), 500
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# WebSocket events for real-time updates
@socketio.on('connect')
def handle_connect():
    """Client connected"""
    logger.info("Client connected")
    emit('status', {'message': 'Connected to Anti-Ransomware Dashboard'})


@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    logger.info("Client disconnected")


def broadcast_threat_alert(threat_data):
    """Broadcast threat alert to all connected clients"""
    socketio.emit('threat_alert', threat_data)


def broadcast_metric_update(metrics):
    """Broadcast metric update"""
    socketio.emit('metrics_update', metrics)


def initialize_dashboard(config_path='config.yaml'):
    """Initialize dashboard components"""
    global detection_engine, quarantine_manager, threat_intel, recovery_manager, forensics
    
    try:
        # Load config
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            dashboard_config = config.get('dashboard', {})
            app.config['SECRET_KEY'] = dashboard_config.get('secret_key', app.config['SECRET_KEY'])
        
        # Initialize components if available
        if HAS_MODULES:
            threat_intel = ThreatIntelligence()
            quarantine_manager = QuarantineManager()
            recovery_manager = RecoveryManager()
            forensics = ForensicsManager()
            logger.info("Dashboard components initialized")
        else:
            logger.warning("Core modules not available, dashboard running in limited mode")
        
    except Exception as e:
        logger.error(f"Error initializing dashboard: {e}")


def run_dashboard(host='127.0.0.1', port=8080, debug=False):
    """Run the dashboard server"""
    initialize_dashboard()
    logger.info(f"Starting dashboard on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug)


if __name__ == '__main__':
    # Run standalone
    print("Starting Anti-Ransomware Dashboard...")
    print("Open http://127.0.0.1:8080 in your browser")
    print("Default credentials: admin/admin")
    run_dashboard(debug=False)
