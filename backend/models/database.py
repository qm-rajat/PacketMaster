"""
Database Models - SQLAlchemy ORM for analysis tracking
"""
from datetime import datetime
from typing import Optional, Dict
import json

# Using SQLite with simple JSON storage for now (no SQLAlchemy dependency required)
import sqlite3
import os

DB_PATH = 'packetmaster.db'


def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database schema"""
    conn = get_db()
    c = conn.cursor()
    
    # Analysis records table
    c.execute('''
        CREATE TABLE IF NOT EXISTS analyses (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_hash TEXT,
            pcap_size INTEGER,
            packet_count INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            execution_time_seconds REAL,
            status TEXT DEFAULT 'pending',
            threat_score REAL,
            anomaly_count INTEGER
        )
    ''')
    
    # Analysis results storage
    c.execute('''
        CREATE TABLE IF NOT EXISTS analysis_results (
            id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL,
            result_type TEXT,
            result_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (analysis_id) REFERENCES analyses(id)
        )
    ''')
    
    # Alerts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL,
            alert_type TEXT,
            severity TEXT,
            description TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            acknowledged BOOLEAN DEFAULT 0,
            FOREIGN KEY (analysis_id) REFERENCES analyses(id)
        )
    ''')
    
    # Reports table
    c.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL,
            report_format TEXT,
            file_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (analysis_id) REFERENCES analyses(id)
        )
    ''')
    
    conn.commit()
    conn.close()


class AnalysisRecord:
    """Represents an analysis record"""
    
    def __init__(self, id: str, filename: str, packet_count: int = 0):
        self.id = id
        self.filename = filename
        self.file_hash = None
        self.pcap_size = 0
        self.packet_count = packet_count
        self.created_at = datetime.now()
        self.completed_at = None
        self.execution_time_seconds = None
        self.status = 'pending'
        self.threat_score = None
        self.anomaly_count = None
    
    def save(self):
        """Save record to database"""
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO analyses 
            (id, filename, file_hash, pcap_size, packet_count, created_at, completed_at, 
             execution_time_seconds, status, threat_score, anomaly_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            self.id, self.filename, self.file_hash, self.pcap_size, self.packet_count,
            self.created_at, self.completed_at, self.execution_time_seconds,
            self.status, self.threat_score, self.anomaly_count
        ))
        conn.commit()
        conn.close()
    
    @staticmethod
    def get(analysis_id: str) -> Optional['AnalysisRecord']:
        """Get record from database"""
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM analyses WHERE id = ?', (analysis_id,))
        row = c.fetchone()
        conn.close()
        
        if not row:
            return None
        
        record = AnalysisRecord(row['id'], row['filename'], row['packet_count'])
        record.file_hash = row['file_hash']
        record.pcap_size = row['pcap_size']
        record.created_at = row['created_at']
        record.completed_at = row['completed_at']
        record.execution_time_seconds = row['execution_time_seconds']
        record.status = row['status']
        record.threat_score = row['threat_score']
        record.anomaly_count = row['anomaly_count']
        return record
    
    @staticmethod
    def get_all(limit: int = 50) -> list:
        """Get all records"""
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM analyses ORDER BY created_at DESC LIMIT ?', (limit,))
        rows = c.fetchall()
        conn.close()
        
        records = []
        for row in rows:
            record = AnalysisRecord(row['id'], row['filename'])
            record.threat_score = row['threat_score']
            record.created_at = row['created_at']
            record.status = row['status']
            records.append(record)
        return records


class AlertRecord:
    """Represents an alert"""
    
    def __init__(self, id: str, analysis_id: str, alert_type: str, severity: str, description: str):
        self.id = id
        self.analysis_id = analysis_id
        self.alert_type = alert_type
        self.severity = severity
        self.description = description
        self.timestamp = datetime.now()
        self.acknowledged = False
    
    def save(self):
        """Save alert to database"""
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT INTO alerts (id, analysis_id, alert_type, severity, description, timestamp, acknowledged)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (self.id, self.analysis_id, self.alert_type, self.severity, self.description, 
              self.timestamp, self.acknowledged))
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_by_analysis(analysis_id: str) -> list:
        """Get all alerts for an analysis"""
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT * FROM alerts WHERE analysis_id = ? ORDER BY timestamp DESC
        ''', (analysis_id,))
        rows = c.fetchall()
        conn.close()
        
        alerts = []
        for row in rows:
            alert = AlertRecord(row['id'], row['analysis_id'], row['alert_type'], 
                               row['severity'], row['description'])
            alert.timestamp = row['timestamp']
            alert.acknowledged = bool(row['acknowledged'])
            alerts.append(alert)
        return alerts


class ResultRecord:
    """Represents analysis results"""
    
    def __init__(self, id: str, analysis_id: str, result_type: str, result_data: Dict):
        self.id = id
        self.analysis_id = analysis_id
        self.result_type = result_type
        self.result_data = result_data
        self.created_at = datetime.now()
    
    def save(self):
        """Save result to database"""
        conn = get_db()
        c = conn.cursor()
        result_json = json.dumps(self.result_data, default=str)
        c.execute('''
            INSERT INTO analysis_results (id, analysis_id, result_type, result_data, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (self.id, self.analysis_id, self.result_type, result_json, self.created_at))
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_by_analysis(analysis_id: str) -> Dict:
        """Get all results for an analysis"""
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT * FROM analysis_results WHERE analysis_id = ?
        ''', (analysis_id,))
        rows = c.fetchall()
        conn.close()
        
        results = {}
        for row in rows:
            results[row['result_type']] = json.loads(row['result_data'])
        return results
