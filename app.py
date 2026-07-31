import sqlite3
import os
import json
import csv
import io
import random
import math
import threading
import time
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, session, redirect, render_template, Response
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

last_device_seen = {}
OFFLINE_SECONDS = 30

# Brute-force protection: lock an email out after repeated failed logins
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5'))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get('LOGIN_LOCKOUT_SECONDS', '300'))
_login_failures = {}  # email -> [failure_count, first_failure_timestamp]

def login_lockout_remaining(email):
    """Seconds left before a locked email can retry (0 = not locked)."""
    entry = _login_failures.get(email)
    if not entry or entry[0] < MAX_LOGIN_ATTEMPTS:
        return 0
    remaining = LOGIN_LOCKOUT_SECONDS - (time.time() - entry[1])
    if remaining <= 0:
        _login_failures.pop(email, None)
        return 0
    return int(remaining)

# Energy pricing (Ghana Cedi per kWh by default, configurable via env vars)
ENERGY_RATE_PER_KWH = float(os.environ.get('ENERGY_RATE', '0.80'))
CURRENCY_SYMBOL = os.environ.get('CURRENCY_SYMBOL', 'GH₵')

# Simulation & retention tuning
SIM_INTERVAL = float(os.environ.get('SIM_INTERVAL', '3'))       # seconds between readings
RETENTION_DAYS = int(os.environ.get('RETENTION_DAYS', '30'))    # keep readings for N days
ALERT_DEDUP_SECONDS = int(os.environ.get('ALERT_DEDUP_SECONDS', '300'))  # min gap between same alert type

# Default alert thresholds (per-device overrides are stored in the devices table).
# Values follow the project report (Ch. 5 findings): high-power >5000W and
# over-voltage >250V, under-voltage <200V, over-current >30A, temperatures 10-50C.
DEFAULT_THRESHOLDS = {
    'power': float(os.environ.get('THRESHOLD_POWER', '5000')),
    'voltage_min': float(os.environ.get('THRESHOLD_VOLTAGE_MIN', '200')),
    'voltage_max': float(os.environ.get('THRESHOLD_VOLTAGE_MAX', '250')),
    'current': float(os.environ.get('THRESHOLD_CURRENT', '30')),
    'temp_min': float(os.environ.get('THRESHOLD_TEMP_MIN', '10')),
    'temp_max': float(os.environ.get('THRESHOLD_TEMP_MAX', '50')),
}

# Maps threshold key -> devices table column
THRESHOLD_COLS = {
    'power': 'power_threshold',
    'voltage_min': 'voltage_min',
    'voltage_max': 'voltage_max',
    'current': 'current_max',
    'temp_min': 'temp_min',
    'temp_max': 'temp_max',
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('ENERGY_DB_PATH', os.path.join(BASE_DIR, 'energy.db'))
HOST = os.environ.get('HOST', '127.0.0.1')
SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(64).hex())

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'),
            static_folder=os.path.join(BASE_DIR, 'static'))
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
socketio = SocketIO(app, cors_allowed_origins='http://127.0.0.1:5000', async_mode='threading')
CORS(app, origins=['http://127.0.0.1:5000', 'http://localhost:5000'])

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            location TEXT NOT NULL,
            device_type TEXT DEFAULT 'smart_meter',
            is_active INTEGER DEFAULT 1,
            power_threshold REAL,
            voltage_min REAL,
            voltage_max REAL,
            current_max REAL,
            temp_min REAL,
            temp_max REAL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            voltage REAL,
            current REAL,
            power REAL,
            energy REAL,
            power_factor REAL,
            frequency REAL,
            temperature REAL,
            humidity REAL,
            timestamp TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (device_id) REFERENCES devices(id)
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT DEFAULT 'warning',
            acknowledged INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (device_id) REFERENCES devices(id)
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_readings_device_time ON readings(device_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_readings_time ON readings(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged, created_at);
    ''')
    # Migration: add per-device threshold columns to existing devices tables
    for col, coltype in ((THRESHOLD_COLS['power'], 'REAL'), (THRESHOLD_COLS['voltage_min'], 'REAL'),
                         (THRESHOLD_COLS['voltage_max'], 'REAL'), (THRESHOLD_COLS['current'], 'REAL'),
                         (THRESHOLD_COLS['temp_min'], 'REAL'), (THRESHOLD_COLS['temp_max'], 'REAL')):
        try:
            conn.execute(f'ALTER TABLE devices ADD COLUMN {col} {coltype}')
        except sqlite3.OperationalError:
            pass  # column already exists
    # Migration: add value/threshold columns to existing alerts tables
    for col, coltype in (('value', 'REAL'), ('threshold', 'REAL')):
        try:
            conn.execute(f'ALTER TABLE alerts ADD COLUMN {col} {coltype}')
        except sqlite3.OperationalError:
            pass  # column already exists
    # Seed global settings if empty
    if not conn.execute('SELECT 1 FROM settings LIMIT 1').fetchone():
        conn.execute('INSERT INTO settings (key, value) VALUES (?,?)', ('energy_rate', str(ENERGY_RATE_PER_KWH)))
        conn.execute('INSERT INTO settings (key, value) VALUES (?,?)', ('currency', CURRENCY_SYMBOL))
    conn.commit()
    cur = conn.execute('SELECT COUNT(*) as c FROM devices')
    if cur.fetchone()['c'] == 0:
        device_names = [
            ('Living Room Meter', 'Living Room'),
            ('Kitchen Meter', 'Kitchen'),
            ('Bedroom 1 Meter', 'Bedroom 1'),
            ('Bedroom 2 Meter', 'Bedroom 2'),
            ('Bedroom 3 Meter', 'Bedroom 3'),
            ('Home Office Meter', 'Home Office'),
            ('Garage Meter', 'Garage'),
            ('Basement Meter', 'Basement'),
            ('Dining Room Meter', 'Dining Room'),
            ('Hallway Meter', 'Hallway'),
            ('Bathroom 1 Meter', 'Bathroom 1'),
            ('Bathroom 2 Meter', 'Bathroom 2'),
            ('Laundry Room Meter', 'Laundry Room'),
            ('Storage Room Meter', 'Storage Room'),
            ('Guest Room Meter', 'Guest Room'),
            ('Garden Shed Meter', 'Garden Shed'),
            ('Study Room Meter', 'Study Room'),
            ('Game Room Meter', 'Game Room'),
            ('Home Theater Meter', 'Home Theater'),
            ('Rooftop Meter', 'Rooftop')
        ]
        for name, location in device_names:
            conn.execute('INSERT INTO devices (name, location) VALUES (?, ?)', (name, location))
        conn.commit()
        now = datetime.now()
        for dev_id in range(1, 21):
            base_v = random.uniform(220, 240)
            base_c = random.uniform(1, 15)
            for h in range(24 * 7):
                ts = now - timedelta(hours=24*7 - h)
                hour_factor = 1 + 0.3 * math.sin((ts.hour - 8) * math.pi / 12)
                v = base_v + random.uniform(-5, 5)
                c = base_c * hour_factor + random.uniform(-1, 1)
                c = max(0.1, c)
                pf = random.uniform(0.75, 0.99)
                p = v * c * pf
                e = p * 1 / 1000
                f = 50 + random.uniform(-0.5, 0.5)
                tmp = random.uniform(25, 40)
                hum = random.uniform(30, 70)
                conn.execute('''INSERT INTO readings
                    (device_id, voltage, current, power, energy, power_factor, frequency, temperature, humidity, timestamp)
                    VALUES (?,?,?,?,?,?,?,?,?,?)''',
                    (dev_id, round(v,2), round(c,3), round(p,2), round(e,3), round(pf,3), round(f,2),
                     round(tmp,1), round(hum,1), ts.isoformat()))
        conn.commit()
    conn.close()

SIMULATOR_RUNNING = True

def get_thresholds(device_row):
    """Return effective thresholds for a device (per-device overrides + defaults)."""
    t = dict(DEFAULT_THRESHOLDS)
    if device_row is not None:
        for key, col in THRESHOLD_COLS.items():
            if device_row[col] is not None:
                t[key] = device_row[col]
    return t

def alert_dedup_window(conn, device_id, alert_type, seconds=ALERT_DEDUP_SECONDS):
    """Return True when a recent unacknowledged alert of the same type exists,
    so the caller can skip inserting a duplicate."""
    cutoff = (datetime.now() - timedelta(seconds=seconds)).isoformat()
    row = conn.execute('''SELECT id FROM alerts
        WHERE device_id=? AND type=? AND created_at >= ?
        ORDER BY id DESC LIMIT 1''', (device_id, alert_type, cutoff)).fetchone()
    return row is not None

def evaluate_alerts(voltage=None, current=None, power=None, temperature=None, thresholds=None):
    """Alert engine: returns a list of alert dicts based on configurable thresholds.

    Thresholds follow the project specification:
      - Over-voltage:   voltage > voltage_max (default 250V, critical)
      - Under-voltage:  voltage < voltage_min (default 200V, warning)
      - Over-current:   current > current_max (default 30A, critical)
      - High power:     power > power_threshold (default 5000W per device, warning)
      - High temperature: temperature > temp_max (default 50C, critical)
      - Low temperature:  temperature < temp_min (default 10C, warning)
    """
    t = get_thresholds(None)
    if thresholds:
        t.update({k: v for k, v in thresholds.items() if v is not None})
    alerts = []
    if voltage is not None:
        if voltage > t['voltage_max']:
            alerts.append({'type': 'over_voltage', 'severity': 'critical',
                           'message': f'Over-voltage detected: {voltage:.1f}V (max {t["voltage_max"]:.0f}V)',
                           'value': round(voltage, 2), 'threshold': t['voltage_max']})
        if voltage < t['voltage_min']:
            alerts.append({'type': 'under_voltage', 'severity': 'warning',
                           'message': f'Under-voltage detected: {voltage:.1f}V (min {t["voltage_min"]:.0f}V)',
                           'value': round(voltage, 2), 'threshold': t['voltage_min']})
    if current is not None and current > t['current']:
        alerts.append({'type': 'over_current', 'severity': 'critical',
                       'message': f'Over-current detected: {current:.2f}A (max {t["current"]:.0f}A)',
                       'value': round(current, 2), 'threshold': t['current']})
    if power is not None and power > t['power']:
        alerts.append({'type': 'high_power', 'severity': 'warning',
                       'message': f'High power consumption: {power:.1f}W (max {t["power"]:.0f}W)',
                       'value': round(power, 1), 'threshold': t['power']})
    if temperature is not None:
        if temperature > t['temp_max']:
            alerts.append({'type': 'high_temperature', 'severity': 'critical',
                           'message': f'High temperature: {temperature:.1f}°C (max {t["temp_max"]:.0f}°C)',
                           'value': round(temperature, 1), 'threshold': t['temp_max']})
        if temperature < t['temp_min']:
            alerts.append({'type': 'low_temperature', 'severity': 'warning',
                           'message': f'Low temperature: {temperature:.1f}°C (min {t["temp_min"]:.0f}°C)',
                           'value': round(temperature, 1), 'threshold': t['temp_min']})
    return alerts

def simulate_readings():
    """Simulates 20 virtual smart metres every SIM_INTERVAL seconds.

    Matches the project spec: power 50-3000W with ±5% noise and occasional
    spike patterns, voltage 220-240V, current derived from power and voltage,
    energy in cumulative kWh, temperature 25-40C, humidity 30-70%.
    """
    global SIMULATOR_RUNNING, last_device_seen
    time.sleep(1)
    while SIMULATOR_RUNNING:
        try:
            conn = get_db()
            devices = conn.execute('''SELECT id, power_threshold, voltage_min, voltage_max,
                current_max, temp_min, temp_max FROM devices WHERE is_active=1''').fetchall()
            now_ts = datetime.now()
            now = now_ts.isoformat()
            for dev in devices:
                did = dev['id']
                thresholds = get_thresholds(dev)
                hour = now_ts.hour
                # Hourly load profile (higher in morning/evening) with ±5% noise
                profile = 0.5 + 0.5 * math.sin((hour - 8) * math.pi / 12)
                power = random.uniform(50, 3000) * (0.4 + 0.6 * profile) * random.uniform(0.95, 1.05)
                # Occasional spike patterns to exercise the alert engine
                if random.random() < 0.01:
                    power = random.uniform(thresholds['power'] * 1.1, thresholds['power'] * 2.0)
                power = max(10, min(9000, power))
                v = random.gauss(230, 5)
                v = max(180, min(265, v))
                pf = random.gauss(0.88, 0.05)
                pf = max(0.5, min(1.0, pf))
                # Current derived from power and voltage (spec 4.3.1)
                c = power / (v * pf)
                c = max(0.1, min(30, c))
                e = power * (SIM_INTERVAL / 3600) / 1000
                f = random.gauss(50, 0.2)
                tmp = random.gauss(32, 4)   # 25-40C ambient + device heat
                hum = random.gauss(50, 10)  # 30-70%
                tmp = max(10, min(55, tmp))
                hum = max(20, min(90, hum))
                conn.execute('''INSERT INTO readings
                    (device_id, voltage, current, power, energy, power_factor, frequency, temperature, humidity, timestamp)
                    VALUES (?,?,?,?,?,?,?,?,?,?)''',
                    (did, round(v,2), round(c,3), round(power,2), round(e,6), round(pf,3), round(f,2),
                     round(tmp,1), round(hum,1), now))
                last_device_seen[did] = now_ts
                for alert in evaluate_alerts(v, c, power, tmp, thresholds):
                    if not alert_dedup_window(conn, did, alert['type']):
                        conn.execute('''INSERT INTO alerts (device_id, type, message, severity, value, threshold)
                            VALUES (?,?,?,?,?,?)''',
                            (did, alert['type'], alert['message'], alert['severity'],
                             alert['value'], alert['threshold']))
            # Offline detection for ALL devices (active or not), 30s without a reading
            all_devices = conn.execute('SELECT id FROM devices').fetchall()
            for dev in all_devices:
                did = dev['id']
                last_seen = last_device_seen.get(did)
                if last_seen and (now_ts - last_seen).total_seconds() > OFFLINE_SECONDS:
                    existing = conn.execute(
                        "SELECT id FROM alerts WHERE device_id=? AND type='device_offline' AND acknowledged=0",
                        (did,)).fetchone()
                    if not existing:
                        conn.execute('''INSERT INTO alerts (device_id, type, message, severity, value, threshold)
                            VALUES (?,?,?,?,?,?)''',
                            (did, 'device_offline',
                             f'Device {did} is offline — no reading for {OFFLINE_SECONDS}s',
                             'critical', int((now_ts - last_seen).total_seconds()), OFFLINE_SECONDS))
                elif last_seen:
                    # Device is back online — auto-acknowledge any open offline alerts
                    conn.execute('''UPDATE alerts SET acknowledged=1
                        WHERE device_id=? AND type='device_offline' AND acknowledged=0''', (did,))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error('Simulator error: %s', e)
        time.sleep(SIM_INTERVAL)

def prune_old_data():
    """Delete readings older than RETENTION_DAYS to keep the database bounded."""
    cutoff = (datetime.now() - timedelta(days=RETENTION_DAYS)).isoformat()
    conn = get_db()
    cur = conn.execute('DELETE FROM readings WHERE timestamp < ?', (cutoff,))
    conn.commit()
    conn.close()
    if cur.rowcount:
        logger.info('Pruned %d readings older than %d days', cur.rowcount, RETENTION_DAYS)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard_page():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html', user_name=session.get('user_name', 'User'))

@app.route('/map')
def map_page():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('map.html', user_name=session.get('user_name', 'User'))

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    if not name or not email or not password:
        return jsonify({'error': 'Name, email, and password are required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'Email already registered'}), 409
    pw_hash = generate_password_hash(password)
    conn.execute('INSERT INTO users (name, email, password) VALUES (?,?,?)',
                 (name, email, pw_hash))
    conn.commit()
    user = conn.execute('SELECT id, name, email FROM users WHERE email=?', (email,)).fetchone()
    conn.close()
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']
    logger.info('User registered: %s', email)
    return jsonify({'name': user['name'], 'email': user['email']})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    # Brute-force protection: temporary lockout after repeated failures
    remaining = login_lockout_remaining(email)
    if remaining > 0:
        return jsonify({'error': f'Too many failed attempts. Try again in {remaining}s'}), 429
    conn = get_db()
    user = conn.execute('SELECT id, name, email, password FROM users WHERE email=?', (email,)).fetchone()
    conn.close()
    if not user or not check_password_hash(user['password'], password):
        entry = _login_failures.setdefault(email, [0, time.time()])
        entry[0] += 1
        logger.warning('Failed login for %s (attempt %d/%d)', email, entry[0], MAX_LOGIN_ATTEMPTS)
        if entry[0] >= MAX_LOGIN_ATTEMPTS:
            return jsonify({'error': f'Too many failed attempts. Try again in {LOGIN_LOCKOUT_SECONDS}s'}), 429
        return jsonify({'error': 'Invalid email or password'}), 401
    _login_failures.pop(email, None)
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']
    logger.info('User logged in: %s', email)
    return jsonify({'name': user['name'], 'email': user['email']})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/me')
@login_required
def api_me():
    return jsonify({'name': session['user_name'], 'email': session['user_email']})

@app.route('/api/devices')
@login_required
def api_devices():
    conn = get_db()
    devices = conn.execute('''SELECT id, name, location, device_type, is_active,
        power_threshold, voltage_min, voltage_max, current_max, temp_min, temp_max
        FROM devices''').fetchall()
    result = []
    for d in devices:
        last = conn.execute('''SELECT voltage, current, power, energy, power_factor, frequency, temperature, humidity, timestamp
            FROM readings WHERE device_id=? ORDER BY timestamp DESC LIMIT 1''', (d['id'],)).fetchone()
        alert_count = conn.execute('SELECT COUNT(*) as c FROM alerts WHERE device_id=? AND acknowledged=0',
                                   (d['id'],)).fetchone()['c']
        thresholds = get_thresholds(d)
        dev = {'id': d['id'], 'name': d['name'], 'location': d['location'],
               'device_type': d['device_type'], 'is_active': bool(d['is_active']),
               'alert_count': alert_count,
               'thresholds': thresholds}
        if last:
            dev.update({
                'voltage': last['voltage'], 'current': last['current'],
                'power': last['power'], 'energy': last['energy'],
                'power_factor': last['power_factor'], 'frequency': last['frequency'],
                'temperature': last['temperature'], 'humidity': last['humidity'],
                'last_reading': last['timestamp']
            })
        result.append(dev)
    conn.close()
    return jsonify(result)

def _parse_thresholds(data):
    """Extract optional per-device threshold overrides from a request payload."""
    thresholds = {}
    for key, col in THRESHOLD_COLS.items():
        if key in data and data[key] is not None:
            try:
                val = float(data[key])
                if val <= 0:
                    continue
                thresholds[key] = val
            except (TypeError, ValueError):
                continue
    return thresholds

@app.route('/api/devices', methods=['POST'])
@login_required
def api_device_create():
    data = request.json or {}
    name = data.get('name', '').strip()
    location = data.get('location', '').strip() or 'Unassigned'
    if not name:
        return jsonify({'error': 'Device name is required'}), 400
    conn = get_db()
    thresholds = _parse_thresholds(data)
    cur = conn.execute('''INSERT INTO devices (name, location, device_type, is_active,
            power_threshold, voltage_min, voltage_max, current_max, temp_min, temp_max)
        VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (name, location,
         data.get('device_type', 'smart_meter'),
         1 if data.get('is_active', True) else 0,
         thresholds.get('power'), thresholds.get('voltage_min'), thresholds.get('voltage_max'),
         thresholds.get('current'), thresholds.get('temp_min'), thresholds.get('temp_max')))
    conn.commit()
    device_id = cur.lastrowid
    conn.close()
    logger.info('Device created: %s (%s)', name, location)
    return jsonify({'ok': True, 'id': device_id}), 201

@app.route('/api/devices/<int:device_id>', methods=['PUT'])
@login_required
def api_device_update(device_id):
    data = request.json or {}
    conn = get_db()
    dev = conn.execute('SELECT * FROM devices WHERE id=?', (device_id,)).fetchone()
    if not dev:
        conn.close()
        return jsonify({'error': 'Device not found'}), 404
    name = data.get('name', dev['name']).strip() or dev['name']
    location = data.get('location', dev['location']).strip() or dev['location']
    device_type = data.get('device_type', dev['device_type'])
    is_active = data.get('is_active', bool(dev['is_active']))
    thresholds = _parse_thresholds(data)
    conn.execute('''UPDATE devices SET name=?, location=?, device_type=?, is_active=?,
        power_threshold=?, voltage_min=?, voltage_max=?, current_max=?, temp_min=?, temp_max=?
        WHERE id=?''',
        (name, location, device_type, 1 if is_active else 0,
         thresholds.get('power', dev['power_threshold']),
         thresholds.get('voltage_min', dev['voltage_min']),
         thresholds.get('voltage_max', dev['voltage_max']),
         thresholds.get('current', dev['current_max']),
         thresholds.get('temp_min', dev['temp_min']),
         thresholds.get('temp_max', dev['temp_max']),
         device_id))
    conn.commit()
    conn.close()
    logger.info('Device updated: %s', device_id)
    return jsonify({'ok': True})

@app.route('/api/devices/<int:device_id>', methods=['DELETE'])
@login_required
def api_device_delete(device_id):
    conn = get_db()
    dev = conn.execute('SELECT id FROM devices WHERE id=?', (device_id,)).fetchone()
    if not dev:
        conn.close()
        return jsonify({'error': 'Device not found'}), 404
    conn.execute('DELETE FROM readings WHERE device_id=?', (device_id,))
    conn.execute('DELETE FROM alerts WHERE device_id=?', (device_id,))
    conn.execute('DELETE FROM devices WHERE id=?', (device_id,))
    conn.commit()
    conn.close()
    last_device_seen.pop(device_id, None)
    logger.info('Device deleted: %s', device_id)
    return jsonify({'ok': True})

def _csv_response(rows, filename, fieldnames):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r[k] for k in fieldnames if k in r})
    return Response(buf.getvalue(), mimetype='text/csv', headers={
        'Content-Disposition': f'attachment; filename={filename}'
    })

@app.route('/api/export/readings')
@login_required
def api_export_readings():
    device_id = request.args.get('device_id', type=int)
    hours = request.args.get('hours', 24, type=int)
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = get_db()
    if device_id:
        rows = conn.execute('''SELECT r.*, d.name as device_name FROM readings r
            JOIN devices d ON r.device_id=d.id
            WHERE r.device_id=? AND r.timestamp >= ? ORDER BY r.timestamp ASC''',
            (device_id, cutoff)).fetchall()
        filename = f'readings_device_{device_id}_{hours}h.csv'
    else:
        rows = conn.execute('''SELECT r.*, d.name as device_name FROM readings r
            JOIN devices d ON r.device_id=d.id
            WHERE r.timestamp >= ? ORDER BY r.timestamp ASC''', (cutoff,)).fetchall()
        filename = f'readings_{hours}h.csv'
    conn.close()
    fieldnames = ['id', 'device_id', 'device_name', 'voltage', 'current', 'power',
                  'energy', 'power_factor', 'frequency', 'temperature', 'humidity', 'timestamp']
    return _csv_response(rows, filename, fieldnames)

@app.route('/api/export/alerts')
@login_required
def api_export_alerts():
    hours = request.args.get('hours', 168, type=int)
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = get_db()
    rows = conn.execute('''SELECT a.*, d.name as device_name FROM alerts a
        JOIN devices d ON a.device_id=d.id
        WHERE a.created_at >= ? ORDER BY a.created_at DESC''', (cutoff,)).fetchall()
    conn.close()
    fieldnames = ['id', 'device_id', 'device_name', 'type', 'message', 'severity',
                  'value', 'threshold', 'acknowledged', 'created_at']
    return _csv_response(rows, f'alerts_{hours}h.csv', fieldnames)

@app.route('/api/readings')
@login_required
def api_readings():
    device_id = request.args.get('device_id', type=int)
    limit = request.args.get('limit', 100, type=int)
    conn = get_db()
    if device_id:
        rows = conn.execute('''SELECT * FROM readings WHERE device_id=?
            ORDER BY timestamp DESC LIMIT ?''', (device_id, limit)).fetchall()
    else:
        rows = conn.execute('''SELECT r.* FROM readings r
            INNER JOIN (SELECT device_id, MAX(timestamp) as mt FROM readings GROUP BY device_id) l
            ON r.device_id=l.device_id AND r.timestamp=l.mt''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/readings/history')
@login_required
def api_readings_history():
    device_id = request.args.get('device_id', type=int)
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 2000, type=int)
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = get_db()
    if device_id:
        # Subquery keeps the NEWEST `limit` rows (previously the limit was
        # applied to the oldest rows, silently dropping recent data).
        rows = conn.execute('''SELECT * FROM (
            SELECT * FROM readings WHERE device_id=? AND timestamp >= ?
            ORDER BY timestamp DESC LIMIT ?
        ) ORDER BY timestamp ASC''', (device_id, cutoff, limit)).fetchall()
    else:
        rows = conn.execute('''SELECT * FROM (
            SELECT * FROM readings WHERE timestamp >= ?
            ORDER BY timestamp DESC LIMIT ?
        ) ORDER BY timestamp ASC''', (cutoff, limit)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/reading', methods=['POST'])
def api_ingest_reading():
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    device_id = data.get('device_id')
    if not device_id:
        return jsonify({'error': 'device_id required'}), 400
    conn = get_db()
    device = conn.execute('''SELECT id, power_threshold, voltage_min, voltage_max,
        current_max, temp_min, temp_max FROM devices WHERE id=?''', (device_id,)).fetchone()
    if not device:
        conn.close()
        return jsonify({'error': 'Unknown device'}), 404
    conn.execute('''INSERT INTO readings
        (device_id, voltage, current, power, energy, power_factor, frequency, temperature, humidity, timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (device_id,
         data.get('voltage'), data.get('current'), data.get('power'),
         data.get('energy'), data.get('power_factor'), data.get('frequency'),
         data.get('temperature'), data.get('humidity'),
         data.get('timestamp', datetime.now().isoformat())))
    # Run the alert engine on the incoming reading using the device's thresholds
    thresholds = get_thresholds(device)
    for alert in evaluate_alerts(data.get('voltage'), data.get('current'),
                                 data.get('power'), data.get('temperature'), thresholds):
        if not alert_dedup_window(conn, device_id, alert['type']):
            conn.execute('''INSERT INTO alerts (device_id, type, message, severity, value, threshold)
                VALUES (?,?,?,?,?,?)''',
                (device_id, alert['type'], alert['message'], alert['severity'],
                 alert['value'], alert['threshold']))
    conn.commit()
    last_id = conn.execute('SELECT last_insert_rowid() as id').fetchone()['id']
    conn.close()
    last_device_seen[device_id] = datetime.now()
    return jsonify({'ok': True, 'reading_id': last_id}), 201

@app.route('/api/alerts')
@login_required
def api_alerts():
    device_id = request.args.get('device_id', type=int)
    limit = request.args.get('limit', 50, type=int)
    pending_only = request.args.get('pending', 'false').lower() in ('1', 'true', 'yes')
    conn = get_db()
    if device_id:
        rows = conn.execute('''SELECT a.*, d.name as device_name FROM alerts a
            JOIN devices d ON a.device_id=d.id
            WHERE a.device_id=? {ack} ORDER BY a.created_at DESC LIMIT ?'''.format(
                ack='AND a.acknowledged=0' if pending_only else ''),
            (device_id, limit)).fetchall()
    else:
        rows = conn.execute('''SELECT a.*, d.name as device_name FROM alerts a
            JOIN devices d ON a.device_id=d.id
            WHERE 1=1 {ack} ORDER BY a.created_at DESC LIMIT ?'''.format(
                ack='AND a.acknowledged=0' if pending_only else ''),
            (limit,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/alerts/acknowledge', methods=['POST'])
@login_required
def api_alerts_acknowledge():
    data = request.json or {}
    alert_id = data.get('alert_id')
    conn = get_db()
    if alert_id is not None:
        row = conn.execute('SELECT id FROM alerts WHERE id=?', (alert_id,)).fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Alert not found'}), 404
        conn.execute('UPDATE alerts SET acknowledged=1 WHERE id=?', (alert_id,))
        conn.commit()
        conn.close()
        return jsonify({'ok': True})
    # Acknowledge all pending alerts
    cur = conn.execute('UPDATE alerts SET acknowledged=1 WHERE acknowledged=0')
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'updated': cur.rowcount})

@app.route('/api/readings/<int:device_id>')
@login_required
def api_readings_by_device(device_id):
    """Reading history for a single device (REST form documented in Ch. 4 §4.3.2)."""
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 2000, type=int)
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = get_db()
    rows = conn.execute('''SELECT * FROM (
        SELECT * FROM readings WHERE device_id=? AND timestamp >= ?
        ORDER BY timestamp DESC LIMIT ?
    ) ORDER BY timestamp ASC''', (device_id, cutoff, limit)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def api_alert_acknowledge_one(alert_id):
    """Acknowledge a single alert (REST form documented in Ch. 4 §4.3.2)."""
    conn = get_db()
    row = conn.execute('SELECT id FROM alerts WHERE id=?', (alert_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Alert not found'}), 404
    conn.execute('UPDATE alerts SET acknowledged=1 WHERE id=?', (alert_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

def get_setting(conn, key, default=None):
    row = conn.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    return row['value'] if row else default

@app.route('/api/settings')
@login_required
def api_settings_get():
    conn = get_db()
    energy_rate = float(get_setting(conn, 'energy_rate', str(ENERGY_RATE_PER_KWH)))
    currency = get_setting(conn, 'currency', CURRENCY_SYMBOL)
    defaults = get_thresholds(None)
    devices = conn.execute('''SELECT id, name, location, power_threshold, voltage_min,
        voltage_max, current_max, temp_min, temp_max FROM devices''').fetchall()
    conn.close()
    return jsonify({
        'energy_rate': energy_rate,
        'currency': currency,
        'defaults': defaults,
        'devices': [{
            'id': d['id'], 'name': d['name'], 'location': d['location'],
            'power': d['power_threshold'], 'voltage_min': d['voltage_min'],
            'voltage_max': d['voltage_max'], 'current': d['current_max'],
            'temp_min': d['temp_min'], 'temp_max': d['temp_max']
        } for d in devices]
    })

@app.route('/api/settings', methods=['PUT'])
@login_required
def api_settings_update():
    data = request.json or {}
    conn = get_db()
    if 'energy_rate' in data:
        try:
            rate = float(data['energy_rate'])
        except (TypeError, ValueError):
            conn.close()
            return jsonify({'error': 'Invalid energy rate'}), 400
        if rate <= 0 or rate > 100:
            conn.close()
            return jsonify({'error': 'Energy rate must be between 0 and 100'}), 400
        conn.execute('INSERT INTO settings (key, value) VALUES (?,?) '
                     'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                     ('energy_rate', str(rate)))
    if 'currency' in data:
        currency = str(data.get('currency', '')).strip()[:16]
        if currency:
            conn.execute('INSERT INTO settings (key, value) VALUES (?,?) '
                         'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                         ('currency', currency))
    # Per-device threshold overrides
    devices = data.get('devices') or []
    for entry in devices:
        if not isinstance(entry, dict) or 'id' not in entry:
            continue
        try:
            device_id = int(entry['id'])
        except (TypeError, ValueError):
            continue
        dev = conn.execute('SELECT id FROM devices WHERE id=?', (device_id,)).fetchone()
        if not dev:
            continue
        thresholds = _parse_thresholds(entry)
        conn.execute('''UPDATE devices SET
            power_threshold=?, voltage_min=?, voltage_max=?, current_max=?, temp_min=?, temp_max=?
            WHERE id=?''',
            (thresholds.get('power'), thresholds.get('voltage_min'), thresholds.get('voltage_max'),
             thresholds.get('current'), thresholds.get('temp_min'), thresholds.get('temp_max'),
             device_id))
    # Reset all devices to default thresholds
    if data.get('apply_defaults'):
        conn.execute('''UPDATE devices SET power_threshold=NULL, voltage_min=NULL,
            voltage_max=NULL, current_max=NULL, temp_min=NULL, temp_max=NULL''')
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/summary')
@login_required
def api_summary():
    now = datetime.now()
    day_cutoff = (now - timedelta(hours=24)).isoformat()
    hour_cutoff = (now - timedelta(hours=1)).isoformat()
    offline_cutoff = (now - timedelta(seconds=OFFLINE_SECONDS)).isoformat()
    conn = get_db()
    total_energy = conn.execute('SELECT SUM(energy) as e FROM readings WHERE timestamp >= ?',
                                (day_cutoff,)).fetchone()['e'] or 0
    device_count = conn.execute('SELECT COUNT(*) as c FROM devices WHERE is_active=1').fetchone()['c']
    offline_count = conn.execute('''SELECT COUNT(*) as c FROM devices d
        WHERE d.is_active=1 AND NOT EXISTS (
            SELECT 1 FROM readings r WHERE r.device_id=d.id AND r.timestamp >= ?)''',
        (offline_cutoff,)).fetchone()['c']
    active_alerts = conn.execute('SELECT COUNT(*) as c FROM alerts WHERE acknowledged=0').fetchone()['c']
    avg_power = conn.execute('SELECT AVG(power) as p FROM readings WHERE timestamp >= ?',
                             (hour_cutoff,)).fetchone()['p'] or 0
    peak_power = conn.execute('SELECT MAX(power) as p FROM readings WHERE timestamp >= ?',
                              (day_cutoff,)).fetchone()['p'] or 0
    energy_rate = float(get_setting(conn, 'energy_rate', str(ENERGY_RATE_PER_KWH)))
    currency = get_setting(conn, 'currency', CURRENCY_SYMBOL)
    conn.close()
    return jsonify({
        'total_energy_kwh': round(total_energy, 2),
        'daily_cost': round(total_energy * energy_rate, 2),
        'currency': currency,
        'energy_rate': energy_rate,
        'active_devices': device_count,
        'offline_devices': offline_count,
        'active_alerts': active_alerts,
        'avg_power_w': round(avg_power, 1),
        'peak_power_w': round(peak_power, 1)
    })

@app.route('/api/usage/ranking')
@login_required
def api_usage_ranking():
    hours = request.args.get('hours', 24, type=int)
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    conn = get_db()
    rows = conn.execute('''SELECT d.id, d.name, d.location, SUM(r.energy) as energy_kwh,
            MAX(r.power) as peak_power
        FROM readings r JOIN devices d ON r.device_id=d.id
        WHERE r.timestamp >= ?
        GROUP BY d.id ORDER BY energy_kwh DESC''', (cutoff,)).fetchall()
    energy_rate = float(get_setting(conn, 'energy_rate', str(ENERGY_RATE_PER_KWH)))
    conn.close()
    return jsonify([{
        'device_id': r['id'], 'name': r['name'], 'location': r['location'],
        'energy_kwh': round(r['energy_kwh'] or 0, 3),
        'cost': round((r['energy_kwh'] or 0) * energy_rate, 3),
        'peak_power': round(r['peak_power'] or 0, 1)
    } for r in rows])

@app.route('/api/usage/trend')
@login_required
def api_usage_trend():
    days = request.args.get('days', 7, type=int)
    days = max(1, min(90, days))
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    conn = get_db()
    rows = conn.execute('''SELECT substr(timestamp, 1, 10) as day, SUM(energy) as energy_kwh
        FROM readings WHERE timestamp >= ?
        GROUP BY day ORDER BY day ASC''', (cutoff,)).fetchall()
    energy_rate = float(get_setting(conn, 'energy_rate', str(ENERGY_RATE_PER_KWH)))
    conn.close()
    return jsonify([{
        'day': r['day'],
        'energy_kwh': round(r['energy_kwh'] or 0, 3),
        'cost': round((r['energy_kwh'] or 0) * energy_rate, 3)
    } for r in rows])

@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'Connected to energy monitor server'})

def broadcast_readings():
    while SIMULATOR_RUNNING:
        try:
            conn = get_db()
            # Use an ISO-formatted cutoff computed in Python so it compares
            # correctly against the ISO timestamps stored by the simulator
            # (SQLite's datetime("now", "-5 seconds") returns a space-separated
            # format that sorts differently).
            cutoff = (datetime.now() - timedelta(seconds=5)).isoformat()
            rows = conn.execute('''SELECT r.*, d.name as device_name, d.location
                FROM readings r JOIN devices d ON r.device_id=d.id
                WHERE r.timestamp >= ?
                ORDER BY r.device_id''', (cutoff,)).fetchall()
            if rows:
                socketio.emit('new_readings', [dict(r) for r in rows])
            alerts = conn.execute('''SELECT a.*, d.name as device_name FROM alerts a
                JOIN devices d ON a.device_id=d.id
                WHERE a.created_at >= ? AND a.acknowledged=0''', (cutoff,)).fetchall()
            if alerts:
                socketio.emit('new_alerts', [dict(a) for a in alerts])
            conn.close()
        except Exception as e:
            logger.error('Broadcast error: %s', e)
        time.sleep(3)

if __name__ == '__main__':
    try:
        logger.info('Initializing database...')
        init_db()
        logger.info('Pruning data older than %d days...', RETENTION_DAYS)
        prune_old_data()
        logger.info('Starting simulator thread...')
        sim_thread = threading.Thread(target=simulate_readings, daemon=True)
        sim_thread.start()
        logger.info('Starting broadcast thread...')
        bcast_thread = threading.Thread(target=broadcast_readings, daemon=True)
        bcast_thread.start()
        logger.info('Server starting at http://%s:5000', HOST)
        socketio.run(app, host=HOST, port=5000, debug=False)
    except KeyboardInterrupt:
        logger.info('Shutting down...')
        global SIMULATOR_RUNNING
        SIMULATOR_RUNNING = False
