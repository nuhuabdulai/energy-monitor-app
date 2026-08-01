import sqlite3
import os
import json
import csv
import io
import random
import smtplib
from collections import deque
from email.message import EmailMessage
import math
import threading
import time
import logging
import urllib.request
from datetime import datetime, timedelta, timezone
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

# Email alert notifications (SMTP via stdlib; configure via env vars)
SMTP_HOST = os.environ.get('SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
EMAIL_FROM = os.environ.get('EMAIL_FROM', SMTP_USER)
EMAIL_THROTTLE_SECONDS = int(os.environ.get('EMAIL_THROTTLE_SECONDS', '600'))
_email_lock = threading.Lock()
_last_email_sent = 0.0

# Simulation & retention tuning
SIM_INTERVAL = float(os.environ.get('SIM_INTERVAL', '3'))       # seconds between readings
RETENTION_DAYS = int(os.environ.get('RETENTION_DAYS', '30'))    # keep readings for N days
ALERT_DEDUP_SECONDS = int(os.environ.get('ALERT_DEDUP_SECONDS', '300'))  # min gap between same alert type

# ML-style anomaly detection: rolling z-score over each device's recent power history
ANOMALY_WINDOW = int(os.environ.get('ANOMALY_WINDOW', '60'))          # readings kept per device
ANOMALY_MIN_SAMPLES = int(os.environ.get('ANOMALY_MIN_SAMPLES', '10'))  # window size before scoring
ANOMALY_ZSCORE = float(os.environ.get('ANOMALY_ZSCORE', '3.0'))        # sigma threshold for a flag
_power_history = {}  # device_id -> deque of recent power readings
_cumulative_energy = {}  # device_id -> running cumulative kWh counter (spec: energy is cumulative)

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
HOST = os.environ.get('HOST', '0.0.0.0')
PORT = int(os.environ.get('PORT', '5000'))
SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(64).hex())

# Simulator transport: the simulator (embedded in app.py or standalone
# simulator.py) sends every reading to the backend via HTTP POST /api/reading,
# matching the documented architecture (Ch. 3 §3.5, Ch. 4 §4.3.1 & §4.5).
SIMULATOR_SERVER_URL = os.environ.get('SIMULATOR_SERVER_URL', f'http://127.0.0.1:{PORT}').rstrip('/')
# When '1' (default) app.py runs the simulator in-process. Set EMBEDDED_SIMULATOR=0
# and run `python simulator.py` as a separate process instead.
EMBEDDED_SIMULATOR = os.environ.get('EMBEDDED_SIMULATOR', '1') == '1'

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'),
            static_folder=os.path.join(BASE_DIR, 'static'))
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
socketio = SocketIO(app, async_mode='threading')
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
            parameter TEXT,
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
    # Migration: add value/threshold/parameter columns to existing alerts tables
    for col, coltype in (('value', 'REAL'), ('threshold', 'REAL'), ('parameter', 'TEXT')):
        try:
            conn.execute(f'ALTER TABLE alerts ADD COLUMN {col} {coltype}')
        except sqlite3.OperationalError:
            pass  # column already exists
    # Seed global settings if empty
    if not conn.execute('SELECT 1 FROM settings LIMIT 1').fetchone():
        conn.execute('INSERT INTO settings (key, value) VALUES (?,?)', ('energy_rate', str(ENERGY_RATE_PER_KWH)))
        conn.execute('INSERT INTO settings (key, value) VALUES (?,?)', ('currency', CURRENCY_SYMBOL))
        conn.execute('INSERT INTO settings (key, value) VALUES (?,?)', ('email_alerts', '0'))
        conn.execute('INSERT INTO settings (key, value) VALUES (?,?)', ('email_recipient', ''))
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
            cum_kwh = random.uniform(20, 80)  # starting cumulative energy (kWh) baseline
            for h in range(24 * 7):
                ts = now - timedelta(hours=24*7 - h)
                hour_factor = 1 + 0.3 * math.sin((ts.hour - 8) * math.pi / 12)
                v = base_v + random.uniform(-5, 5)
                c = base_c * hour_factor + random.uniform(-1, 1)
                c = max(0.1, c)
                pf = random.uniform(0.75, 0.99)
                p = v * c * pf
                cum_kwh += p * 1 / 1000  # energy is cumulative kWh (spec Ch. 4 §4.4)
                f = 50 + random.uniform(-0.5, 0.5)
                tmp = random.uniform(25, 40)
                hum = random.uniform(30, 70)
                conn.execute('''INSERT INTO readings
                    (device_id, voltage, current, power, energy, power_factor, frequency, temperature, humidity, timestamp)
                    VALUES (?,?,?,?,?,?,?,?,?,?)''',
                    (dev_id, round(v,2), round(c,3), round(p,2), round(cum_kwh,3), round(pf,3), round(f,2),
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
    so the caller can skip inserting a duplicate.

    Alerts store timestamps with SQLite's datetime('now') (UTC, space-separated,
    e.g. "2026-08-01 06:00:00"), so the cutoff must use the same format. Using
    datetime.now().isoformat() here produced "2026-08-01T06:00:00.123456" which
    sorts AFTER every stored alert and silently defeated the dedup.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime('%Y-%m-%d %H:%M:%S')
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
            alerts.append({'type': 'over_voltage', 'parameter': 'voltage', 'severity': 'critical',
                           'message': f'Over-voltage detected: {voltage:.1f}V (max {t["voltage_max"]:.0f}V)',
                           'value': round(voltage, 2), 'threshold': t['voltage_max']})
        if voltage < t['voltage_min']:
            alerts.append({'type': 'under_voltage', 'parameter': 'voltage', 'severity': 'warning',
                           'message': f'Under-voltage detected: {voltage:.1f}V (min {t["voltage_min"]:.0f}V)',
                           'value': round(voltage, 2), 'threshold': t['voltage_min']})
    if current is not None and current > t['current']:
        alerts.append({'type': 'over_current', 'parameter': 'current', 'severity': 'critical',
                       'message': f'Over-current detected: {current:.2f}A (max {t["current"]:.0f}A)',
                       'value': round(current, 2), 'threshold': t['current']})
    if power is not None and power > t['power']:
        alerts.append({'type': 'high_power', 'parameter': 'power', 'severity': 'warning',
                       'message': f'High power consumption: {power:.1f}W (max {t["power"]:.0f}W)',
                       'value': round(power, 1), 'threshold': t['power']})
    if temperature is not None:
        if temperature > t['temp_max']:
            alerts.append({'type': 'high_temperature', 'parameter': 'temperature', 'severity': 'critical',
                           'message': f'High temperature: {temperature:.1f}°C (max {t["temp_max"]:.0f}°C)',
                           'value': round(temperature, 1), 'threshold': t['temp_max']})
        if temperature < t['temp_min']:
            alerts.append({'type': 'low_temperature', 'parameter': 'temperature', 'severity': 'warning',
                           'message': f'Low temperature: {temperature:.1f}°C (min {t["temp_min"]:.0f}°C)',
                           'value': round(temperature, 1), 'threshold': t['temp_min']})
    return alerts

def detect_power_anomaly(device_id, power):
    """ML-style anomaly detection: rolling z-score over a device's recent power.

    Keeps a per-device rolling window of power readings. Once the window has
    ANOMALY_MIN_SAMPLES samples, the latest reading is scored against the
    window's own mean and standard deviation. Readings deviating by more than
    ANOMALY_ZSCORE standard deviations are flagged as anomalies. The current
    reading is excluded from the baseline so a spike cannot mask itself.
    """
    hist = _power_history.setdefault(device_id, deque(maxlen=ANOMALY_WINDOW))
    result = None
    if len(hist) >= ANOMALY_MIN_SAMPLES:
        values = list(hist)
        mean = sum(values) / len(values)
        var = sum((x - mean) ** 2 for x in values) / len(values)
        std = math.sqrt(var)
        if std > 1e-6:
            z = (power - mean) / std
            if abs(z) >= ANOMALY_ZSCORE:
                result = {'type': 'anomaly', 'parameter': 'power', 'severity': 'warning',
                          'message': f'Unusual power consumption detected: {power:.0f}W ({z:+.1f}σ from device baseline)',
                          'value': round(power, 1), 'threshold': round(mean + ANOMALY_ZSCORE * std, 1)}
    hist.append(power)
    return result

def generate_reading(thresholds, now_ts):
    """Generate one realistic reading dict (spec Ch. 4 §4.3.1).

    - Power: 50-3000W with ±5% noise, plus occasional spike patterns
    - Voltage: 220-240V (standard residential range)
    - Current: derived from power and voltage (0.5-40A, spikes may exceed 30A)
    - Temperature: 25-40C, Humidity: 30-70%, Frequency: ~50Hz
    """
    hour = now_ts.hour
    # Hourly load profile (higher in morning/evening) with ±5% noise
    profile = 0.5 + 0.5 * math.sin((hour - 8) * math.pi / 12)
    power = random.uniform(50, 3000) * (0.4 + 0.6 * profile) * random.uniform(0.95, 1.05)
    # Occasional spike patterns to exercise the alert engine
    if random.random() < 0.01:
        power = random.uniform(thresholds['power'] * 1.1, thresholds['power'] * 2.0)
    power = max(10, min(9000, power))
    v = random.gauss(230, 4)
    v = max(220, min(240, v))
    pf = random.gauss(0.88, 0.05)
    pf = max(0.5, min(1.0, pf))
    # Current derived from power and voltage; clamp allows spike-driven over-current
    c = power / (v * pf)
    c = max(0.1, min(40, c))
    f = random.gauss(50, 0.2)
    tmp = random.gauss(32, 4)   # 25-40C ambient + device heat
    hum = random.gauss(50, 10)  # 30-70%
    tmp = max(25, min(40, tmp))
    hum = max(30, min(70, hum))
    return {'voltage': round(v, 2), 'current': round(c, 3), 'power': round(power, 2),
            'power_factor': round(pf, 3), 'frequency': round(f, 2),
            'temperature': round(tmp, 1), 'humidity': round(hum, 1)}

def add_cumulative_energy(device_id, power):
    """Increment a device's cumulative energy (kWh) by this interval's delta."""
    delta = power * (SIM_INTERVAL / 3600) / 1000
    _cumulative_energy[device_id] = _cumulative_energy.get(device_id, 0.0) + delta
    return _cumulative_energy[device_id]

def init_cumulative_energy():
    """Load each device's last stored (cumulative) energy so a restart continues
    from the persisted value instead of resetting to zero."""
    try:
        conn = get_db()
        rows = conn.execute('''SELECT device_id, energy FROM readings
            WHERE id IN (SELECT MAX(id) FROM readings GROUP BY device_id)''').fetchall()
        for r in rows:
            if r['energy'] is not None:
                _cumulative_energy[r['device_id']] = float(r['energy'])
        conn.close()
    except Exception as e:
        logger.error('init_cumulative_energy error: %s', e)

def post_reading(payload):
    """Send one JSON reading to the backend /api/reading endpoint over HTTP."""
    try:
        req = urllib.request.Request(
            f'{SIMULATOR_SERVER_URL}/api/reading',
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST')
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 201
    except Exception as e:
        logger.error('Simulator POST failed (device %s): %s', payload.get('device_id'), e)
        return False

def simulate_readings():
    """Simulates 20 virtual smart metres every SIM_INTERVAL seconds and sends
    each reading to the backend via HTTP POST /api/reading (spec Ch. 4 §4.3.1).

    The simulator only generates and transports readings — storage, the alert
    engine, anomaly detection and offline monitoring all run on the backend.
    """
    global SIMULATOR_RUNNING
    time.sleep(1)
    init_cumulative_energy()
    while SIMULATOR_RUNNING:
        try:
            conn = get_db()
            devices = conn.execute('''SELECT id, name, power_threshold, voltage_min, voltage_max,
                current_max, temp_min, temp_max FROM devices WHERE is_active=1''').fetchall()
            conn.close()
            now_ts = datetime.now()
            for dev in devices:
                did = dev['id']
                thresholds = get_thresholds(dev)
                reading = generate_reading(thresholds, now_ts)
                reading['energy'] = round(add_cumulative_energy(did, reading['power']), 6)
                post_reading({'device_id': did, **reading})
        except Exception as e:
            logger.error('Simulator error: %s', e)
        time.sleep(SIM_INTERVAL)

def check_offline_devices(conn, now_ts):
    """Insert (or auto-acknowledge) device_offline alerts based on last seen time.

    Runs on the backend so it works with both the embedded simulator and a
    separate simulator.py process (spec Ch. 4 §4.3.3, OFFLINE_SECONDS = 30s).
    Returns True if any new alert was inserted.
    """
    changed = False
    all_devices = conn.execute('SELECT id FROM devices').fetchall()
    for dev in all_devices:
        did = dev['id']
        last_seen = last_device_seen.get(did)
        if last_seen and (now_ts - last_seen).total_seconds() > OFFLINE_SECONDS:
            existing = conn.execute(
                "SELECT id FROM alerts WHERE device_id=? AND type='device_offline' AND acknowledged=0",
                (did,)).fetchone()
            if not existing:
                conn.execute('''INSERT INTO alerts (device_id, type, parameter, message, severity, value, threshold)
                    VALUES (?,?,?,?,?,?,?)''',
                    (did, 'device_offline', 'device',
                     f'Device {did} is offline — no reading for {OFFLINE_SECONDS}s',
                     'critical', int((now_ts - last_seen).total_seconds()), OFFLINE_SECONDS))
                changed = True
        elif last_seen:
            # Device is back online — auto-acknowledge any open offline alerts
            conn.execute('''UPDATE alerts SET acknowledged=1
                WHERE device_id=? AND type='device_offline' AND acknowledged=0''', (did,))
    return changed

def offline_monitor():
    """Background thread: raises device-offline alerts when a device stops
    sending readings (runs on the backend, independent of the simulator)."""
    global SIMULATOR_RUNNING
    while SIMULATOR_RUNNING:
        try:
            conn = get_db()
            check_offline_devices(conn, datetime.now())
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error('Offline monitor error: %s', e)
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

# PWA support: manifest + service worker served from the root so the worker
# scope covers the whole app (Ch. 5 recommendation: mobile experience).
@app.route('/manifest.webmanifest')
def webmanifest():
    resp = app.send_static_file('manifest.webmanifest')
    resp.headers['Content-Type'] = 'application/manifest+json'
    resp.headers['Cache-Control'] = 'no-cache'
    return resp

@app.route('/sw.js')
def service_worker():
    resp = app.send_static_file('sw.js')
    resp.headers['Content-Type'] = 'application/javascript'
    resp.headers['Cache-Control'] = 'no-cache'
    return resp

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
    fieldnames = ['id', 'device_id', 'device_name', 'type', 'parameter', 'message', 'severity',
                  'value', 'threshold', 'acknowledged', 'created_at']
    return _csv_response(rows, f'alerts_{hours}h.csv', fieldnames)

def _bucket_expr(period):
    """SQLite expression that buckets a reading timestamp into a report period."""
    if period == 'weekly':
        return "date(timestamp, 'weekday 0', '-6 days')"
    if period == 'monthly':
        return "strftime('%Y-%m', timestamp)"
    return "date(timestamp)"

def _report_rows(conn, period, cutoff, rate):
    """Aggregated energy/cost per period, ready for both JSON and CSV use.

    Energy is stored as cumulative kWh (spec Ch. 4 §4.4), so the energy used in
    a bucket is the per-device (MAX - MIN) of the cumulative readings, summed
    across devices.
    """
    bucket = _bucket_expr(period)
    rows = conn.execute(f'''SELECT {bucket} AS label, device_id,
            MAX(energy) AS mx, MIN(energy) AS mn,
            MAX(power) AS peak_power, COUNT(*) AS reading_count
        FROM readings WHERE timestamp >= ? AND energy IS NOT NULL
        GROUP BY label, device_id ORDER BY label ASC''', (cutoff,)).fetchall()
    agg = {}
    for r in rows:
        d = agg.setdefault(r['label'], {'energy_kwh': 0.0, 'peak_power': 0.0, 'reading_count': 0})
        d['energy_kwh'] += max(0.0, (r['mx'] or 0.0) - (r['mn'] or 0.0))
        d['peak_power'] = max(d['peak_power'], r['peak_power'] or 0.0)
        d['reading_count'] += r['reading_count']
    return [{'label': label, 'energy_kwh': round(v['energy_kwh'], 3),
             'cost': round(v['energy_kwh'] * rate, 2),
             'peak_power': round(v['peak_power'], 1), 'reading_count': v['reading_count']}
            for label, v in sorted(agg.items())]

@app.route('/api/reports')
@login_required
def api_reports():
    """Historical cost analytics: energy and cost bucketed daily/weekly/monthly."""
    period = request.args.get('period', 'daily')
    if period not in ('daily', 'weekly', 'monthly'):
        return jsonify({'error': 'period must be daily, weekly or monthly'}), 400
    days = min(request.args.get('days', 30, type=int), 90)
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    conn = get_db()
    rate = float(get_setting(conn, 'energy_rate', str(ENERGY_RATE_PER_KWH)))
    currency = get_setting(conn, 'currency', CURRENCY_SYMBOL)
    data = _report_rows(conn, period, cutoff, rate)
    top_devices = conn.execute('''SELECT d.name,
            (MAX(r.energy) - MIN(r.energy)) AS energy_kwh
        FROM readings r JOIN devices d ON r.device_id=d.id
        WHERE r.timestamp >= ? AND r.energy IS NOT NULL
        GROUP BY d.id ORDER BY energy_kwh DESC LIMIT 5''', (cutoff,)).fetchall()
    conn.close()
    total_energy = round(sum(r['energy_kwh'] for r in data), 3)
    return jsonify({
        'period': period, 'days': days, 'currency': currency, 'rate': rate,
        'rows': data,
        'totals': {'energy_kwh': total_energy, 'cost': round(total_energy * rate, 2),
                   'peak_power': max((r['peak_power'] for r in data), default=0)},
        'top_devices': [{'name': d['name'], 'energy_kwh': round(max(0.0, d['energy_kwh'] or 0.0), 3),
                         'cost': round(max(0.0, d['energy_kwh'] or 0.0) * rate, 2)} for d in top_devices]
    })

@app.route('/api/reports/export')
@login_required
def api_reports_export():
    period = request.args.get('period', 'daily')
    if period not in ('daily', 'weekly', 'monthly'):
        return jsonify({'error': 'period must be daily, weekly or monthly'}), 400
    days = min(request.args.get('days', 30, type=int), 90)
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    conn = get_db()
    rate = float(get_setting(conn, 'energy_rate', str(ENERGY_RATE_PER_KWH)))
    rows = _report_rows(conn, period, cutoff, rate)
    conn.close()
    out = [{'period': r['label'], 'energy_kwh': r['energy_kwh'], 'cost': r['cost'],
            'peak_power': r['peak_power'], 'reading_count': r['reading_count']} for r in rows]
    return _csv_response(out, f'report_{period}_{days}d.csv',
                         ['period', 'energy_kwh', 'cost', 'peak_power', 'reading_count'])

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
    device = conn.execute('''SELECT id, name, power_threshold, voltage_min, voltage_max,
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
            conn.execute('''INSERT INTO alerts (device_id, type, parameter, message, severity, value, threshold)
                VALUES (?,?,?,?,?,?,?)''',
                (device_id, alert['type'], alert['parameter'], alert['message'], alert['severity'],
                 alert['value'], alert['threshold']))
            maybe_email_alert(conn, device['name'], alert)
    # ML-style anomaly detection: flag readings that deviate strongly from the
    # device's recent power baseline (rolling z-score)
    try:
        power_val = float(data.get('power'))
    except (TypeError, ValueError):
        power_val = None
    if power_val is not None:
        anomaly = detect_power_anomaly(device_id, power_val)
        if anomaly and not alert_dedup_window(conn, device_id, anomaly['type']):
            conn.execute('''INSERT INTO alerts (device_id, type, parameter, message, severity, value, threshold)
                VALUES (?,?,?,?,?,?,?)''',
                (device_id, anomaly['type'], anomaly['parameter'], anomaly['message'], anomaly['severity'],
                 anomaly['value'], anomaly['threshold']))
            maybe_email_alert(conn, device['name'], anomaly)
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

def email_notifications_enabled(conn):
    """True when email alerts are enabled in settings AND SMTP is configured."""
    if get_setting(conn, 'email_alerts', '0') != '1':
        return False
    if not (SMTP_HOST and SMTP_USER and SMTP_PASSWORD):
        logger.warning('Email alerts are enabled but SMTP is not configured '
                       '(set SMTP_HOST, SMTP_USER, SMTP_PASSWORD env vars)')
        return False
    return True

def maybe_email_alert(conn, device_name, alert):
    """Rate-limited dispatch of an alert email (sent in a background thread).

    At most one email per EMAIL_THROTTLE_SECONDS, so a flapping alert cannot
    flood the recipient's inbox.
    """
    global _last_email_sent
    if not email_notifications_enabled(conn):
        return False
    with _email_lock:
        now = time.time()
        if now - _last_email_sent < EMAIL_THROTTLE_SECONDS:
            return False
        _last_email_sent = now
    recipient = get_setting(conn, 'email_recipient', '').strip()
    if not recipient:
        return False
    subject = f'[Smart Energy Monitor] {alert["type"]} alert on {device_name}'
    body = (f'An alert was raised on device "{device_name}":\n\n'
            f'  Type:     {alert["type"]}\n'
            f'  Severity: {alert["severity"]}\n'
            f'  Message:  {alert["message"]}\n'
            f'  Time:     {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n'
            'Log in to the dashboard for live details.')
    threading.Thread(target=_send_email_async, args=(recipient, subject, body), daemon=True).start()
    logger.info('Alert email queued for %s (%s)', recipient, alert['type'])
    return True

def _send_email_async(recipient, subject, body):
    """Deliver the email with smtplib; failures are logged, never crash the app."""
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM or SMTP_USER
        msg['To'] = recipient
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        logger.info('Alert email sent to %s', recipient)
    except Exception as e:
        logger.error('Failed to send alert email: %s', e)

@app.route('/api/settings')
@login_required
def api_settings_get():
    conn = get_db()
    energy_rate = float(get_setting(conn, 'energy_rate', str(ENERGY_RATE_PER_KWH)))
    currency = get_setting(conn, 'currency', CURRENCY_SYMBOL)
    email_alerts = get_setting(conn, 'email_alerts', '0')
    email_recipient = get_setting(conn, 'email_recipient', '')
    defaults = get_thresholds(None)
    devices = conn.execute('''SELECT id, name, location, power_threshold, voltage_min,
        voltage_max, current_max, temp_min, temp_max FROM devices''').fetchall()
    conn.close()
    return jsonify({
        'energy_rate': energy_rate,
        'currency': currency,
        'email_alerts': email_alerts,
        'email_recipient': email_recipient,
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
    if 'email_alerts' in data:
        val = '1' if data.get('email_alerts') in (True, 1, '1', 'true', 'on') else '0'
        conn.execute('INSERT INTO settings (key, value) VALUES (?,?) '
                     'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                     ('email_alerts', val))
    if 'email_recipient' in data:
        recipient = str(data.get('email_recipient', '')).strip()[:254]
        if recipient and '@' not in recipient:
            conn.close()
            return jsonify({'error': 'Invalid email address'}), 400
        conn.execute('INSERT INTO settings (key, value) VALUES (?,?) '
                     'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                     ('email_recipient', recipient))
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
    total_energy = 0.0
    # Energy is cumulative (spec Ch. 4 §4.4): consumption in the window is the
    # per-device (MAX - MIN) of the cumulative readings, summed across devices.
    for r in conn.execute('''SELECT MAX(energy) AS mx, MIN(energy) AS mn
        FROM readings WHERE timestamp >= ? AND energy IS NOT NULL
        GROUP BY device_id''', (day_cutoff,)).fetchall():
        total_energy += max(0.0, (r['mx'] or 0.0) - (r['mn'] or 0.0))
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
    rows = conn.execute('''SELECT d.id, d.name, d.location,
            (MAX(r.energy) - MIN(r.energy)) as energy_kwh,
            MAX(r.power) as peak_power
        FROM readings r JOIN devices d ON r.device_id=d.id
        WHERE r.timestamp >= ? AND r.energy IS NOT NULL
        GROUP BY d.id ORDER BY energy_kwh DESC''', (cutoff,)).fetchall()
    energy_rate = float(get_setting(conn, 'energy_rate', str(ENERGY_RATE_PER_KWH)))
    conn.close()
    return jsonify([{
        'device_id': r['id'], 'name': r['name'], 'location': r['location'],
        'energy_kwh': round(max(0.0, r['energy_kwh'] or 0.0), 3),
        'cost': round(max(0.0, r['energy_kwh'] or 0.0) * energy_rate, 3),
        'peak_power': round(r['peak_power'] or 0, 1)
    } for r in rows])

@app.route('/api/usage/trend')
@login_required
def api_usage_trend():
    days = request.args.get('days', 7, type=int)
    days = max(1, min(90, days))
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    conn = get_db()
    rows = conn.execute('''SELECT substr(timestamp, 1, 10) as day, device_id,
            (MAX(energy) - MIN(energy)) as energy_kwh
        FROM readings WHERE timestamp >= ? AND energy IS NOT NULL
        GROUP BY day, device_id ORDER BY day ASC''', (cutoff,)).fetchall()
    energy_rate = float(get_setting(conn, 'energy_rate', str(ENERGY_RATE_PER_KWH)))
    conn.close()
    by_day = {}
    for r in rows:
        by_day[r['day']] = by_day.get(r['day'], 0.0) + max(0.0, r['energy_kwh'] or 0.0)
    return jsonify([{
        'day': day,
        'energy_kwh': round(v, 3),
        'cost': round(v * energy_rate, 3)
    } for day, v in sorted(by_day.items())])

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
            # Alerts use SQLite's datetime('now') (UTC, space-separated), so their
            # cutoff must match that format, not the readings' ISO format above.
            alert_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=5)).strftime('%Y-%m-%d %H:%M:%S')
            alerts = conn.execute('''SELECT a.*, d.name as device_name FROM alerts a
                JOIN devices d ON a.device_id=d.id
                WHERE a.created_at >= ? AND a.acknowledged=0''', (alert_cutoff,)).fetchall()
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
        # Offline monitoring runs on the backend regardless of where the
        # simulator lives (embedded thread or standalone simulator.py).
        logger.info('Starting offline monitor thread...')
        offline_thread = threading.Thread(target=offline_monitor, daemon=True)
        offline_thread.start()
        if EMBEDDED_SIMULATOR:
            logger.info('Starting embedded simulator thread...')
            sim_thread = threading.Thread(target=simulate_readings, daemon=True)
            sim_thread.start()
        else:
            logger.info('Embedded simulator disabled (EMBEDDED_SIMULATOR=0); run simulator.py separately')
        logger.info('Starting broadcast thread...')
        bcast_thread = threading.Thread(target=broadcast_readings, daemon=True)
        bcast_thread.start()
        logger.info('Server starting at http://%s:%s', HOST, PORT)
        # The embedded Werkzeug server is fine for a demo deployment; the
        # allow_unsafe_werkzeug flag is required by Flask-SocketIO >= 5.4 /
        # Werkzeug >= 3.0 which refuse to run it in production without this opt-in.
        socketio.run(app, host=HOST, port=PORT, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        logger.info('Shutting down...')
        SIMULATOR_RUNNING = False
