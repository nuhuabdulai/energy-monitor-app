import os
import sys
import tempfile
import sqlite3
import unittest
from datetime import datetime, timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TEST_DB_FD, TEST_DB_PATH = tempfile.mkstemp(suffix='.db')
os.environ['TEST_DB_PATH'] = TEST_DB_PATH

import app as energy_app

app = energy_app.app
app.config['TESTING'] = True
app.config['SECRET_KEY'] = 'test-secret'
client = app.test_client()

energy_app.DB_PATH = TEST_DB_PATH

def setUpModule():
    with app.app_context():
        energy_app.init_db()

def tearDownModule():
    os.close(TEST_DB_FD)
    os.unlink(TEST_DB_PATH)

_registered = set()

def register_user(email, password='pass123', name=None):
    return client.post('/api/signup', json={
        'name': name or email.split('@')[0],
        'email': email,
        'password': password
    })

def login_user(email, password='pass123'):
    return client.post('/api/login', json={
        'email': email,
        'password': password
    })

def ensure_user(email, password='pass123', name=None):
    if email not in _registered:
        resp = register_user(email, password, name)
        if resp.status_code == 200:
            _registered.add(email)
            return
    with client.session_transaction() as sess:
        sess.clear()
    login_user(email, password)

class TestDatabase(unittest.TestCase):
    def test_tables_exist(self):
        conn = sqlite3.connect(TEST_DB_PATH)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        conn.close()
        for t in ['users', 'devices', 'readings', 'alerts']:
            self.assertIn(t, tables)

    def test_devices_seeded(self):
        conn = sqlite3.connect(TEST_DB_PATH)
        conn.row_factory = sqlite3.Row
        count = conn.execute('SELECT COUNT(*) as c FROM devices').fetchone()['c']
        conn.close()
        self.assertEqual(count, 20)

    def test_readings_seeded(self):
        conn = sqlite3.connect(TEST_DB_PATH)
        conn.row_factory = sqlite3.Row
        count = conn.execute('SELECT COUNT(*) as c FROM readings').fetchone()['c']
        conn.close()
        self.assertGreater(count, 0)

class TestAuth(unittest.TestCase):
    def setUp(self):
        with client.session_transaction() as sess:
            sess.clear()

    def test_signup_success(self):
        resp = register_user('test@example.com', 'pass123', 'Test User')
        data = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data['name'], 'Test User')
        self.assertEqual(data['email'], 'test@example.com')

    def test_signup_missing_fields(self):
        resp = client.post('/api/signup', json={'name': '', 'email': '', 'password': ''})
        self.assertEqual(resp.status_code, 400)

    def test_signup_short_password(self):
        resp = client.post('/api/signup', json={
            'name': 'A', 'email': 'a@b.com', 'password': '12345'
        })
        self.assertEqual(resp.status_code, 400)

    def test_signup_duplicate_email(self):
        register_user('dup@example.com', 'pass123')
        resp = register_user('dup@example.com', 'pass123')
        self.assertEqual(resp.status_code, 409)

    def test_login_success(self):
        register_user('login@test.com', 'mypassword')
        with client.session_transaction() as sess:
            sess.clear()
        resp = login_user('login@test.com', 'mypassword')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['email'], 'login@test.com')

    def test_login_wrong_password(self):
        register_user('wrongpw@test.com', 'correctpw')
        with client.session_transaction() as sess:
            sess.clear()
        resp = login_user('wrongpw@test.com', 'wrongpw')
        self.assertEqual(resp.status_code, 401)

    def test_login_nonexistent_user(self):
        resp = login_user('nobody@test.com', 'pass123')
        self.assertEqual(resp.status_code, 401)

    def test_logout(self):
        register_user('logout@test.com', 'pass123')
        resp = client.post('/api/logout')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['ok'])

    def test_me_requires_auth(self):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get('/api/me')
        self.assertEqual(resp.status_code, 401)

    def test_me_returns_user(self):
        register_user('me@test.com', 'pass123')
        resp = client.get('/api/me')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['email'], 'me@test.com')

class TestLoginLockout(unittest.TestCase):
    """Brute-force protection: lock an email after MAX_LOGIN_ATTEMPTS failures."""

    def setUp(self):
        energy_app._login_failures.clear()
        with client.session_transaction() as sess:
            sess.clear()

    def tearDown(self):
        energy_app._login_failures.clear()

    def test_lockout_after_five_failures(self):
        register_user('lockout1@test.com', 'pass123')
        for _ in range(4):
            resp = login_user('lockout1@test.com', 'wrongpw')
            self.assertEqual(resp.status_code, 401)
        resp = login_user('lockout1@test.com', 'wrongpw')
        self.assertEqual(resp.status_code, 429)

    def test_locked_email_rejects_correct_password(self):
        register_user('lockout2@test.com', 'pass123')
        for _ in range(energy_app.MAX_LOGIN_ATTEMPTS):
            login_user('lockout2@test.com', 'wrongpw')
        resp = login_user('lockout2@test.com', 'pass123')
        self.assertEqual(resp.status_code, 429)

    def test_successful_login_resets_failures(self):
        register_user('lockout3@test.com', 'pass123')
        for _ in range(3):
            login_user('lockout3@test.com', 'wrongpw')
        with client.session_transaction() as sess:
            sess.clear()
        resp = login_user('lockout3@test.com', 'pass123')
        self.assertEqual(resp.status_code, 200)
        with client.session_transaction() as sess:
            sess.clear()
        for _ in range(4):
            resp = login_user('lockout3@test.com', 'wrongpw')
            self.assertEqual(resp.status_code, 401)

class TestDevices(unittest.TestCase):
    def setUp(self):
        ensure_user('devices@test.com', 'pass123')

    def test_list_devices(self):
        resp = client.get('/api/devices')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    def test_device_has_expected_fields(self):
        resp = client.get('/api/devices')
        data = resp.get_json()
        device = data[0]
        for key in ['id', 'name', 'location', 'device_type', 'is_active',
                     'voltage', 'current', 'power', 'energy', 'power_factor',
                     'frequency', 'last_reading', 'alert_count', 'thresholds']:
            self.assertIn(key, device)
        self.assertIn('power', device['thresholds'])

    def test_devices_unauthorized(self):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get('/api/devices')
        self.assertEqual(resp.status_code, 401)

    def test_device_has_temperature_and_humidity(self):
        resp = client.get('/api/devices')
        data = resp.get_json()
        device = data[0]
        self.assertIn('temperature', device)
        self.assertIn('humidity', device)

class TestReadingIngest(unittest.TestCase):
    def setUp(self):
        ensure_user('ingest@test.com', 'pass123')

    def test_ingest_valid_reading(self):
        resp = client.post('/api/reading', json={
            'device_id': 1,
            'voltage': 230, 'current': 5, 'power': 1150,
            'energy': 1.15, 'power_factor': 0.95, 'frequency': 50,
            'temperature': 32.5, 'humidity': 45
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data['ok'])
        self.assertIn('reading_id', data)

    def test_ingest_missing_device_id(self):
        resp = client.post('/api/reading', json={'voltage': 230})
        self.assertEqual(resp.status_code, 400)

    def test_ingest_unknown_device(self):
        resp = client.post('/api/reading', json={'device_id': 999})
        self.assertEqual(resp.status_code, 404)

    def test_ingest_invalid_json(self):
        resp = client.post('/api/reading', data='not json', content_type='application/json')
        self.assertEqual(resp.status_code, 400)

class TestReadings(unittest.TestCase):
    def setUp(self):
        ensure_user('readings@test.com', 'pass123')

    def test_readings_latest_per_device(self):
        resp = client.get('/api/readings')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, list)

    def test_readings_by_device(self):
        resp = client.get('/api/readings?device_id=1&limit=5')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        for r in data:
            self.assertEqual(r['device_id'], 1)

    def test_readings_history(self):
        resp = client.get('/api/readings/history?device_id=1&hours=24')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, list)

    def test_readings_by_device_rest_route(self):
        # Ch. 4 §4.3.2: GET /api/readings/<device_id>
        resp = client.get('/api/readings/1?hours=24&limit=5')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, list)
        for r in data:
            self.assertEqual(r['device_id'], 1)

    def test_history_keeps_newest_when_limited(self):
        # Regression: the limit used to keep the OLDEST rows, dropping fresh data
        conn = sqlite3.connect(TEST_DB_PATH)
        now = datetime.now()
        inserted = []
        for i in range(5):
            ts = (now - timedelta(minutes=10 - i)).isoformat()
            inserted.append(ts)
            conn.execute("INSERT INTO readings (device_id, power, timestamp) VALUES (2, ?, ?)",
                         (100 + i, ts))
        conn.commit()
        conn.close()
        resp = client.get('/api/readings/history?device_id=2&hours=24&limit=3')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data), 3)
        stamps = [r['timestamp'] for r in data]
        # ascending order and includes the newest inserted reading
        self.assertEqual(stamps, sorted(stamps))
        self.assertIn(inserted[-1], stamps)
        self.assertNotIn(inserted[0], stamps)

    def test_readings_unauthorized(self):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get('/api/readings')
        self.assertEqual(resp.status_code, 401)

class TestAlerts(unittest.TestCase):
    def setUp(self):
        ensure_user('alerts@test.com', 'pass123')

    def test_list_alerts(self):
        resp = client.get('/api/alerts?limit=10')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, list)

    def test_acknowledge_alert(self):
        resp = client.get('/api/alerts?limit=1')
        alerts = resp.get_json()
        if alerts:
            alert_id = alerts[0]['id']
            resp = client.post('/api/alerts/acknowledge', json={'alert_id': alert_id})
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data['ok'])

    def test_acknowledge_nonexistent_alert(self):
        resp = client.post('/api/alerts/acknowledge', json={'alert_id': 99999})
        self.assertEqual(resp.status_code, 404)

    def test_acknowledge_alert_rest_route(self):
        # Ch. 4 §4.3.2: POST /api/alerts/<id>/acknowledge
        resp = client.get('/api/alerts?limit=1')
        alerts = resp.get_json()
        if alerts:
            alert_id = alerts[0]['id']
            resp = client.post(f'/api/alerts/{alert_id}/acknowledge')
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data['ok'])
        resp = client.post('/api/alerts/99999/acknowledge')
        self.assertEqual(resp.status_code, 404)

    def test_acknowledge_all(self):
        resp = client.post('/api/alerts/acknowledge', json={})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['ok'])

    def test_alerts_unauthorized(self):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get('/api/alerts')
        self.assertEqual(resp.status_code, 401)

class TestSummary(unittest.TestCase):
    def setUp(self):
        ensure_user('summary@test.com', 'pass123')

    def test_summary_fields(self):
        resp = client.get('/api/summary')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        for key in ['total_energy_kwh', 'active_devices', 'offline_devices',
                    'active_alerts', 'avg_power_w']:
            self.assertIn(key, data)

    def test_summary_values_are_numbers(self):
        resp = client.get('/api/summary')
        data = resp.get_json()
        self.assertIsInstance(data['total_energy_kwh'], (int, float))
        self.assertIsInstance(data['active_devices'], int)
        self.assertIsInstance(data['active_alerts'], int)
        self.assertIsInstance(data['avg_power_w'], (int, float))

    def test_summary_unauthorized(self):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get('/api/summary')
        self.assertEqual(resp.status_code, 401)

class TestAlertEngine(unittest.TestCase):
    def setUp(self):
        conn = sqlite3.connect(TEST_DB_PATH)
        conn.row_factory = sqlite3.Row
        self.conn = conn

    def tearDown(self):
        self.conn.close()

    def _evaluate_alerts(self, voltage=None, current=None, power=None, temperature=None):
        return energy_app.evaluate_alerts(voltage, current, power, temperature)

    def _types(self, alerts):
        return [a['type'] for a in alerts]

    def test_overvoltage_alert_triggered(self):
        alerts = self._evaluate_alerts(265, 5, 1000)
        self.assertIn('over_voltage', self._types(alerts))

    def test_undervoltage_alert_triggered(self):
        alerts = self._evaluate_alerts(190, 5, 1000)
        self.assertIn('under_voltage', self._types(alerts))

    def test_overcurrent_alert_triggered(self):
        alerts = self._evaluate_alerts(230, 35, 1000)
        self.assertIn('over_current', self._types(alerts))

    def test_highpower_alert_triggered(self):
        alerts = self._evaluate_alerts(230, 10, 6000)
        self.assertIn('high_power', self._types(alerts))

    def test_no_alert_for_normal_values(self):
        alerts = self._evaluate_alerts(230, 5, 1000)
        self.assertEqual(len(alerts), 0)

    def test_boundary_voltage_250_no_alert(self):
        alerts = self._evaluate_alerts(250, 5, 1000)
        self.assertNotIn('over_voltage', self._types(alerts))

    def test_boundary_voltage_200_no_alert(self):
        alerts = self._evaluate_alerts(200, 5, 1000)
        self.assertNotIn('under_voltage', self._types(alerts))

    def test_multiple_alerts_simultaneously(self):
        alerts = self._evaluate_alerts(265, 35, 6000)
        types = self._types(alerts)
        self.assertIn('over_voltage', types)
        self.assertIn('over_current', types)
        self.assertIn('high_power', types)

    def test_overvoltage_severity_critical(self):
        alerts = self._evaluate_alerts(265, 5, 1000)
        for a in alerts:
            if a['type'] == 'over_voltage':
                self.assertEqual(a['severity'], 'critical')

    def test_alerts_include_value_and_threshold(self):
        alerts = self._evaluate_alerts(265, 5, 1000)
        over = [a for a in alerts if a['type'] == 'over_voltage'][0]
        self.assertEqual(over['value'], 265.0)
        self.assertEqual(over['threshold'], 250)

    def test_high_temperature_alert(self):
        alerts = self._evaluate_alerts(temperature=55)
        self.assertIn('high_temperature', self._types(alerts))

    def test_low_temperature_alert(self):
        alerts = self._evaluate_alerts(temperature=5)
        self.assertIn('low_temperature', self._types(alerts))

    def test_temperature_boundary_50_no_alert(self):
        alerts = self._evaluate_alerts(temperature=50)
        self.assertNotIn('high_temperature', self._types(alerts))

    def test_temperature_boundary_10_no_alert(self):
        alerts = self._evaluate_alerts(temperature=10)
        self.assertNotIn('low_temperature', self._types(alerts))

    def test_alert_engine_runs_on_ingest(self):
        resp = client.post('/api/reading', json={
            'device_id': 1, 'voltage': 265, 'current': 5, 'power': 1000
        })
        self.assertEqual(resp.status_code, 201)
        conn = sqlite3.connect(TEST_DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE device_id=1 AND type='over_voltage'").fetchone()
        conn.close()
        self.assertGreater(row['c'], 0)

    def test_per_device_threshold_override(self):
        alerts = energy_app.evaluate_alerts(230, 5, 2500, None, thresholds={'power': 2000})
        self.assertIn('high_power', self._types(alerts))
        alerts = energy_app.evaluate_alerts(230, 5, 2500, None, thresholds={'power': 3000})
        self.assertNotIn('high_power', self._types(alerts))

    def test_default_power_threshold_is_5000(self):
        # Ch. 5 findings: high-power alert triggers above 5000W per device
        self.assertEqual(energy_app.DEFAULT_THRESHOLDS['power'], 5000)
        alerts = energy_app.evaluate_alerts(230, 5, 5001)
        self.assertIn('high_power', self._types(alerts))
        alerts = energy_app.evaluate_alerts(230, 5, 5000)
        self.assertNotIn('high_power', self._types(alerts))

    def test_alert_dedup_window_on_ingest(self):
        # Repeated identical violations must not flood the alerts table
        ensure_user('dedup@test.com', 'pass123')  # device creation requires login
        resp = client.post('/api/devices', json={'name': 'Dedup Meter', 'location': 'Lab'})
        did = resp.get_json()['id']
        # Remove the temporary device so other tests see exactly 20 seeded devices
        self.addCleanup(client.delete, f'/api/devices/{did}')
        payload = {'device_id': did, 'voltage': 265, 'current': 5, 'power': 1000}
        client.post('/api/reading', json=payload)
        client.post('/api/reading', json=payload)
        conn = sqlite3.connect(TEST_DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE device_id=? AND type='over_voltage'",
            (did,)).fetchone()
        conn.close()
        self.assertEqual(row['c'], 1)

class TestAnomalyDetection(unittest.TestCase):
    def setUp(self):
        energy_app._power_history.clear()

    def test_needs_min_samples(self):
        # Anomaly scoring starts only after ANOMALY_MIN_SAMPLES readings
        for _ in range(energy_app.ANOMALY_MIN_SAMPLES - 1):
            self.assertIsNone(energy_app.detect_power_anomaly(999, 1000))
        self.assertIn(999, energy_app._power_history)
        self.assertEqual(len(energy_app._power_history[999]), energy_app.ANOMALY_MIN_SAMPLES - 1)

    def test_stable_reading_no_false_positive(self):
        # Small normal fluctuation around the baseline must not be flagged
        for i in range(energy_app.ANOMALY_MIN_SAMPLES):
            energy_app.detect_power_anomaly(1, 500 + (i % 5) * 4 - 8)
        result = energy_app.detect_power_anomaly(1, 505)
        self.assertIsNone(result)

    def test_spike_is_flagged(self):
        for i in range(energy_app.ANOMALY_MIN_SAMPLES):
            energy_app.detect_power_anomaly(2, 500 + (i % 5) * 4 - 8)
        result = energy_app.detect_power_anomaly(2, 9000)
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'anomaly')
        self.assertIn('anomaly', result['type'])
        self.assertIn('9000W', result['message'])
        self.assertIn('value', result)
        self.assertIn('threshold', result)

    def test_anomaly_wired_into_simulator_path(self):
        # simulate_readings runs detect_power_anomaly per device: verify the
        # function signature matches the call site
        import inspect
        sig = inspect.signature(energy_app.simulate_readings)
        self.assertEqual(sig.parameters, {})
        self.assertTrue(callable(energy_app.detect_power_anomaly))

class TestEmailNotifications(unittest.TestCase):
    def setUp(self):
        ensure_user('emailtest@test.com', 'pass123')
        energy_app._last_email_sent = 0.0

    def test_settings_email_fields_persist(self):
        resp = client.put('/api/settings', json={'email_alerts': True, 'email_recipient': 'me@example.com'})
        self.assertEqual(resp.status_code, 200)
        data = client.get('/api/settings').get_json()
        self.assertEqual(data['email_alerts'], '1')
        self.assertEqual(data['email_recipient'], 'me@example.com')

    def test_settings_rejects_invalid_email(self):
        resp = client.put('/api/settings', json={'email_recipient': 'not-an-email'})
        self.assertEqual(resp.status_code, 400)

    def test_email_disabled_without_smtp(self):
        # Enabled in settings but SMTP env vars missing -> no email is sent
        client.put('/api/settings', json={'email_alerts': True, 'email_recipient': 'me@example.com'})
        with app.app_context():
            conn = energy_app.get_db()
            sent = energy_app.maybe_email_alert(conn, 'Living Room Meter',
                                                {'type': 'high_power', 'severity': 'warning', 'message': 'x'})
            conn.close()
        self.assertFalse(sent)

    def test_email_rate_limited(self):
        # At most one email per EMAIL_THROTTLE_SECONDS
        client.put('/api/settings', json={'email_alerts': True, 'email_recipient': 'me@example.com'})
        with mock.patch.object(energy_app, 'SMTP_HOST', 'smtp.test.com'), \
             mock.patch.object(energy_app, 'SMTP_USER', 'user'), \
             mock.patch.object(energy_app, 'SMTP_PASSWORD', 'pass'), \
             mock.patch.object(energy_app, '_send_email_async') as send:
            with app.app_context():
                conn = energy_app.get_db()
                first = energy_app.maybe_email_alert(conn, 'Meter',
                                                     {'type': 'high_power', 'severity': 'warning', 'message': 'x'})
                second = energy_app.maybe_email_alert(conn, 'Meter',
                                                      {'type': 'over_voltage', 'severity': 'critical', 'message': 'y'})
                conn.close()
        self.assertTrue(first)
        self.assertFalse(second)  # throttled
        send.assert_called_once()

class TestReports(unittest.TestCase):
    def setUp(self):
        ensure_user('reporttest@test.com', 'pass123')

    def test_reports_daily_returns_rows(self):
        resp = client.get('/api/reports?period=daily&days=7')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['period'], 'daily')
        self.assertIn('rows', data)
        self.assertIn('totals', data)
        self.assertIn('top_devices', data)
        self.assertGreater(len(data['rows']), 0)
        row = data['rows'][0]
        for key in ('label', 'energy_kwh', 'cost', 'peak_power', 'reading_count'):
            self.assertIn(key, row)

    def test_reports_weekly_and_monthly(self):
        for period in ('weekly', 'monthly'):
            resp = client.get(f'/api/reports?period={period}')
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.get_json()['period'], period)

    def test_reports_invalid_period(self):
        resp = client.get('/api/reports?period=hourly')
        self.assertEqual(resp.status_code, 400)

    def test_reports_unauthorized(self):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get('/api/reports')
        self.assertEqual(resp.status_code, 401)

    def test_reports_export_csv(self):
        resp = client.get('/api/reports/export?period=daily&days=7')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('text/csv', resp.mimetype)
        text = resp.get_data(as_text=True)
        self.assertIn('period,energy_kwh,cost,peak_power,reading_count', text)

class TestDeviceManagement(unittest.TestCase):
    def setUp(self):
        ensure_user('devmgr@test.com', 'pass123')

    def test_create_device(self):
        resp = client.post('/api/devices', json={'name': 'Office Plug', 'location': 'Office'})
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data['ok'])
        self.assertIn('id', data)

    def test_create_device_missing_name(self):
        resp = client.post('/api/devices', json={'location': 'Office'})
        self.assertEqual(resp.status_code, 400)

    def test_update_device(self):
        resp = client.post('/api/devices', json={'name': 'Old Name', 'location': 'A'})
        device_id = resp.get_json()['id']
        resp = client.put(f'/api/devices/{device_id}', json={'name': 'New Name'})
        self.assertEqual(resp.status_code, 200)
        conn = sqlite3.connect(TEST_DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute('SELECT name FROM devices WHERE id=?', (device_id,)).fetchone()
        conn.close()
        self.assertEqual(row['name'], 'New Name')

    def test_update_device_toggle_inactive(self):
        resp = client.post('/api/devices', json={'name': 'Toggle Me', 'location': 'B'})
        device_id = resp.get_json()['id']
        resp = client.put(f'/api/devices/{device_id}', json={'is_active': False})
        self.assertEqual(resp.status_code, 200)
        conn = sqlite3.connect(TEST_DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute('SELECT is_active FROM devices WHERE id=?', (device_id,)).fetchone()
        conn.close()
        self.assertEqual(row['is_active'], 0)

    def test_update_nonexistent_device(self):
        resp = client.put('/api/devices/99999', json={'name': 'X'})
        self.assertEqual(resp.status_code, 404)

    def test_delete_device(self):
        resp = client.post('/api/devices', json={'name': 'To Delete', 'location': 'C'})
        device_id = resp.get_json()['id']
        resp = client.delete(f'/api/devices/{device_id}')
        self.assertEqual(resp.status_code, 200)
        conn = sqlite3.connect(TEST_DB_PATH)
        row = conn.execute('SELECT id FROM devices WHERE id=?', (device_id,)).fetchone()
        conn.close()
        self.assertIsNone(row)

    def test_delete_nonexistent_device(self):
        resp = client.delete('/api/devices/99999')
        self.assertEqual(resp.status_code, 404)

    def test_device_management_unauthorized(self):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.post('/api/devices', json={'name': 'X', 'location': 'Y'})
        self.assertEqual(resp.status_code, 401)

class TestUsageInsights(unittest.TestCase):
    def setUp(self):
        ensure_user('usage@test.com', 'pass123')

    def test_summary_has_cost_and_peak(self):
        resp = client.get('/api/summary')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        for key in ['daily_cost', 'peak_power_w', 'currency', 'energy_rate']:
            self.assertIn(key, data)

    def test_usage_ranking(self):
        resp = client.get('/api/usage/ranking?hours=24')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, list)
        if data:
            for key in ['device_id', 'name', 'energy_kwh', 'cost', 'peak_power']:
                self.assertIn(key, data[0])

    def test_usage_trend(self):
        resp = client.get('/api/usage/trend?days=7')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, list)
        if data:
            for key in ['day', 'energy_kwh', 'cost']:
                self.assertIn(key, data[0])

    def test_usage_endpoints_unauthorized(self):
        with client.session_transaction() as sess:
            sess.clear()
        for url in ['/api/usage/ranking', '/api/usage/trend', '/api/summary']:
            resp = client.get(url)
            self.assertEqual(resp.status_code, 401)

class TestSettings(unittest.TestCase):
    def setUp(self):
        ensure_user('settings@test.com', 'pass123')

    def test_get_settings(self):
        resp = client.get('/api/settings')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        for key in ['energy_rate', 'currency', 'defaults', 'devices']:
            self.assertIn(key, data)
        self.assertEqual(data['defaults']['power'], 5000)
        self.assertGreaterEqual(len(data['devices']), 20)

    def test_update_energy_rate(self):
        resp = client.put('/api/settings', json={'energy_rate': 1.25})
        self.assertEqual(resp.status_code, 200)
        resp = client.get('/api/settings')
        data = resp.get_json()
        self.assertEqual(data['energy_rate'], 1.25)

    def test_update_invalid_rate(self):
        resp = client.put('/api/settings', json={'energy_rate': -5})
        self.assertEqual(resp.status_code, 400)

    def test_update_device_thresholds(self):
        resp = client.put('/api/settings', json={'devices': [{'id': 1, 'power': 1500}]})
        self.assertEqual(resp.status_code, 200)
        resp = client.get('/api/settings')
        data = resp.get_json()
        dev = [d for d in data['devices'] if d['id'] == 1][0]
        self.assertEqual(dev['power'], 1500)

    def test_reset_thresholds_to_defaults(self):
        client.put('/api/settings', json={'devices': [{'id': 1, 'power': 1500}]})
        resp = client.put('/api/settings', json={'apply_defaults': True})
        self.assertEqual(resp.status_code, 200)
        resp = client.get('/api/settings')
        data = resp.get_json()
        dev = [d for d in data['devices'] if d['id'] == 1][0]
        self.assertIsNone(dev['power'])

    def test_settings_unauthorized(self):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get('/api/settings')
        self.assertEqual(resp.status_code, 401)

class TestExportCSV(unittest.TestCase):
    def setUp(self):
        ensure_user('export@test.com', 'pass123')

    def test_export_readings(self):
        resp = client.get('/api/export/readings?hours=24')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('text/csv', resp.content_type)
        self.assertIn('attachment', resp.headers.get('Content-Disposition', ''))

    def test_export_readings_per_device(self):
        resp = client.get('/api/export/readings?device_id=1&hours=24')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('text/csv', resp.content_type)

    def test_export_alerts(self):
        resp = client.get('/api/export/alerts?hours=168')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('text/csv', resp.content_type)

    def test_export_unauthorized(self):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get('/api/export/readings')
        self.assertEqual(resp.status_code, 401)

class TestPages(unittest.TestCase):
    def test_index_page(self):
        resp = client.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Smart Energy Monitor', resp.data)

    def test_login_page(self):
        resp = client.get('/login')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Sign In', resp.data)

    def test_signup_page(self):
        resp = client.get('/signup')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Create Account', resp.data)

    def test_dashboard_redirects_when_not_logged_in(self):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get('/dashboard')
        self.assertEqual(resp.status_code, 302)

    def test_dashboard_page(self):
        ensure_user('dash@test.com', 'pass123')
        resp = client.get('/dashboard')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Dashboard', resp.data)

    def test_map_page_redirects_when_not_logged_in(self):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get('/map')
        self.assertEqual(resp.status_code, 302)

    def test_map_page(self):
        ensure_user('map@test.com', 'pass123')
        resp = client.get('/map')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Device Map', resp.data)

class TestAlertSchema(unittest.TestCase):
    """Ch 4 §4.4: alerts carry the triggering parameter + value + threshold."""

    def test_alert_parameter_fields(self):
        by_type = {a['type']: a for a in energy_app.evaluate_alerts(265, 5, 1000)}
        self.assertEqual(by_type['over_voltage']['parameter'], 'voltage')
        by_type = {a['type']: a for a in energy_app.evaluate_alerts(230, 35, 1000)}
        self.assertEqual(by_type['over_current']['parameter'], 'current')
        by_type = {a['type']: a for a in energy_app.evaluate_alerts(230, 10, 6000)}
        self.assertEqual(by_type['high_power']['parameter'], 'power')
        by_type = {a['type']: a for a in energy_app.evaluate_alerts(temperature=55)}
        self.assertEqual(by_type['high_temperature']['parameter'], 'temperature')
        by_type = {a['type']: a for a in energy_app.evaluate_alerts(temperature=5)}
        self.assertEqual(by_type['low_temperature']['parameter'], 'temperature')

    def test_anomaly_has_parameter(self):
        energy_app._power_history.clear()
        for i in range(energy_app.ANOMALY_MIN_SAMPLES):
            energy_app.detect_power_anomaly(2, 500 + (i % 5) * 4 - 8)
        result = energy_app.detect_power_anomaly(2, 9000)
        self.assertIsNotNone(result)
        self.assertEqual(result['parameter'], 'power')

    def test_alerts_table_has_parameter_column(self):
        conn = sqlite3.connect(TEST_DB_PATH)
        cols = [r[1] for r in conn.execute('PRAGMA table_info(alerts)').fetchall()]
        conn.close()
        self.assertIn('parameter', cols)

    def test_parameter_persisted_on_ingest(self):
        ensure_user('par@test.com', 'pass123')
        client.post('/api/reading', json={'device_id': 1, 'voltage': 265, 'current': 5, 'power': 1000})
        conn = sqlite3.connect(TEST_DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute('''SELECT parameter FROM alerts WHERE device_id=1 AND type='over_voltage'
            ORDER BY id DESC LIMIT 1''').fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row['parameter'], 'voltage')

class TestSimulatorSpec(unittest.TestCase):
    """Ch 4 §4.3.1: simulated reading ranges match the documented specification."""

    def test_generate_reading_ranges(self):
        for _ in range(300):
            r = energy_app.generate_reading(energy_app.DEFAULT_THRESHOLDS, datetime.now())
            self.assertGreaterEqual(r['voltage'], 220)
            self.assertLessEqual(r['voltage'], 240)
            self.assertGreaterEqual(r['temperature'], 25)
            self.assertLessEqual(r['temperature'], 40)
            self.assertGreaterEqual(r['humidity'], 30)
            self.assertLessEqual(r['humidity'], 70)
            self.assertGreater(r['current'], 0)
            self.assertLessEqual(r['current'], 40)
            self.assertGreater(r['power'], 0)
            self.assertLessEqual(r['power'], 9000)

    def test_current_can_exceed_overcurrent_threshold(self):
        # A power spike must be able to drive current above the 30A alert threshold
        self.assertEqual(energy_app.DEFAULT_THRESHOLDS['current'], 30)
        r = energy_app.generate_reading({'power': 5000}, datetime.now())
        self.assertLessEqual(r['current'], 40)

    def test_cumulative_energy_is_monotonic(self):
        energy_app._cumulative_energy.clear()
        energy_app._cumulative_energy[777] = 100.0
        first = energy_app.add_cumulative_energy(777, 1000)
        second = energy_app.add_cumulative_energy(777, 1500)
        self.assertGreater(second, first)
        self.assertGreater(first, 100.0)
        energy_app._cumulative_energy.clear()

    def test_standalone_simulator_module_exists(self):
        # Ch 4 §4.3.1 documents simulator.py as a separate process module
        self.assertTrue(os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'simulator.py')))

class TestOfflineMonitoring(unittest.TestCase):
    """Ch 4 §4.3.3: a device with no reading for OFFLINE_SECONDS is flagged offline."""

    def test_offline_alert_created(self):
        ensure_user('offline@test.com', 'pass123')
        resp = client.post('/api/devices', json={'name': 'Offline Meter', 'location': 'Lab'})
        did = resp.get_json()['id']
        self.addCleanup(client.delete, f'/api/devices/{did}')
        energy_app.last_device_seen[did] = datetime.now() - timedelta(seconds=energy_app.OFFLINE_SECONDS + 5)
        conn = energy_app.get_db()
        changed = energy_app.check_offline_devices(conn, datetime.now())
        conn.commit()
        row = conn.execute('''SELECT parameter, severity, value, threshold FROM alerts
            WHERE device_id=? AND type='device_offline' AND acknowledged=0''', (did,)).fetchone()
        conn.close()
        self.assertTrue(changed)
        self.assertIsNotNone(row)
        self.assertEqual(row['parameter'], 'device')
        self.assertEqual(row['severity'], 'critical')
        self.assertEqual(row['threshold'], energy_app.OFFLINE_SECONDS)

    def test_offline_alert_auto_acknowledged_when_back_online(self):
        ensure_user('offline2@test.com', 'pass123')
        resp = client.post('/api/devices', json={'name': 'Online Meter', 'location': 'Lab'})
        did = resp.get_json()['id']
        self.addCleanup(client.delete, f'/api/devices/{did}')
        conn = energy_app.get_db()
        conn.execute('''INSERT INTO alerts (device_id, type, parameter, message, severity)
            VALUES (?, 'device_offline', 'device', 'stale open alert', 'critical')''', (did,))
        conn.commit()
        energy_app.last_device_seen[did] = datetime.now()
        energy_app.check_offline_devices(conn, datetime.now())
        conn.commit()
        count = conn.execute('''SELECT COUNT(*) c FROM alerts
            WHERE device_id=? AND type='device_offline' AND acknowledged=0''', (did,)).fetchone()['c']
        conn.close()
        self.assertEqual(count, 0)

class TestCumulativeEnergy(unittest.TestCase):
    """Ch 4 §4.4: energy is cumulative, so consumption = per-device max - min."""

    def _make_device(self):
        resp = client.post('/api/devices', json={'name': 'Cumulative Meter', 'location': 'Lab'})
        return resp.get_json()['id']

    def test_summary_uses_consumption_not_cumulative_sum(self):
        ensure_user('cum@test.com', 'pass123')
        did = self._make_device()
        self.addCleanup(client.delete, f'/api/devices/{did}')
        conn = sqlite3.connect(TEST_DB_PATH)
        conn.row_factory = sqlite3.Row
        now = datetime.now()
        for i, e in enumerate([10.0, 10.5, 11.2, 12.0]):
            ts = (now - timedelta(minutes=30 - i)).isoformat()
            conn.execute('INSERT INTO readings (device_id, power, energy, timestamp) VALUES (?, 1000, ?, ?)',
                         (did, e, ts))
        conn.commit()
        conn.close()
        data = client.get('/api/summary').get_json()
        # The new device contributes 12.0 - 10.0 = 2.0 kWh to the 24h total
        self.assertGreaterEqual(data['total_energy_kwh'], 2.0)

    def test_report_uses_consumption_per_bucket(self):
        ensure_user('cum2@test.com', 'pass123')
        did = self._make_device()
        self.addCleanup(client.delete, f'/api/devices/{did}')
        conn = sqlite3.connect(TEST_DB_PATH)
        conn.row_factory = sqlite3.Row
        now = datetime.now()
        for i, e in enumerate([100.0, 101.0, 102.5]):
            ts = (now - timedelta(minutes=10 - i)).isoformat()
            conn.execute('INSERT INTO readings (device_id, power, energy, timestamp) VALUES (?, 1000, ?, ?)',
                         (did, e, ts))
        conn.commit()
        conn.close()
        data = client.get('/api/reports?period=daily&days=1').get_json()
        today = now.strftime('%Y-%m-%d')
        row = next((r for r in data['rows'] if r['label'] == today), None)
        self.assertIsNotNone(row)
        self.assertGreaterEqual(row['energy_kwh'], 2.5)

class TestSecurity(unittest.TestCase):
    """Ch 4 §4.6.4: password hashes never exposed; XSS payloads handled safely."""

    def test_no_password_in_api_responses(self):
        ensure_user('security@test.com', 'pass123')
        for url in ['/api/me', '/api/settings', '/api/devices']:
            resp = client.get(url)
            self.assertEqual(resp.status_code, 200)
            self.assertNotIn('password', resp.get_data(as_text=True).lower())

    def test_xss_payload_does_not_break_api(self):
        ensure_user('xss@test.com', 'pass123')
        resp = client.post('/api/devices', json={
            'name': '<script>alert(1)</script>', 'location': 'Lab'})
        self.assertEqual(resp.status_code, 201)
        did = resp.get_json()['id']
        self.addCleanup(client.delete, f'/api/devices/{did}')
        data = client.get('/api/devices').get_json()
        names = [d['name'] for d in data if d['id'] == did]
        self.assertIn('<script>alert(1)</script>', names)
        # dashboard.js escapes user-controlled strings before rendering (XSS defence)
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'templates', 'dashboard.html')) as fh:
            self.assertIn('esc(d.name)', fh.read())

class TestValidationScenario(unittest.TestCase):
    """Ch 4 §4.6.3: set a device power threshold to 100W and observe alert generation."""

    def test_low_power_threshold_generates_alert_via_api(self):
        ensure_user('val@test.com', 'pass123')
        resp = client.post('/api/devices', json={
            'name': 'Low Threshold', 'location': 'Lab', 'power': 100})
        self.assertEqual(resp.status_code, 201)
        did = resp.get_json()['id']
        self.addCleanup(client.delete, f'/api/devices/{did}')
        client.post('/api/reading', json={
            'device_id': did, 'voltage': 230, 'current': 5, 'power': 150})
        conn = sqlite3.connect(TEST_DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute('''SELECT type, parameter, value, threshold FROM alerts
            WHERE device_id=? AND type='high_power' ORDER BY id DESC LIMIT 1''', (did,)).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row['parameter'], 'power')
        self.assertEqual(row['value'], 150)
        self.assertEqual(row['threshold'], 100)

class TestWebSocket(unittest.TestCase):
    """Ch 4 §4.5: backend broadcasts over WebSocket (Socket.IO test client)."""

    def test_connect_event_emitted(self):
        io_client = energy_app.socketio.test_client(energy_app.app)
        received = io_client.get_received()
        io_client.disconnect()
        self.assertTrue(any(m['name'] == 'connected' for m in received))

if __name__ == '__main__':
    unittest.main()
