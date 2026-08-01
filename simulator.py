#!/usr/bin/env python3
"""Standalone device simulator (spec Ch. 4 §4.3.1).

The simulator is a separate Python process that creates 20 virtual smart metres,
generates realistic readings and sends each one as JSON via HTTP POST to the
Flask backend's /api/reading endpoint — matching the documented architecture
(Ch. 3 §3.5, Ch. 4 §4.5).

Usage
-----
1. Run the backend:
       python app.py

2. If the backend's embedded simulator is still on, either stop it or disable it:
       EMBEDDED_SIMULATOR=0 python app.py

3. Run this simulator (defaults to http://127.0.0.1:5000):
       python simulator.py

Optional environment variables:
    SIMULATOR_SERVER_URL   backend URL (e.g. http://192.168.1.10:5000)
    SIM_INTERVAL           seconds between reading cycles (default 3)
    ENERGY_DB_PATH         SQLite file so the simulator can list devices
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app as energy_app  # noqa: E402  (reuses the same simulation loop)


if __name__ == '__main__':
    energy_app.SIMULATOR_RUNNING = True
    print(f'Simulator started. Sending readings to {energy_app.SIMULATOR_SERVER_URL} '
          f'every {energy_app.SIM_INTERVAL}s. Press Ctrl+C to stop.')
    try:
        energy_app.simulate_readings()
    except KeyboardInterrupt:
        print('\nSimulator stopped.')
        energy_app.SIMULATOR_RUNNING = False
