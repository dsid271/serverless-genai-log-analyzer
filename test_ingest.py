import urllib.request
import json
import time

url = 'http://localhost:8000/ingest'
headers = {'Content-Type': 'application/json'}

for i in range(10):
    log = {
        'timestamp': f'2023-01-01T00:00:{i:02d}Z',
        'severity': 'ERROR',
        'source': 'test-service',
        'message': f'Test error message {i}',
        'source_ip': '192.168.1.1',
        'request_id': f'req-{i}'
    }
    data = json.dumps({'logs': [log]}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req) as response:
            print(f'Sent log {i}: {response.getcode()}')
    except Exception as e:
        print(f'Error sending log {i}: {e}')
    time.sleep(0.1)