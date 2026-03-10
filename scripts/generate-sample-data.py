import random
import json
from datetime import datetime, timedelta

# Configuration for the sample data generation
num_events = 100
start_time = datetime.utcnow() - timedelta(days=1)

# Sample event types
event_types = ['login_success', 'login_failure', 'file_access', 'file_modification', 'network_intrusion']

# Function to generate sample security event data

def generate_event(event_time):
    return {
        'timestamp': event_time.isoformat(),
        'event_type': random.choice(event_types),
        'user_id': random.randint(1000, 9999),
        'description': 'Sample description for event'
    }

# Generate sample data
sample_data = []
for i in range(num_events):
    event_time = start_time + timedelta(minutes=i)
    sample_data.append(generate_event(event_time))

# Save to JSON file
with open('sample_security_events.json', 'w') as json_file:
    json.dump(sample_data, json_file, indent=4)
