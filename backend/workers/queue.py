"""
Job Queue Configuration for Shadow AI Hunter
Uses Redis + RQ for background job processing
"""

import os
from redis import Redis
from rq import Queue

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Create queue connection
redis_conn = Redis.from_url(REDIS_URL)

# Define queues
scan_queue = Queue('scans', connection=redis_conn)
telemetry_queue = Queue('telemetry', connection=redis_conn)
detection_queue = Queue('detection', connection=redis_conn)
enrichment_queue = Queue('enrichment', connection=redis_conn)
report_queue = Queue('reports', connection=redis_conn)

# All queues for bulk operations
ALL_QUEUES = [scan_queue, telemetry_queue, detection_queue, enrichment_queue, report_queue]


def get_queue(queue_name: str) -> Queue:
    """Get queue by name"""
    queues = {
        'scans': scan_queue,
        'telemetry': telemetry_queue,
        'detection': detection_queue,
        'enrichment': enrichment_queue,
        'reports': report_queue
    }
    return queues.get(queue_name, scan_queue)
