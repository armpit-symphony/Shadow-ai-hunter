"""
Shadow AI Hunter - RQ Detection Worker Entrypoint
Processes jobs from the 'detection' queue.

Usage:
    python run_worker.py

Environment variables (same as backend):
    MONGO_URL   - MongoDB connection string
    REDIS_URL   - Redis connection string (default: redis://localhost:6379/0)

The worker watches the 'detection' queue and calls functions
enqueued by /ingest/event (via workers.queue.detection_queue).
"""
import sys
import os

# Ensure the backend/ directory is on the Python path so that
# 'from workers.detector_worker import run_detection' resolves correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from workers.queue import detection_queue
from rq import Worker

if __name__ == "__main__":
    print("Starting RQ worker on queue: detection")
    print(f"MONGO_URL  = {os.getenv('MONGO_URL', 'not set')}")
    print(f"REDIS_URL = {os.getenv('REDIS_URL', 'redis://localhost:6379/0')}")

    worker = Worker(
        [detection_queue],
        connection=detection_queue.connection,
        name="shadow-ai-detector",
    )
    worker.work()
