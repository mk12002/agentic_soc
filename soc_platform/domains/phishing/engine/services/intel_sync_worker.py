"""
Pro-active Threat Intelligence Sync Worker.
Periodically harvests IOCs from external feeds (URLHaus, OpenPhish, etc.)
and updates the local SQLite store independently of email analysis traffic.
"""

import signal
import sys
import time

# Add parent directory to path for imports
# (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.agents.threat_intel_agent.agent import _refresh_ioc_store_if_needed
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger, setup_logging

logger = get_service_logger("intel_sync_worker")

def handle_shutdown(signum, frame):
    logger.info("Intel sync worker shutting down...")
    sys.exit(0)

def main():
    setup_logging()
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    
    # Random offset to avoid thundering herd if multiple services restart
    import random
    startup_delay = random.randint(1, 15)
    logger.info(f"Intel sync worker starting up in {startup_delay}s...", 
                interval_seconds=settings.ioc_refresh_seconds)
    time.sleep(startup_delay)

    while True:
        try:
            logger.info("Starting scheduled IOC harvest cycle...")
            start_ts = time.monotonic()
            
            # This function handles staleness checks internally via ioc_refresh_seconds
            total_iocs = _refresh_ioc_store_if_needed()
            
            elapsed = time.monotonic() - start_ts
            logger.info("IOC harvest cycle complete", 
                        total_records=total_iocs, 
                        duration_seconds=round(elapsed, 2))
            
        except Exception as exc:
            logger.error("IOC harvest cycle failed", error=str(exc))
        
        # Sleep for the refresh interval (default 300s / 5 mins)
        sleep_time = max(60, settings.ioc_refresh_seconds)
        logger.debug(f"Sleeping for {sleep_time}s until next harvest...")
        time.sleep(sleep_time)

if __name__ == "__main__":
    main()
