from apscheduler.schedulers.background import BackgroundScheduler
from app.scheduler.refresh_job import refresh_api_keys, add_keys_from_source
import logging

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()

def start_scheduler():
    """Start scheduler untuk auto-refresh"""
    
    # Jadwalkan refresh rutin tiap 1 hari (biar yang udah lewat 7 hari lgsg kehapus)
    scheduler.add_job(
        func=refresh_api_keys,
        trigger="interval",
        days=1,
        id="refresh_keys",
        name="Refresh API Keys",
        replace_existing=True
    )
    
    # Jadwalkan tambah key dari source tiap minggu
    scheduler.add_job(
        func=add_keys_from_source,
        trigger="interval",
        days=7,
        id="add_keys_from_source",
        name="Add Keys From Source",
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("[SCHEDULER] Started! Auto-refresh every 3 days, source sync every 7 days")

def stop_scheduler():
    """Stop scheduler"""
    scheduler.shutdown()
    logger.info("[SCHEDULER] Stopped!")