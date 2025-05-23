import os
import redis
from flexOps import foLoader
from datetime import datetime

config_path = os.getenv(
    "NEXTWAVE_CONFIG_PATH", "/home/neuralit/Workspace/Nextwave/Nextwave/config.ini"
)
components = foLoader.load_application(
    config_path,
    consumer_needed=False,
    setup_auth=False,
    logger_needed=True,
    cache_needed=False,
    jwt_authentication_needed=False,
    datalake_needed=False,
    database_needed=False,
)

log = components["log"]
config = components["config"]

REDIS_HOST = config.get("REDIS", "host")
REDIS_PORT = config.get("REDIS", "port")
REDIS_PASSWORD = config.get("REDIS", "password")
CACHE_DB = int(config.get("REDIS", "cache_db"))

if REDIS_PASSWORD:
    redis_client = redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=CACHE_DB, decode_responses=True
    )
else:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=CACHE_DB, decode_responses=True)

def clear_redis_db():
    try:
        redis_client.flushdb()
        log.info(f"Redis database {CACHE_DB} cleared successfully at {datetime.now()}")
    except Exception as e:
        log.error(f"Error clearing Redis database {CACHE_DB}: {e}")

if __name__ == "__main__":
    clear_redis_db()
