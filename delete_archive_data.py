from pymongo import MongoClient
from datetime import datetime, timedelta
from flexOps import foLoader
import os
import traceback


def delete_old_archived_data():
    config = None
    mongo_client = None
    
    try:
        config_path = os.getenv(
            "NEXTWAVE_CONFIG_PATH", "/home/neuralit/Documents/nextwave_workspace/Backend/Nextwave/config.ini",
        )

        if not os.path.exists(config_path):
            raise ValueError(f"Config file not found at: {config_path}")
    
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

        config = components["config"]
        log = components.get("log")
        
        cron_type = "ARCHIVE_DELETION_MONGO_DATA"

        datalake_type = config.get("DATA_LAKE", "type")
        datalake_host = config.get("DATA_LAKE", "host")
        datalake_port = config.get("DATA_LAKE", "port")
        datalake_db = config.get("DATA_LAKE", "db")
        destination_coll = config.get(cron_type, "destination_collection")
        delete_after_days = int(config.get(cron_type, "delete_after_days", fallback="365"))

        with MongoClient(
            f"{datalake_type}://{datalake_host}:{datalake_port}/",
            connectTimeoutMS=10000,
            serverSelectionTimeoutMS=10000,
        ) as mongo_client:
            db_client = mongo_client[datalake_db]

            if destination_coll not in db_client.list_collection_names():
                if log:
                    log.info(f"Archive collection {destination_coll} does not exist - nothing to delete")
                return

            archive_collection = db_client[destination_coll]

            # Calculate threshold date (30 days from now)
            # Calculate threshold date (1 year ago from now)
            threshold_date = datetime.utcnow() - timedelta(days=delete_after_days)
            threshold_date_str = threshold_date.date().strftime("%Y-%m-%d")

            if log:
                log.info(f"Deleting archived data older than: {threshold_date_str}")

            # Delete documents older than 1 year
            result = archive_collection.delete_many({"batch_date": {"$lte": threshold_date_str}})

            if log:
                log.info(f"Deleted {result.deleted_count} documents from archive collection")

    except Exception as e:
        error_msg = f"Error in delete_old_archived_data: {str(e)}\n{traceback.format_exc()}"
        if log:
            log.error(error_msg)
        else:
            print(error_msg)
        raise


if __name__ == "__main__":
    delete_old_archived_data()
