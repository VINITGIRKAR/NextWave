from pymongo import MongoClient
from datetime import datetime, timedelta
from flexOps import foLoader
import os
import traceback
import sys


def archive_old_data():
    config = None
    mongo_client = None
    
    try:
        config_path = os.getenv(
    "NEXTWAVE_CONFIG_PATH", "/home/neuralit/Documents/nextwave_workspace/Backend/Nextwave/config.ini",
        )

        if not os.path.exists(config_path):
            raise ValueError(f"Config file not found at: {config_path}")
            #raise ValueError("Config File Not Found at:", config_path)
    
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
        
        cron_type = "ARCHIVE_MONGO_DATA"

        datalake_type = config.get("DATA_LAKE", "type")
        datalake_host = config.get("DATA_LAKE", "host")
        datalake_port = config.get("DATA_LAKE", "port")
        datalake_db = config.get("DATA_LAKE", "db")
        source_coll = config.get(cron_type, "source_collection")
        destination_coll = config.get(cron_type, "destination_collection")
        time_diff = int(config.get(cron_type, "time_period"))

        with MongoClient(
            f"{datalake_type}://{datalake_host}:{datalake_port}/",
            connectTimeoutMS=10000,
            serverSelectionTimeoutMS=10000,
        ) as mongo_client:
            db_client = mongo_client[datalake_db]

            if source_coll not in db_client.list_collection_names():
                raise ValueError(f"Source collection {source_coll} does not exist")

            source_collection = db_client[source_coll]
            archive_collection = db_client[destination_coll]

            threshold_date = datetime.utcnow() - timedelta(days=time_diff)

            # threshold_date_str = threshold_date.date().isoformat()
            threshold_date_str = threshold_date.date().strftime("%Y-%m-%d")

            print(f"threshold date: {threshold_date_str}")

            batch_size = 1000
            total_archived = 0

            while True:
                cursor = source_collection.find(
                    {"batch_date": {"$lte": threshold_date_str}}
                ).limit(batch_size)

                batch = list(cursor)
                if not batch:
                    break

                try:
                    archive_collection.insert_many(batch, ordered=False)
                except Exception as e:
                    if "duplicate key error" not in str(e).lower():
                        raise
                    if log:
                        log.warning("Skipped duplicate documents during archiving")

                ids_to_delete = [doc["_id"] for doc in batch]
                source_collection.delete_many({"_id": {"$in": ids_to_delete}})

                # Delete the archived documents from the source collection
                # ids_to_delete = [doc["_id"] for doc in batch]
                # source_collection.delete_many({"_id": {"$in": ids_to_delete}})

                # Uncomment the following line if you want to keep the documents in the source collection
                # instead of deleting them after archiving.
                #ids_not_to_delete = [doc["_id"] for doc in batch]
                #source_collection.insert_many({"_id": {"$in": ids_not_to_delete}})

                total_archived += len(batch)
                if log:
                    log.info(f"Archived {len(batch)} documents in current batch")

            if log:
                if total_archived > 0:
                    log.info(f"Successfully archived {total_archived} documents total")
                else:
                    log.info("No documents found to archive")

    except Exception as e:
        error_msg = f"Error in archive_old_data: {str(e)}\n{traceback.format_exc()}"
        if log:
            log.error(error_msg)
        else:
            print(error_msg)
        raise


if __name__ == "__main__":
    # if len(sys.argv) < 2:
    #     print("Usage: python3 move_to_archive.py <cron_name>")
    #     sys.exit(1)
    # cron_type = sys.argv[1]
    archive_old_data()
