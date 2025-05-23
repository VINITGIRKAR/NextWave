from pymongo import MongoClient
from datetime import datetime, timedelta
from flexOps import foLoader
import os


def archive_old_data():
    try:
        config_path = os.getenv(
            "NEXTWAVE_CONFIG_PATH", "/home/neuralit/Documents/nextwave_workspace/Backend/Nextwave/config.ini",
        )
        components = foLoader.load_application(
            config_path,
            consumer_needed=False,
            setup_auth=False,
            logger_needed=False,
            cache_needed=False,
            jwt_authentication_needed=False,
            datalake_needed=False,
            database_needed=False,
        )

        config = components["config"]
        datalake_type = config.get("DATA_LAKE", "type")
        datalake_host = config.get("DATA_LAKE", "host")
        datalake_port = config.get("DATA_LAKE", "port")
        datalake_db = config.get("DATA_LAKE", "db")

        mongo_client = MongoClient(
            f"{datalake_type}://{datalake_host}:{datalake_port}/"
        )
        db_client = mongo_client[datalake_db]

        source_collection = db_client["tbl_device_channel_images_data"]
        archive_collection = db_client["tbl_archived_device_images"]
        threshold_date = datetime.now() - timedelta(days=90)
        old_records = list(
            source_collection.find({"timestamp": {"$lt": threshold_date}})
        )

        if old_records:
            archive_collection.insert_many(old_records)
            ids_to_delete = [record["_id"] for record in old_records]
            source_collection.delete_many({"_id": {"$in": ids_to_delete}})

            print(f"Archived {len(old_records)} records successfully.")
        else:
            print("No records to archive.")

        mongo_client.close()
    except Exception as e:
        raise ValueError(f"Exception in archive_data: {e}")


if __name__ == "__main__":
    archive_old_data()
