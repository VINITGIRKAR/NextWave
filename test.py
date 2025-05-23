import os
import configparser
from bson import ObjectId
from pymongo import MongoClient

#  Read config.ini (or fall back to sensible defaults)
config_path = os.getenv(
    "NEXTWAVE_CONFIG_PATH",
    "/home/neuralit/Documents/nextwave_workspace/Backend/Nextwave/config.ini"
)

cfg = configparser.ConfigParser()
cfg.read(config_path)

DATALAKE_TYPE = cfg.get("DATA_LAKE", "type", fallback="mongodb")
DATALAKE_HOST = cfg.get("DATA_LAKE", "host", fallback="localhost")
DATALAKE_PORT = cfg.getint("DATA_LAKE", "port", fallback=27017)
DATALAKE_DB   = cfg.get("DATA_LAKE", "db",   fallback="nextwave")

# 2) Connect to Mongo

mongo_client = MongoClient(f"{DATALAKE_TYPE}://{DATALAKE_HOST}:{DATALAKE_PORT}/")
db          = mongo_client[DATALAKE_DB]
test_col    = db["test"]

# 3) Add/update contact number for the specific document

result_one = test_col.update_one(
    {"_id": ObjectId("682d7dce4a6dc1051dd05c80")},
    {"$set": {"contact_number": "9876543210"}}
)
print(f"[single] matched={result_one.matched_count}, updated={result_one.modified_count}")

# 4) Initialize new field for all documents
new_field_name = "status"  # Change this to your desired field name
default_value = "active"   # Change this to your desired default value

# Initialize the new field for all documents that don't have it
result_new_field = test_col.update_many(
    {new_field_name: {"$exists": False}},
    {"$set": {new_field_name: default_value}}
)
print(f"[new field] initialized {result_new_field.modified_count} docs with '{new_field_name}'")

# 5) (Optional) Ensure every doc has the contact_number field
result_many = test_col.update_many(
    {"contact_number": {"$exists": False}},
    {"$set": {"contact_number": None}}
)
print(f"[sweep] initialized {result_many.modified_count} other docs with contact_number")

# 6) Quick sanity check
print(test_col.find_one({"_id": ObjectId("682d7dce4a6dc1051dd05c80")}))
