from datetime import datetime, date, timedelta
from decimal import Decimal
import os
import redis
from flexOps import foLoader, foCommon
from pymongo import MongoClient
from hasher import DrupalPasswordHasher
from bson import ObjectId
import json
from models import (
    User,
)
from fastapi import HTTPException
from typing import Dict, Any, Optional, List
from package_handler.centrifugo.centrifugo_socket import CentrifugoClient
import uuid
import httpx

config_path = os.getenv(
    "NEXTWAVE_CONFIG_PATH", "/neuralit/web/apps/python/Nextwave/config.ini"
)
components = foLoader.load_application(
    config_path,
    consumer_needed=False,
    setup_auth=False,
    logger_needed=True,
    cache_needed=False,
    jwt_authentication_needed=False,
    datalake_needed=False,
    database_needed=True,
)

db_connect = components["db"]
log = components["log"]
consumer = components["consumer"]
config = components["config"]

REDIS_HOST = config.get("REDIS", "host")
REDIS_PORT = config.get("REDIS", "port")
REDIS_PASSWORD = config.get("REDIS", "password")
CACHE_DB = config.get("REDIS", "cache_db")


DATALAKE_TYPE = config.get("DATA_LAKE", "type")
DATALAKE_HOST = config.get("DATA_LAKE", "host")
DATALAKE_PORT = config.get("DATA_LAKE", "port")
DATALAKE_DB = config.get("DATA_LAKE", "db")

NSQ_HOST = config.get("NSQ", "host")
NSQD_PORT = config.getint("NSQ", "nsqd_port")
NSQLOOKUPD_PORT = config.getint("NSQ", "nsqlookupd_port")

CENTRIFUGO_URL = config.get("CENTRIFUGO", "url")
CENTRIFUGO_API_KEY = config.get("CENTRIFUGO", "api_key")

if REDIS_PASSWORD:
    redis_client = redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True
    )
else:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

mongo_client = MongoClient(f"{DATALAKE_TYPE}://{DATALAKE_HOST}:{DATALAKE_PORT}/")
db_client = mongo_client[DATALAKE_DB]


def get_redis_client():
    return redis_client


def serialize_decimals(data):
    if isinstance(data, list):
        return [serialize_decimals(item) for item in data]

    elif isinstance(data, dict):
        return {
            key: str(value) if isinstance(value, Decimal) else value
            for key, value in data.items()
        }

    return data


def serialize_dates(data):
    """Recursively converts datetime and date objects in data to ISO format strings."""
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (datetime, date)):
                data[key] = value.isoformat()
            elif isinstance(value, (dict, list)):
                data[key] = serialize_dates(value)
    elif isinstance(data, list):
        data = [serialize_dates(item) for item in data]
    return data


def convert_id_to_string(data):
    if isinstance(data, dict):
        if "_id" in data and isinstance(data["_id"], ObjectId):
            data["_id"] = str(data["_id"])

        for key, value in data.items():
            data[key] = convert_id_to_string(value)
    elif isinstance(data, list):
        for i in range(len(data)):
            data[i] = convert_id_to_string(data[i])

    return data


def json_serializer(data):
    try:
        if isinstance(data, list):
            return [json_serializer(item) for item in data]
        elif isinstance(data, dict):
            return {key: json_serializer(value) for key, value in data.items()}
        elif isinstance(data, ObjectId):
            return str(data)
        elif isinstance(data, datetime):
            return data.isoformat()
        elif isinstance(data, Decimal):
            return str(data)
        else:
            return data
    except Exception as e:
        if log:
            log.error(f"Error serializing data: {e}")
        return data


def hash_password(password: str) -> str:
    """Hash the password using bcrypt."""
    try:
        if not password:
            return None

        hasher = DrupalPasswordHasher(count_log2=15)
        return hasher.hash_password(password=password)
    except Exception as e:
        raise ValueError(f"Exception in hash_password : {e}")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify if the entered password matches the stored hash."""
    try:
        if not plain_password and not hashed_password:
            return False

        hasher = DrupalPasswordHasher(count_log2=15)
        return hasher.check_password(password=plain_password, hashed=hashed_password)
    except Exception as e:
        raise ValueError(f"Exception in verify_password: {e}")


def generate_jwt_token(username, user_id, jwt_auth, access_token_expire_minutes):
    try:
        token = jwt_auth.create_jwt_token(
            data={"sub": username, "custom_id": user_id},
            expires_delta=timedelta(minutes=int(access_token_expire_minutes)),
        )
        if not token:
            raise ValueError(f"Failed to generate JWT token")
        return token
    except Exception as e:
        raise ValueError(f"Failed to generate JWT token {e}")


def get_user_roles(user_id: int):
    try:
        cache_key = f"user_roles_{user_id}"

        # Check Redis cache first
        user_roles = redis_client.json().get(cache_key, "$")
        if user_roles:
            return user_roles[0]

        # Fetch roles from DB if not found in cache
        user_roles = foCommon.db_execute(
            connection=db_connect,
            querydata="SELECT roles_target_id FROM user__roles WHERE entity_id = ?",
            params=(user_id,),
            fetchData=True,
            log=log,
        )

        # Store roles in cache for later use
        redis_client.json().set(cache_key, "$", serialize_dates(user_roles))
        print("user roles: ", user_roles)
        return serialize_dates(user_roles)
    except Exception as e:
        raise ValueError(f"Exception in user_roles: {e}")


def check_image_permissions(
    user_roles, user_permissions, state, city, operator, device=None
):
    try:
        check_permissions = True

        # Check for administrator role
        for role in user_roles or []:
            if (
                isinstance(role, dict)
                and role.get("roles_target_id") == "administrator"
            ):
                check_permissions = False
                break

        if not check_permissions:
            return True

        permissions_dict = extract_user_access(user_permissions)

        # Check if permissions_dict is empty or only has device_page_permission
        if not permissions_dict or (
            len(permissions_dict) == 1 and "device_page_permission" in permissions_dict
        ):
            return True

        # Check entity-specific permissions
        if has_permission(user_permissions, "tbl_state", [state]):
            return True
        if has_permission(user_permissions, "tbl_city", [city]):
            return True
        if has_permission(user_permissions, "tbl_operator", [operator]):
            return True
        if device and has_permission(user_permissions, "tbl_device", [device]):
            return True

        return False
    except Exception as e:
        raise ValueError(f"Exception in check_image_permissions: {e}")


def get_user_permissions(user_id: int):
    try:
        cache_key = f"user_permissions_{user_id}"

        # Check Redis cache first
        permissions = redis_client.json().get(cache_key, "$")
        if permissions:
            return permissions[0]

        # Fetch permissions from DB if not found in cache
        permissions = foCommon.db_execute(
            connection=db_connect,
            querydata="SELECT up_access_ids, up_access_type FROM tbl_user_permission WHERE up_user_id = ?",
            params=(user_id,),
            fetchData=True,
            log=log,
        )

        # Store permissions in cache for later use
        redis_client.json().set(cache_key, "$", serialize_dates(permissions))
        return serialize_dates(permissions)
    except Exception as e:
        raise ValueError(f"Exception in get_user_permissions: {e}")


def get_current_user(request, jwt_auth):
    try:
        # Check the Authorization header for Bearer token
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Unauthorized: Missing or invalid Authorization header",
            )

        token = auth_header[len("Bearer ") :]

        try:
            payload = jwt_auth.decode_jwt_token(token)
        except Exception as e:
            raise HTTPException(
                status_code=401, detail="Unauthorized: Token has expired"
            )

        username = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=401, detail="Unauthorized: Token is missing 'sub' claim"
            )

        # Cache key for user data
        user_cache_key = f"user_data_{username}"
        user = redis_client.json().get(user_cache_key, "$")

        if user:
            user = user[0]

        if not user:
            # Fetch user data from DB if not in cache
            user = foCommon.db_execute(
                connection=db_connect,
                querydata="SELECT * FROM users_field_data WHERE name = ? OR mail = ?",
                params=(username, username),
                fetchOne=True,
                log=log,
            )
            if not user:
                raise HTTPException(status_code=404, detail="User not found.")

            # Cache user data in Redis
            redis_client.json().set(user_cache_key, "$", serialize_dates(user))

        user = serialize_dates(user)
        # Get permissions from DB or cache
        user_permissions = get_user_permissions(user[0].get("uid"))

        user_roles = get_user_roles(user[0].get("uid"))

        user_obj = User(
            uid=user[0].get("uid"),
            name=user[0].get("name"),
            mail=user[0].get("mail", "") if user[0].get("mail", "") else "",
            permissions=user_permissions,
            user_roles=user_roles,
        )

        return user_obj

    except HTTPException as he:
        raise he
    except Exception as e:
        msg = str(e)
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {msg}")


def has_permission(user_permissions, access_type, access_ids):
    try:
        if user_permissions:
            for permission in user_permissions:
                if permission.get("up_access_type") == access_type:
                    user_access_ids = permission.get("up_access_ids")
                    if user_access_ids:
                        user_access_ids = (
                            set(map(int, user_access_ids.split(",")))
                            if isinstance(user_access_ids, str)
                            else set(user_access_ids)
                        )
                        if user_access_ids & set(access_ids):
                            return True
        return False
    except Exception as e:
        return False


def extract_user_access(user_object=None):
    try:
        if not user_object:
            return {}

        access_object = {}
        for permissions in user_object:
            access_type = permissions.get("up_access_type")
            access_ids = permissions.get("up_access_ids")
            # print("access type: ", access_type,"\naccess_ids",access_ids)
            if access_type is None:
                continue

            if access_type not in access_object:
                access_object[access_type] = []

            if access_ids is not None:
                if isinstance(access_ids, list):
                    access_ids = access_ids
                elif isinstance(access_ids, str):
                    access_ids = [int(id) for id in access_ids.split(",")]
                else:
                    access_ids = [access_ids]
                access_object[access_type].extend(access_ids)

        return access_object
    except Exception as e:
        raise ValueError(f"Exception in extract_user_access: {e}")


def send_message_to_nsq(topic: str, message_data: Dict):
    """Send a message to the specified NSQ topic and handle errors."""
    try:
        if isinstance(message_data, bytes):
            message_data = message_data.decode("utf-8")
        # Insert idempotency key
        if isinstance(message_data, str):
            message_data = json.loads(message_data)
        message_data["idempotency_key"] = str(uuid.uuid4())

        NSQ_URL = f"http://{NSQ_HOST}:{NSQD_PORT}/pub?topic={topic}"
        with httpx.Client() as client:
            response = client.post(NSQ_URL, data=json.dumps(message_data))

            if response.status_code != 200:
                log.error(f"Failed to publish to NSQ topic '{topic}': {response.text}")
                raise HTTPException(
                    status_code=500, detail=f"Failed to queue {topic} operation"
                )

        log.info(f"Queued {topic} successfully with message: {message_data}")
    except Exception as e:
        log.error(f"Error queuing {topic}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Error processing {topic} operation"
        )


def load_states(user_id=None):
    try:
        # print("user id to fetch states: ", user_id)
        all_states = []

        if user_id:
            if redis_client.json().get(f"tbl_state_{user_id}", "$"):
                all_states = redis_client.json().get(f"tbl_state_{user_id}", "$")
            else:
                all_states = redis_client.json().get(f"all_states", "$")
            # print("Fetched states from redis for user: ", all_states)

        else:
            all_states = redis_client.json().get(f"all_states", "$")
            # print("Fetched all states from redis  ", all_states)

        if all_states:
            return all_states[0]

        if user_id:

            user_state_ids = foCommon.db_execute(
                connection=db_connect,
                querydata=f"SELECT up_access_ids FROM tbl_user_permission WHERE up_user_id = ? AND up_access_type = ?",
                params=(user_id, "tbl_state"),
                fetchData=True,
                log=log,
            )

            user_state_ids = (
                user_state_ids[0].get("up_access_ids") if user_state_ids else None
            )
            user_state_ids = (
                [int(id) for id in user_state_ids.split(",")]
                if user_state_ids
                else None
            )
            if user_state_ids:
                placeholder = ",".join(["?"] * len(user_state_ids))
                all_states = foCommon.db_execute(
                    connection=db_connect,
                    querydata=f"SELECT * FROM tbl_state WHERE ts_is_deleted = ? AND ts_id in ({placeholder})",
                    params=(0, *user_state_ids),
                    fetchData=True,
                    log=log,
                )
                # print("Fetched states from db for user: ", user_id)
                outp = redis_client.json().set(
                    f"tbl_state_{user_id}", "$", serialize_dates(all_states)
                )
            # print("outp: ", outp)

        else:

            all_states = foCommon.db_execute(
                connection=db_connect,
                querydata=f"SELECT * FROM tbl_state WHERE ts_is_deleted = ?",
                params=(0,),
                fetchData=True,
                log=log,
            )

            # print("Fetched states from db for user: ", user_id)
            outp = redis_client.json().set(
                f"all_states", "$", serialize_dates(all_states)
            )
            # print("Fetched all states from db : ")
        return serialize_dates(all_states)
    except Exception as e:
        raise ValueError(f"Exception in load_state: {e}")


def load_district(user_id=None):
    try:
        # print("user id to fetch district: ", user_id)
        all_district = []

        if user_id:
            if redis_client.json().get(f"tbl_district_{user_id}", "$"):
                all_district = redis_client.json().get(f"tbl_district_{user_id}", "$")
                # print("Fetched district from redis for user: ", all_district)
            else:
                all_district = redis_client.json().get(f"all_district", "$")
                # print("Fetched all district from redis: ", all_district)

        else:
            all_district = redis_client.json().get(f"all_district", "$")
            # print("Fetched all district from redis: ", all_district)

        if all_district:
            return all_district[0]

        if user_id:
            user_district_ids = foCommon.db_execute(
                connection=db_connect,
                querydata=f"SELECT up_access_ids FROM tbl_user_permission WHERE up_user_id = ? AND up_access_type = ?",
                params=(user_id, "tbl_district"),
                fetchData=True,
                log=log,
            )

            user_district_ids = (
                user_district_ids[0].get("up_access_ids") if user_district_ids else None
            )
            user_district_ids = (
                [int(id) for id in user_district_ids.split(",")]
                if user_district_ids
                else None
            )
            if user_district_ids:
                placeholder = ",".join(["?"] * len(user_district_ids))
                all_district = foCommon.db_execute(
                    connection=db_connect,
                    querydata=f"SELECT * FROM tbl_district WHERE td_is_deleted = ? AND td_id in ({placeholder})",
                    params=(0, *user_district_ids),
                    fetchData=True,
                    log=log,
                )
                # print("Fetched district from db for user: ", user_id)
                outp = redis_client.json().set(
                    f"tbl_district_{user_id}", "$", serialize_dates(all_district)
                )
            # print("outp: ", outp)

        else:
            all_district = foCommon.db_execute(
                connection=db_connect,
                querydata=f"SELECT * FROM tbl_district WHERE td_is_deleted = ?",
                params=(0,),
                fetchData=True,
                log=log,
            )
            # print("Fetched all district from db: ")

        return serialize_dates(all_district)
    except Exception as e:
        raise ValueError(f"Exception in load_district: {e}")


def load_cities(user_id=None):
    try:
        all_cities = []
        if user_id:
            if redis_client.json().get(f"tbl_city_{user_id}", "$"):
                all_cities = redis_client.json().get(f"tbl_city_{user_id}", "$")
            else:
                all_cities = redis_client.json().get(f"all_cities", "$")
                # print("Fetched cities from redis for user1: ", all_cities)

        else:
            all_cities = redis_client.json().get(f"all_cities", "$")
            # print("Fetched all cities from redis")

        if all_cities:
            return all_cities[0]

        if user_id:

            user_city_ids = foCommon.db_execute(
                connection=db_connect,
                querydata=f"SELECT up_access_ids FROM tbl_user_permission WHERE up_user_id = ? AND up_access_type = ?",
                params=(user_id, "tbl_city"),
                fetchData=True,
                log=log,
            )

            user_city_ids = (
                user_city_ids[0].get("up_access_ids") if user_city_ids else None
            )
            user_city_ids = (
                [int(id) for id in user_city_ids.split(",")] if user_city_ids else None
            )

            if user_city_ids:
                placeholder = ",".join(["?"] * len(user_city_ids))
                all_cities = foCommon.db_execute(
                    connection=db_connect,
                    querydata=f"SELECT * FROM tbl_city WHERE tc_is_deleted = ? AND tc_id in ({placeholder})",
                    params=(0, *user_city_ids),
                    fetchData=True,
                    log=log,
                )
                # print("Fetched cities from db for user: ", user_id)
                outp = redis_client.json().set(
                    f"tbl_city_{user_id}", "$", serialize_dates(all_cities)
                )
            # print("outp: ", outp)
        else:
            all_cities = foCommon.db_execute(
                connection=db_connect,
                querydata=f"SELECT * FROM tbl_city WHERE tc_is_deleted = ?",
                params=(0,),
                fetchData=True,
                log=log,
            )

            outp = redis_client.json().set(
                f"all_cities", "$", serialize_dates(all_cities)
            )
        return serialize_dates(all_cities)
    except Exception as e:
        raise ValueError(f"Exception in load_city: {e}")


def load_operators(user_id=None):
    try:
        # print("user id to fetch operators: ", user_id)
        all_operators = []

        if user_id:
            if redis_client.json().get(f"tbl_operator_{user_id}", "$"):
                all_operators = redis_client.json().get(f"tbl_operator_{user_id}", "$")
                # print("Fetched operators from redis for user: ", all_operators)
            else:
                all_operators = redis_client.json().get(f"all_operators", "$")
        else:
            all_operators = redis_client.json().get(f"all_operators", "$")
            # print("Fetched all operators from redis: ", all_operators)

        if all_operators:
            return all_operators[0]

        if user_id:
            user_operator_ids = foCommon.db_execute(
                connection=db_connect,
                querydata=f"SELECT up_access_ids FROM tbl_user_permission WHERE up_user_id = ? AND up_access_type = ?",
                params=(user_id, "tbl_operator"),
                fetchData=True,
                log=log,
            )

            user_operator_ids = (
                user_operator_ids[0].get("up_access_ids") if user_operator_ids else None
            )
            user_operator_ids = (
                [int(id) for id in user_operator_ids.split(",")]
                if user_operator_ids
                else None
            )
            if user_operator_ids:
                placeholder = ",".join(["?"] * len(user_operator_ids))
                all_operators = foCommon.db_execute(
                    connection=db_connect,
                    querydata=f"""SELECT 
                            `to`.*, 
                            `ts`.`ts_name`, 
                            `tc`.`tc_name`
                        FROM 
                            `tbl_operator` AS `to`
                        LEFT JOIN 
                            `tbl_state` AS `ts` 
                            ON `to`.`to_state_id` = `ts`.`ts_id`
                        LEFT JOIN 
                            `tbl_city` AS `tc` 
                        ON `to`.`to_city_id` = `tc`.`tc_id` WHERE to_is_deleted = ? AND to_id in ({placeholder})""",
                    params=(0, *user_operator_ids),
                    fetchData=True,
                    log=log,
                )
                # print("Fetched operators from db for user: ", user_id)
                outp = redis_client.json().set(
                    f"tbl_operator_{user_id}", "$", serialize_dates(all_operators)
                )
            # print("outp: ", outp)

        else:
            all_operators = foCommon.db_execute(
                connection=db_connect,
                querydata=f"""SELECT 
                        `to`.*, 
                        `ts`.`ts_name`, 
                        `tc`.`tc_name`
                    FROM 
                        `tbl_operator` AS `to`
                    LEFT JOIN 
                        `tbl_state` AS `ts` 
                        ON `to`.`to_state_id` = `ts`.`ts_id`
                    LEFT JOIN 
                        `tbl_city` AS `tc` 
                        ON `to`.`to_city_id` = `tc`.`tc_id` WHERE to_is_deleted = ?""",
                params=(0,),
                fetchData=True,
                log=log,
            )
            # print("Fetched all operators from db: ")
            outp = redis_client.json().set(
                f"all_operators", "$", serialize_dates(all_operators)
            )
        return serialize_dates(all_operators)
    except Exception as e:
        raise ValueError(f"Exception in load_operators: {e}")


def load_devices(user_id=None):
    try:
        # print("user id to fetch devices: ", user_id)
        all_devices = []

        if user_id:
            if redis_client.json().get(f"tbl_device_{user_id}", "$"):
                all_devices = redis_client.json().get(f"tbl_device_{user_id}", "$")
                # print("Fetched devices from redis for user: ", all_devices)
            else:
                all_devices = redis_client.json().get(f"all_devices", "$")
        else:
            all_devices = redis_client.json().get(f"all_devices", "$")
            # print("Fetched all devices from redis: ", all_devices)

        if all_devices:
            return all_devices[0]

        if user_id:
            user_device_ids = foCommon.db_execute(
                connection=db_connect,
                querydata=f"SELECT up_access_ids FROM tbl_user_permission WHERE up_user_id = ? AND up_access_type = ?",
                params=(user_id, "tbl_device"),
                fetchData=True,
                log=log,
            )

            user_device_ids = (
                user_device_ids[0].get("up_access_ids") if user_device_ids else None
            )
            user_device_ids = (
                [int(id) for id in user_device_ids.split(",")]
                if user_device_ids
                else None
            )
            if user_device_ids:
                placeholder = ",".join(["?"] * len(user_device_ids))
                all_devices = foCommon.db_execute(
                    connection=db_connect,
                    querydata=f"SELECT * FROM tbl_device WHERE td_is_deleted = ? AND td_id in ({placeholder})",
                    params=(0, *user_device_ids),
                    fetchData=True,
                    log=log,
                )
                # print("Fetched devices from db for user: ", user_id)
                outp = redis_client.json().set(
                    f"tbl_device_{user_id}", "$", serialize_dates(all_devices)
                )
            # print("outp: ", outp)

        else:
            all_devices = foCommon.db_execute(
                connection=db_connect,
                querydata=f"SELECT * FROM tbl_device WHERE td_is_deleted = ?",
                params=(0,),
                fetchData=True,
                log=log,
            )
            # print("Fetched all devices from db: ")

        return serialize_dates(all_devices)
    except Exception as e:
        raise ValueError(f"Exception in load_devices: {e}")


def load_channels(user_id=None):
    try:
        # print("user id to fetch channels: ", user_id)
        all_channels = []

        if user_id:
            if redis_client.json().get(f"tbl_channels_{user_id}", "$"):
                all_channels = redis_client.json().get(f"tbl_channels_{user_id}", "$")
                # print("Fetched channels from redis for user: ", all_channels)
            else:
                all_channels = redis_client.json().get(f"all_channels", "$")
                # print("Fetched all channels from redis: ", all_channels)

        else:
            all_channels = redis_client.json().get(f"all_channels", "$")
            # print("Fetched all channels from redis: ", all_channels)

        if all_channels:
            return all_channels[0]

        if user_id:
            user_channel_ids = foCommon.db_execute(
                connection=db_connect,
                querydata=f"SELECT up_access_ids FROM tbl_user_permission WHERE up_user_id = ? AND up_access_type = ?",
                params=(user_id, "tbl_channels"),
                fetchData=True,
                log=log,
            )

            user_channel_ids = (
                user_channel_ids[0].get("up_access_ids") if user_channel_ids else None
            )
            user_channel_ids = (
                [int(id) for id in user_channel_ids.split(",")]
                if user_channel_ids
                else None
            )
            if user_channel_ids:
                placeholder = ",".join(["?"] * len(user_channel_ids))
                all_channels = foCommon.db_execute(
                    connection=db_connect,
                    querydata=f"SELECT * FROM tbl_channels WHERE ch_is_deleted = ? AND ch_id in ({placeholder})",
                    params=(0, *user_channel_ids),
                    fetchData=True,
                    log=log,
                )
                # print("Fetched channels from db for user: ", user_id)
                outp = redis_client.json().set(
                    f"tbl_channels_{user_id}", "$", serialize_dates(all_channels)
                )
            # print("outp: ", outp)

        else:
            all_channels = foCommon.db_execute(
                connection=db_connect,
                querydata=f"SELECT * FROM tbl_channels WHERE ch_is_deleted = ?",
                params=(0,),
                fetchData=True,
                log=log,
            )
            # print("Fetched all channels from db: ")

        return serialize_dates(all_channels)
    except Exception as e:
        raise ValueError(f"Exception in load_channels: {e}")


def fetch_batches_data(
    state: int,
    city: int,
    operator: int,
    date: Optional[str] = None,
    device_id: int = None,
) -> List:
    try:
        coll = db_client["tbl_device_channel_images_data"]
        # Build the filter query with all compulsory parameters.
        filter_query = {
            "state": state,
            "city": city,
            "operator": operator,
            "isDeleted": {"$ne": 1},
            # "device": device_id,
        }

        if device_id and not str(device_id) == "null":
            filter_query["device"] = int(device_id)

        if date:
            filter_query["batch_date"] = date

        pipeline = [
            {"$match": filter_query},
            {
                "$project": {
                    "_id": "$batch",
                    "img_count": {
                        "$size": {
                            "$filter": {
                                "input": "$images",
                                "as": "img",
                                "cond": { "$ne": ["$$img.isLanding", 1] }
                            }
                        }
                    }
                },
            },
        ]

        batches = list(coll.aggregate(pipeline))

        return [f'{doc["_id"]} ({doc["img_count"]})' for doc in batches]

    except Exception as e:
        if log:
            log.error(f"Error in fetching batches data: {e}", exc_info=True)
        raise Exception(f"Error fetching batches data: {e}")


def to_int_safe(value):
    try:
        return int(value or 0)
    except (ValueError, TypeError):
        return 0


def fetch_device_channel_images_data(state, city, operator, batch_date, device=None, batch=None, fetch_multi_batches=None):
    try:
        if not all(
            [
                state not in [None, "undefined"],
                city not in [None, "undefined"],
                operator not in [None, "undefined"],
                batch_date not in [None, "undefined"],
            ]
        ):
            raise ValueError(
                "'state', 'city', 'operator', and 'batch_date' parameters are required."
            )

        tbl_device_channel_images_data = db_client["tbl_device_channel_images_data"]
        tbl_last_sequence_data = db_client["tbl_last_sequence_data"]

        filter_query = {
            "state": int(state),
            "city": int(city),
            "operator": int(operator),
            "batch_date": batch_date,
            "isDeleted": {"$ne": 1},
        }

        # If batch is not provided, fetch the latest batch for the given batch_date
        if batch is None and not fetch_multi_batches:
            batch_pipeline = [
                {"$match": filter_query},
                {"$sort": {"batch": -1}},
                {"$project": {"batch": 1, "_id": 0}},
            ]

            batch_cursor = list(
                tbl_device_channel_images_data.aggregate(batch_pipeline)
            )

            if not batch_cursor:
                raise ValueError(f"No batch found for batch_date: {batch_date}")

            batch = batch_cursor[0]["batch"]

        if batch and not fetch_multi_batches:
            filter_query["batch"] = int(batch)
        
        if device and isinstance(device, int):
            filter_query["device"] = device
        
        if fetch_multi_batches:
            # Fetch parent document
            parent_doc = tbl_device_channel_images_data.find(filter_query)
            multi_batches_doc = {}
            if parent_doc:
                for doc in parent_doc:
                    images = doc.get("images")
                    images_sorted = sorted(
                        [img for img in images if img.get("isLanding") != 1],
                        key=lambda img: img.get("sequence", 0),
                    ) if images else []
                    doc["images"] = images_sorted
                    multi_batches_doc[doc.get("batch")] = doc
            return serialize_dates(serialize_decimals(multi_batches_doc))
        else:
            # Fetch parent document
            parent_doc = tbl_device_channel_images_data.find_one(filter_query)
        
        if not parent_doc or not isinstance(parent_doc, dict):
            raise ValueError("No data found")

        if parent_doc.get("isProcessed"):
            if log:
                log.info(
                    f"batch {state}-{city}-{operator}-{batch} already processed, returning the same."
                )
            print("batch already processed, returning the same.")
            return serialize_dates(serialize_decimals(parent_doc))

        images = parent_doc.get("images", [])

        if not images:
            raise ValueError("No Images data found")

        # Filter out images
        images = sorted(
            [img for img in images if img.get("isLanding") != 1],
            key=lambda img: img.get("sequence", 0),
        )

        # Fetch additional metadata from tbl_last_sequence_data
        sequence_data_doc = tbl_last_sequence_data.find_one(
            {
                "state": int(state),
                "city": int(city),
                "operator": int(operator),
                "version": 1,
            },
            {"sequence": 1, "_id": 0},
        )
        sequence_images = (
            sequence_data_doc.get("sequence", []) if sequence_data_doc else []
        )
        if sequence_images:
            for idx, img in enumerate(images):
                seq_img = sequence_images[idx] if len(sequence_images) > idx else {}
                img["lcn"] = seq_img.get("lcn", 0)
                img["channel_id"] = seq_img.get("channel_id", 0)

        images_sorted = sorted(images, key=lambda x: x.get("sequence", float("inf")))

        parent_doc["images"] = images_sorted
        if log:
            log.info(
                f"batch {state}-{city}-{operator}-{batch} not processed , returning from last sequence"
            )
        return serialize_dates(serialize_decimals(parent_doc))

    except ValueError as ve:
        if log:
            log.error(f"Error in fetch_device_channel_images_data: {ve}", exc_info=True)
        raise ValueError(f"{ve}")

    except Exception as e:
        if log:
            log.error(f"Error in fetch_device_channel_images_data: {e}", exc_info=True)
        raise ValueError(f"Unexpected Error: {e}")


def submit_device_channel_images_data(
    state, city, operator, batch, updated_images, user={}
):
    try:
        if not all(
            [
                state not in [None, "undefined"],
                city not in [None, "undefined"],
                operator not in [None, "undefined"],
                batch not in [None, "undefined"],
                updated_images not in [None, "undefined"],
            ]
        ):
            raise ValueError(
                "'state', 'city', 'operator', 'batch', and 'updated_images' are required."
            )

        tbl_device_channel_images_data = db_client["tbl_device_channel_images_data"]
        tbl_last_sequence_data = db_client["tbl_last_sequence_data"]
        
        batch = batch.split()[0]
        
        filter_query = {
            "state": int(state),
            "city": int(city),
            "operator": int(operator),
            "batch": int(batch),
        }

        # Step 1: Update tbl_device_channel_images_data
        existing_doc = tbl_device_channel_images_data.find_one(filter_query)

        if not existing_doc:
            raise ValueError(
                "No matching document found in tbl_device_channel_images_data."
            )

        images = sorted(
            [
                img
                for img in existing_doc.get("images", [])
                if img.get("isLanding") != 1
            ],
            key=lambda img: img.get("sequence", 0),
        )

        # Create a map for the existing images based on index
        existing_images_map = {idx: img for idx, img in enumerate(images)}

        # Update existing images based on sequence field with specified fields
        for idx, new_img in enumerate(updated_images):
            if idx in existing_images_map:
                existing_images_map[idx].update(
                    {
                        "channel_id": new_img.get("channel_id"),
                        "lcn": new_img.get("lcn"),
                    }
                )

        updated_images_list = list(existing_images_map.values())

        tbl_device_channel_images_data.update_one(
            filter_query,
            {
                "$set": {
                    "images": updated_images_list,
                    "isProcessed": 1,
                    "updated_by": {
                        "uid": user.get("uid"),
                        "username": user.get("name"),
                    },
                }
            },
        )

        # Step 2: Manage separate version documents in tbl_last_sequence_data
        last_seq_filter = {
            "state": int(state),
            "city": int(city),
            "operator": int(operator),
        }

        # Fetch the latest version 1 document (if it exists)
        version_1_doc = tbl_last_sequence_data.find_one(
            {**last_seq_filter, "version": 1}
        )

        if version_1_doc:
            # Rotate versions in tbl_last_sequence_data
            tbl_last_sequence_data.delete_one({**last_seq_filter, "version": 3})
            tbl_last_sequence_data.update_one(
                {**last_seq_filter, "version": 2}, {"$set": {"version": 3}}
            )
            tbl_last_sequence_data.update_one(
                {**last_seq_filter, "version": 1}, {"$set": {"version": 2}}
            )

        # Prepare filtered images for the new version
        filtered_images = [
            {
                "channel_id": img.get("channel_id"),
                "lcn": img.get("lcn"),
            }
            for img in updated_images
        ]

        # Create a new version document for tbl_last_sequence_data
        new_version = {
            "state": int(state),
            "city": int(city),
            "operator": int(operator),
            "version": 1,
            "updated_at": datetime.now(),
            "sequence": filtered_images,
        }

        tbl_last_sequence_data.insert_one(new_version)

        add_activity_log(
            entity="image-scheduling",
            activity_type="add",
            activity_desc=f"User: `{user.get('name')}` has submitted image scheduling for {state}-{city}-{operator}-{batch}.",
            user=user,
        )
        return {"status": "success", "message": "Data submitted successfully"}

    except ValueError as ve:
        if log:
            log.error(
                f"Error in submit_device_channel_images_data: {ve}", exc_info=True
            )
        raise ValueError(f"{str(ve)}")
    except Exception as e:
        if log:
            log.error(f"Error in submit_device_channel_images_data: {e}", exc_info=True)
        raise ValueError(f"Unexpected Error: {str(e)}")


def publish_to_websocket(channel_name: str, message: dict):

    ws_handler = CentrifugoClient(CENTRIFUGO_URL, CENTRIFUGO_API_KEY)
    print("message: ", message)
    ws_handler.publish(channel=channel_name, data=json.dumps(message))


def get_device_data(device_mac_id, database_id=3):
    if not device_mac_id:
        return None
    try:
        redis_client.select(database_id)
        data = redis_client.get(f"{device_mac_id}")
    finally:
        redis_client.select(CACHE_DB)
    # data = redis_client.json().get(f"{device_mac_id}", "$")
    if data:
        return data
    else:
        return None


def fetch_customer_info():
    try:
        customer_info = foCommon.db_execute(
            connection=db_connect,
            querydata="SELECT * FROM `view_device_customer_link`",
            log=log,
        )
        return customer_info if customer_info else None
    except Exception as e:
        if log:
            log.error(f"Error fetching customer info: {str(e)}")
        print(f"Error fetching customer info: {str(e)}")
        return None


def add_activity_log(
    entity: str,
    activity_type: str,
    activity_desc: str,
    user,
):
    try:
        log_entry_data = {
            "entity": entity,
            "activity_type": activity_type,
            "activity_description": activity_desc,
            "performed_by": user.get("uid"),
            "performed_at": datetime.now(),
        }
        activity_log = db_client["activity_log"]
        activity_log.insert_one(log_entry_data)
    except Exception as e:
        if log:
            log.error(f"Error logging activity: {e}")


def fetch_device_channel_images_data_in_batches(
    state, city, operator, start_date, end_date, device=None
):
    try:

        if not all(
            [
                state not in [None, "undefined"],
                city not in [None, "undefined"],
                operator not in [None, "undefined"],
                start_date not in [None, "undefined"],
                end_date not in [None, "undefined"],
            ]
        ):
            raise ValueError(
                "'state', 'city', 'operator', 'start_date', and 'end_date' parameters are required."
            )

        tbl_device_channel_images_data = db_client["tbl_device_channel_images_data"]

        filter_query = {
            "state": int(state),
            "city": int(city),
            "operator": int(operator),
            "isDeleted": {"$ne": 1},
            "batch_date": {"$gte": start_date, "$lte": end_date},
        }

        print("filter_query: ", filter_query)

        # Fetch all documents that match the date range and filter criteria
        cursor = tbl_device_channel_images_data.find(filter_query)

        # Prepare the final response
        device_image_data = {
            "state": state,
            "city": city,
            "operator": operator,
            "device": int(device) if device else None,
            "filtered_batches": {},
        }

        # Iterate over the documents and group them by batch_date
        for doc in cursor:

            batch_date = doc.get("batch_date")

            if batch_date and doc.get("isProcessed"):

                if isinstance(batch_date, datetime):
                    batch_date = batch_date.strftime("%Y-%m-%d")

                if batch_date not in device_image_data["filtered_batches"]:
                    device_image_data["filtered_batches"][batch_date] = {}

                images = doc.get("images", [])
                # Filter out images that are "Landing" (if needed)
                images = [img for img in images if img.get("isLanding") != 1]
                images[0]["updated_by"] = doc.get("updated_by", {})
                # Add images to the corresponding batch_date
                device_image_data["filtered_batches"][batch_date][
                    doc.get("batch")
                ] = images

        return serialize_dates(serialize_decimals(device_image_data))

    except ValueError as ve:
        if log:
            log.error(f"Error in fetch_device_channel_images_data: {ve}", exc_info=True)
        raise ValueError(f"{ve}")

    except Exception as e:
        if log:
            log.error(f"Error in fetch_device_channel_images_data: {e}", exc_info=True)
        raise ValueError(f"Unexpected Error: {e}")


def delete_batch(state: int, city: int, operator: int, device: int, batches: List[str], batch_date: str) -> None:
    try:
        coll = db_client["tbl_device_channel_images_data"]
        
        filter_query = {
            "state": state,
            "city": city,
            "operator": operator,
            "device": device,
            "batch_date": batch_date,
            "batch": {"$in": [int(batch) for batch in batches]}
        }
        print("filter: ", filter_query)
        update_query = {
            "$set": {
                "isDeleted": 1
            }
        }

        result = coll.update_many(filter_query, update_query)

        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="No batches found to delete.")
        
        return result.modified_count

    except Exception as e:
        if log:
            log.error(f"Failed to delete batches: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete batches: {str(e)}")


def fetch_rf_batches_data(
    state, city, operator, device, date, log=None
) -> List:
    try:
        if not all([
            state not in [None, "undefined"],
            city not in [None, "undefined"],
            operator not in [None, "undefined"],
            device not in [None, "undefined"],
            date not in [None, "undefined"]
        ]):
            raise ValueError("All parameters are required")

        coll = db_client["device_csv_data"]

        filter_query = {
            "tdcd_state_id": state,
            "tdcd_city_id": city,
            "tdcd_device_id": device,
            "tdcd_operator_id": operator,
            "tdcd_timestamp_date": date,
        }

        pipeline = [
            {"$match": filter_query},
            {"$project": {
                "_id": "$tdcd_unique_key",
                # "cas_data": "$tdcd_cas_data"
            }}
        ]

        batches = list(coll.aggregate(pipeline))
        return batches

    except Exception as e:
        if log:
            log.error(f"Error: {str(e)}", exc_info=True)
        raise


def fetch_rf_data(unique_key: str):
    try:
        if unique_key in [None, "undefined"]:
            raise ValueError(
                "'unique_key' parameters is required."
            )
        
        device_csv_data = db_client["device_csv_data"]
        
        filter_query = {
            "tdcd_unique_key": unique_key,
        }
        
        rf_data = device_csv_data.find_one(filter_query)
        
        return rf_data
    
    except ValueError as ve:
        raise ve
    except Exception as e:
        raise Exception(f"Error in `fetch_rf_data`: {e}")
