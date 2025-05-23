import json
from fastapi import FastAPI, Form, Request, HTTPException, Depends, Body
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
from typing import Optional
from flexOps import foCommon, foLoader
from flexOps.foJWTAuthentication import JWTAuthentication
from common_functions import (
    verify_password,
    serialize_dates,
    serialize_decimals,
    load_states,
    load_district,
    load_cities,
    get_redis_client,
    load_operators,
    load_devices,
    load_channels,
    fetch_device_channel_images_data,
    fetch_device_channel_images_data_in_batches,
    extract_user_access,
    generate_jwt_token,
    get_current_user,
    json_serializer,
    publish_to_websocket,
    get_user_permissions,
    has_permission,
    fetch_batches_data,
    send_message_to_nsq,
    get_device_data,
    fetch_customer_info,
    check_image_permissions,
    delete_batch,
    fetch_rf_batches_data,
    fetch_rf_data,
    fetch_entities,
    create_entity_helper,
    update_entity_helper,
    delete_entity_helper,
    fetch_entity_by_id,
    test_func,
)
from models import (
    User,
)


config_path = os.getenv(
    "NEXTWAVE_CONFIG_PATH", "/home/neuralit/Documents/nextwave_workspace/Backend/Nextwave/config.ini"
)
components = foLoader.load_application(
    config_path,
    consumer_needed=False,
    setup_auth=False,
    logger_needed=True,
    cache_needed=True,
    jwt_authentication_needed=True,
    datalake_needed=True,
    database_needed=True,
)

config = components["config"]
db_connect = components["db"]
log = components["log"]
jwt_auth: JWTAuthentication = components["jwt_auth"]
access_token_expire_minutes = config.get("JWT", "access_token_expire_minutes")

redis_client = get_redis_client()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_current_user_dependency(request: Request):
    return get_current_user(request, jwt_auth=jwt_auth)


@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    try:
        user = foCommon.db_execute(
            connection=db_connect,
            querydata=f"SELECT * FROM users_field_data WHERE name = ? OR mail = ?",
            params=(
                username,
                username,
            ),
            fetchOne=True,
            log=log,
        )

        if not user:
            return {"error": "Invalid Username."}

        user = user[0]
        verified = verify_password(password, user.get("pass", None)) if user else False

        if not verified:
            return {"error": "Incorrect Password."}
        user_permissions = get_user_permissions(user.get("uid"))

        jwt_token = generate_jwt_token(
            username,
            user["uid"],
            jwt_auth=jwt_auth,
            access_token_expire_minutes=access_token_expire_minutes,
        )

        try:
            cookies = None

            # url = "https://next.nextwave.world/user/login"
            # form_data = {
            #     "name": username,
            #     "pass": password,
            #     "form_build_id": "form-vlmZ1vE4GCDPJrfbcBLkmyB2eTSclNPR9JbGkIwe4LA",
            #     "form_id": "user_login_form",
            #     "antibot_key": "iN_uofjhz9Xv-qMuzuoc-MHPw0DVwSiCZTTkxvBRcww",
            #     "op": "Log in",
            # }

            # response = requests.post(url, data=form_data)
            # # if response.status_code != 200:
            # #     raise HTTPException(
            # #         status_code=response.status_code, detail="Error during login request"
            # #     )

            # cookies = response.cookies
            # print("cookies: ", cookies)
        except Exception as e:
            if log:
                log.error(f"Failed to create Drupal session, Error: {e}")

        if log:
            log.info(f"User {user['uid']}:{username} logged in successfully")
        return {
            "message": "Login Successfull.",
            "user": user,
            "token": jwt_token,
            "user_permissions": serialize_decimals(serialize_dates(user_permissions)),
            "drupal_cookies": cookies if cookies else None,
        }

    except Exception as e:
        if log:
            log.error(f"User {user['uid']}:{username} failed to Login\nError:{e}")
        raise HTTPException(status_code=500, detail=f"Error in login {e}")


@app.get("/dashboard")
async def dashboard(
    state: str = None,
    city: str = None,
    operator: str = None,
    device_name: str = None,
    user_object: User = Depends(get_current_user_dependency),
):
    try:
        print("user object is: ", user_object)

        user_object = user_object.dict()
        user_roles_object = user_object.get("user_roles")
        user_permission_object = user_object.get("permissions")

        # if not user_permission_object:
        #     raise HTTPException(
        #         status_code=403, detail="User does not have any permissions."
        #     )

        user_for_states = None
        user_for_operators = None
        user_for_cities = None
        user_for_devices = None
        check_permissions = True

        if user_roles_object:
            for role in user_roles_object:
                if (
                    isinstance(role, dict)
                    and role.get("roles_target_id", "") == "administrator"
                ):
                    check_permissions = False
                    break

        if check_permissions:
            for permissions in user_permission_object:
                uid = user_object.get("uid")

                if permissions.get("up_access_type") == "tbl_state":
                    user_for_states = uid
                if permissions.get("up_access_type") == "tbl_operator":
                    user_for_operators = uid
                if permissions.get("up_access_type") == "tbl_city":
                    user_for_cities = load_cities(uid)
                if permissions.get("up_access_type") == "tbl_device":
                    user_for_devices = uid

        states = load_states(user_id=user_for_states)

        operators = load_operators(user_id=user_for_operators)
        devices_list = load_devices(user_id=user_for_devices)
        customer_info = fetch_customer_info()
        print(
            "customer info: ", len(customer_info), type(customer_info), customer_info[0]
        )

        device_customer_link = {}
        if customer_info:
            for customer in customer_info:
                if customer["dc_device_id"] not in device_customer_link:
                    device_id = (
                        customer.get("dc_device_id")
                        if isinstance(customer, dict)
                        else None
                    )
                    if device_id:
                        device_customer_link[device_id] = customer

        if state or city or operator or device_name:
            if operator:
                operators = [op for op in operators if str(op.get("to_id")) == operator]
            elif state or city:
                operators = [
                    op
                    for op in operators
                    if (state is None or str(op.get("to_state_id")) == state)
                    and (city is None or str(op.get("to_city_id")) == city)
                ]

        grouped_devices = {}
        total_devices = 0

        for operator in operators:
            state_id = operator.get("to_state_id")
            if state_id is None:
                continue
            if devices_list:
                for device in devices_list:
                    if device.get("td_operator_id") == operator.get("to_id") and (
                        not device_name
                        or device_name.lower() in device.get("td_name", "").lower()
                    ):

                        if not isinstance(states, list) or state_id not in [
                            user_state.get("ts_id")
                            for user_state in states
                            if isinstance(user_state, dict)
                        ]:
                            continue
                        device_status = get_device_data(
                            device_mac_id=device.get("td_mac_id", ""), database_id=3
                        )

                        if device_status:
                            if device:
                                device["td_is_online"] = 1
                                device["td_last_heartbeat"] = device_status
                                
                        if state_id not in grouped_devices:
                            grouped_devices[state_id] = []

                        if device_customer_link:
                            device_id = device.get("td_id")
                            if device_id:
                                device.update(device_customer_link.get(device_id)) if device_customer_link.get(device_id) else None
                            
                        device.update(operator)
                        grouped_devices[state_id].append(device)
                        total_devices += 1

        for state_id, devices in grouped_devices.items():
            grouped_devices[state_id][0]["device_count"] = len(devices)

        return {
            "states": states,
            "cities": load_cities()[0] if state else [],
            "operators": operators if state or city else [],
            "devices": grouped_devices,
            "total_devices": total_devices,
        }
    except Exception as e:
        if log:
            log.error(f"Exception in dashboard: {e}")
        raise ValueError(f"Exception in dashboard: {e}")


@app.get("/get-states")
async def get_states(user_id: int = None):
    try:
        states = load_states()

        if states:
            return JSONResponse(content={"states": states})
        else:
            return JSONResponse(content={"states": [], "message": "No states found"})
    except Exception as e:
        if log:
            log.error(f"Exception in get_states: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)

# changes by vinit.g
@app.get("/get-districts/{state_id}")
async def get_districts(user_id: int = None, state_id: int = None):
    try:
        districts = load_district(user_id=user_id, state_id=state_id)

        if districts:
            return JSONResponse(content={"districts": districts})
        else:
            return JSONResponse(content={"districts": [], "message": "No districts found"})
    except Exception as e:
        if log:
            log.error(f"Exception in get_districts: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/get-cities/{state_id}")
async def get_cities(state_id: int):
    try:
        if state_id:
            tbl_districts = load_district()
            tbl_cities = load_cities()
            district_ids = [
                d["td_id"] for d in tbl_districts if d["td_state_id"] == state_id
            ]

            cities = [
                city for city in tbl_cities if city["tc_district_id"] in district_ids
            ]

            return JSONResponse(content={"cities": cities})
        else:
            return JSONResponse(
                content={"cities": [], "message": "Please select state."}
            )
    except Exception as e:
        if log:
            log.error(f"Exception in get_cities: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/get-operators/{state_id}/{city_id}")
async def get_operators(state_id: int, city_id: int):
    try:
        if state_id and city_id:
            all_operators = load_operators()
            filtered_operators = [
                op
                for op in all_operators
                if op["to_state_id"] == state_id and op["to_city_id"] == city_id
            ]
            return JSONResponse(content={"operators": filtered_operators})
        else:
            return JSONResponse(
                content={"operators": [], "message": "Please select state and city."}
            )
    except Exception as e:
        if log:
            log.error(f"Exception in get_operators: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/get-devices/{operator_id}")
async def get_devices(operator_id: int):
    try:
        if operator_id:
            all_devices = load_devices()
            filtered_devices = [
                device
                for device in all_devices
                if device["td_operator_id"] == operator_id
            ]
            return JSONResponse(content={"devices": filtered_devices})
        else:
            return JSONResponse(
                content={"devices": [], "message": "Please select operator."}
            )
    except Exception as e:
        if log:
            log.error(f"Exception in get_devices: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/get-batches")
async def get_batches(
    state: int, city: int, operator: int, date: Optional[str] = None, device_id=None
):
    try:
        batches = fetch_batches_data(
            state=state, city=city, operator=operator, date=date, device_id=device_id
        )
        return batches
    except Exception as e:
        if log:
            log.error(f"Exception in get_batches: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/image-scheduling/{state}/{city}/{operator}")
async def image_scheduling(
    state: int,
    city: int,
    operator: int,
    batch_date: str,
    device: int = None,
    batch: int = None,
    user_object: User = Depends(get_current_user_dependency),
):
    try:
        user = user_object.dict()
        user_roles = user.get("user_roles", [])
        user_permissions = user.get("permissions", [])

        if not check_image_permissions(user_roles, user_permissions, state, city, operator, device):
            if log:
                log.error(
                    f"Access denied: user: {user.get('uid','')}-{user.get('name', '')} has no permission for the given state, city, or operator."
                )
            raise HTTPException(403, "Insufficient permissions")

        channels = [
            channel
            for channel in load_channels()
            if str(channel.get("ch_is_deleted", "")) == "0"
        ]

        # Fetch Device Image Data
        try:
            device_image_data = fetch_device_channel_images_data(
                state=state,
                city=city,
                operator=operator,
                batch_date=batch_date,
                batch=batch,
            )
        except ValueError as ve:
            if log:
                log.error(f"Error fetching scheduling data: {str(ve)}")
            raise HTTPException(status_code=400, detail=str(ve))

        user_id = user.get("uid")

        # Fetch Metadata from Redis
        try:
            state_name = redis_client.json().get(
                f"all_states", f"$[?(@.ts_id=={state})].ts_name"
            )
            city_name = redis_client.json().get(
                f"all_cities", f"$[?(@.tc_id=={city})].tc_name"
            )
            operator_name = redis_client.json().get(
                f"all_operators", f"$[?(@.to_id=={operator})].to_org_name"
            )

            if device_image_data:
                device_image_data["state_name"] = state_name[0] if state_name else ""
                device_image_data["city_name"] = city_name[0] if city_name else ""
                device_image_data["operator_name"] = (
                    operator_name[0] if operator_name else ""
                )
        except Exception as e:
            if log:
                log.error(f"Error fetching metadata from Redis: {str(e)}")
            print(f"Error fetching metadata from Redis: {str(e)}")

        return JSONResponse(
            status_code=200,
            content={
                "device_images": json_serializer(device_image_data),
                "channels": json_serializer(channels),
                "states": load_states(user_id),
            },
        )

    except HTTPException as he:
        if log:
            log.error(f"Error fetching device image data: {str(he)}")
        raise he
    except Exception as e:
        if log:
            log.error(f"Error fetching device image data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")



@app.get("/device-image-data/{state}/{city}/{operator}")
async def device_image_data(
    state: int,
    city: int,
    operator: int,
    batch_date: str,
    device: int,
    user_object: User = Depends(get_current_user_dependency),
):
    try:
        user = user_object.dict()
        user_roles = user.get("user_roles", [])
        user_permissions = user.get("permissions", [])

        if not check_image_permissions(user_roles, user_permissions, state, city, operator, device):
            if log:
                log.error(
                    f"Access denied: user: {user.get('uid','')}-{user.get('name', '')} has no permission for the given state, city, or operator."
                )
            raise HTTPException(403, "Insufficient permissions")

        # Fetch Device Image Data
        try:
            device_image_data = fetch_device_channel_images_data(
                state=state,
                city=city,
                operator=operator,
                device=device,
                batch_date=batch_date,
                batch=None,
                fetch_multi_batches=1,
            )
            
        except ValueError as ve:
            if log:
                log.error(f"Error fetching scheduling data: {str(ve)}")
            raise HTTPException(status_code=400, detail=str(ve))

        return JSONResponse(
            status_code=200,
            content={
                "device_images": json_serializer(device_image_data),
            },
        )

    except HTTPException as he:
        if log:
            log.error(f"Error in device_image_data: {str(he)}")
        raise he
    except Exception as e:
        if log:
            log.error(f"Error in device_image_data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")


@app.post("/image-scheduling/submit")
async def update_last_sequence_data_api(
    state,
    city,
    operator,
    batch,
    updated_images: list[dict] = Body(...),
    user_object: User = Depends(get_current_user_dependency),

):
    try:
        user = user_object.dict()
        print("user roles: ", user)
        
        if not updated_images:
            if log:
                log.error(f"Error in `update_last_sequence_data_api`: updated_images are empty")
            raise HTTPException(
                status_code=400, detail="updated_images cannot be empty"
            )

        message_data = {
            "state": state,
            "city": city,
            "operator": operator, 
            "batch": batch,
            "updated_images": updated_images,
            "user": user,
        }

        send_message_to_nsq(topic="submit-image-scheduling", message_data=message_data)

        return {"message": "Submitted successfully!"}

    except HTTPException as http_exc:
        if log:
            log.error(f"Error in `update_last_sequence_data_api`: {str(http_exc)}")
        raise http_exc
    except Exception as e:
        if log:
            log.error(f"Error in `update_last_sequence_data_api`: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/set-device-status")
async def set_device_status(channel_name: str, message: dict):
    try:
        print("message: ", message)
        publish_to_websocket(channel_name, message)
    except Exception as e:
        if log:
            log.error(f"Error in `set_device_status`: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error occurred while setting device status: {str(e)}",
        )


@app.get("/image-scheduled/{state}/{city}/{operator}")
async def get_scheduled_images_report(
    state: int,
    city: int,
    operator: int,
    start_date: str,
    end_date: str,
    device: int = None,
    user_object: User = Depends(get_current_user_dependency),
):
    try:
        user = user_object.dict()
        user_roles = user.get("user_roles", [])
        user_permissions = user.get("permissions", [])

        if not check_image_permissions(user_roles, user_permissions, state, city, operator, device):
            if log:
                log.error(
                    f"Access denied: user: {user.get('uid','')}-{user.get('name', '')} has no permission for the given state, city, or operator."
                )
            raise HTTPException(403, "Insufficient permissions")

        try:
            device_image_data = fetch_device_channel_images_data_in_batches(
                state=state,
                city=city,
                operator=operator,
                start_date=start_date,
                end_date=end_date,
                device=device,
            )
            
            channels = [
                channel
                for channel in load_channels()
                if str(channel.get("ch_is_deleted", "")) == "0"
            ]
            
            if device_image_data and isinstance(device_image_data,dict):
                device_image_data["channels"] = json_serializer(channels)
                
        except ValueError as ve:
            if log:
                log.error(f"Error fetching scheduling data: {str(ve)}")
            raise HTTPException(status_code=400, detail=str(ve))

        return json_serializer(device_image_data)
 
    except HTTPException as he:
        if log:
            log.error(f"Error in get_scheduled_images_report: {str(he)}")
        raise he
    except Exception as e:
        if log:
            log.error(f"Error in get_scheduled_images_report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")


@app.delete("/batch/delete")
async def delete_batches(
    request: Request,
    user_object: User = Depends(get_current_user_dependency),
):
    try:
        data = await request.json() 
        state = data.get("state")
        city = data.get("city")
        operator = data.get("operator")
        device_id = data.get("device_id")
        batches = data.get("batches")
        batch_date = data.get("batch_date")

        if not all([state, city, operator, device_id, batches, batch_date]):
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        modified_count = delete_batch(
            state=state, 
            city=city, 
            operator=operator, 
            device=device_id, 
            batches=batches,
            batch_date=batch_date,
        )

        return {"success": f"Successfully deleted {modified_count} batches."}
        
    except HTTPException as http_exc:
        if log:
            log.error(f"Error in `delete_batches`: {str(http_exc)}")
        raise http_exc
    except Exception as e:
        if log:
            log.error(f"Error in `delete_batches`: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")



@app.get("/get-rf-batches")
async def get_rf_batches(
    state: int, city: int, operator: int, date: Optional[str] = None, device_id:int = None
):
    try:
        batches = fetch_rf_batches_data(
            state=state, city=city, operator=operator, date=date, device=device_id
        )
        
        return batches
    except Exception as e:
        if log:
            log.error(f"Exception in get_rf_batches: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/rf-report")
async def get_rf_report(
    unique_key = str,
    user_object: User = Depends(get_current_user_dependency),
):
    try:
        user = user_object.dict()
        user_roles = user.get("user_roles", [])
        user_permissions = user.get("permissions", [])


        try:
            rf_data = fetch_rf_data(
                unique_key=unique_key,
            )
            
            if rf_data and isinstance(rf_data, dict):
                return json_serializer(rf_data)
             
        except ValueError as ve:
            if log:
                log.error(f"Error fetching rf report: {str(ve)}")
            raise HTTPException(status_code=400, detail=str(ve))

    except HTTPException as he:
        if log:
            log.error(f"Error in get_rf_report: {str(he)}")
        raise he
    except Exception as e:
        if log:
            log.error(f"Error in get_rf_report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")
    
@app.get("/test-health")
async def testhealth(): 
    try:
        result = test_func()
        return result
    except Exception as e:  
        if log:
            log.error(f"Exception in test api: {e}")
        return JSONResponse(content={"error23": str(e)}, status_code=500)

# changes by prerna
@app.get("/masters/{entity_type}")
async def get_entities(
    entity_type: str,
    state_id: Optional[str] = None,
    district_id: Optional[str] = None,
    city_id: Optional[str] = None,
    operator_id: Optional[str] = None,
    name: Optional[str] = None
):
    try:
        valid_entities = ["states", "districts", "cities", "operators", "devices"]
        if entity_type not in valid_entities:
            raise ValueError("Invalid entity type")

        entities = fetch_entities(
            collection_name=entity_type,
            state_id=state_id,
            district_id=district_id,
            city_id=city_id,
            operator_id=operator_id,
            name=name
        )
        return entities
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/{entity_type}/{entity_id}")
async def get_entity(entity_type: str, entity_id: str):
    try:
        entity = fetch_entity_by_id(entity_type, entity_id)
        if not entity:
            return JSONResponse(content={"error": "Not found"}, status_code=404)
        return entity
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/{entity_type}")
async def create_entity(entity_type: str, entity_data: dict):
    try:
        required_fields = {
            "states": ["ts_name"],
            "districts": ["name", "stateId"],
            "cities": ["name", "stateId", "districtId"],
            "operators": ["name", "cityId", "districtId", "stateId"],
            "devices": ["name", "operatorId", "cityId", "districtId", "stateId"]
        }

        # Validate required fields
        missing = [field for field in required_fields[entity_type] if field not in entity_data]
        if missing:
            raise ValueError(f"Missing required fields: {missing}")

        created_id = create_entity_helper(entity_type, entity_data)
        return {"id": created_id}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)


@app.put("/{entity_type}/{entity_id}")
async def update_entity(entity_type: str, entity_id: str, update_data: dict):
    try:
        updated_count = update_entity_helper(entity_type, entity_id, update_data)
        if updated_count == 0:
            return JSONResponse(content={"error": "Not found"}, status_code=404)
        return {"updated": True}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)


@app.delete("/{entity_type}/{entity_id}")
async def delete_entity(entity_type: str, entity_id: str):
    try:
        deleted_count = delete_entity_helper(entity_type, entity_id)
        if deleted_count == 0:
            return JSONResponse(content={"error": "Not found"}, status_code=404)
        return {"deleted": True}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

