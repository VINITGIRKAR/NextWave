def load_cities(user_id=None, district_id=None, state_id=None):
    try:
        all_cities = []

        if user_id:
            if redis_client.json().get(f"tbl_city_{user_id}", "$"):
                all_cities = redis_client.json().get(redis_key, "$")
        elif district_id:
            if redis_client.json().get(f"tbl_city_district_{district_id}", "$"):
                all_cities = redis_client.json().get(redis_key, "$")
        elif state_id:
            if redis_client.json().get(f"tbl_city_state_{state_id}", "$"):
                all_cities = redis_client.json().get(redis_key, "$")
        else:
            if redis_client.json().get(f"all_cities", "$"):
                all_cities = redis_client.json().get(redis_key, "$")

        if all_cities:
            return all_cities[0]

        if user_id:
            user_city_ids = foCommon.db_execute(
                connection=db_connect,
                querydata="SELECT up_access_ids FROM tbl_user_permission WHERE up_user_id = ? AND up_access_type = ?",
                params=(user_id, "tbl_city"),
                fetchData=True,
                log=log,
            )

            user_city_ids = (
                user_city_ids[0].get("up_access_ids") if user_city_ids else None
            )
            user_city_ids = (
                [int(cid) for cid in user_city_ids.split(",")] if user_city_ids else None
            )

            if user_city_ids:
                placeholder = ",".join(["?"] * len(user_city_ids))
                all_cities = foCommon.db_execute(
                    connection=db_connect,
                    querydata=f"SELECT * FROM tbl_city WHERE tc_is_deleted = ? AND tc_id IN ({placeholder})",
                    params=(0, *user_city_ids),
                    fetchData=True,
                    log=log,
                )
                redis_client.json().set(f"tbl_city_{user_id}", "$", serialize_dates(all_cities))

        elif district_id:
            all_cities = foCommon.db_execute(
                connection=db_connect,
                querydata="SELECT * FROM tbl_city WHERE tc_district_id = ? AND tc_is_deleted = ?",
                params=(district_id, 0),
                fetchData=True,
                log=log,
            )
            redis_client.json().set(f"tbl_city_district_{district_id}", "$", serialize_dates(all_cities))

        elif state_id:
            all_cities = foCommon.db_execute(
                connection=db_connect,
                querydata="""
                    SELECT tc.* FROM tbl_city tc
                    INNER JOIN tbl_district td ON tc.tc_district_id = td.td_id
                    WHERE td.td_state_id = ? AND tc.tc_is_deleted = ? AND td.td_is_deleted = ?
                """,
                params=(state_id, 0, 0),
                fetchData=True,
                log=log,
            )
            redis_client.json().set(f"tbl_city_state_{state_id}", "$", serialize_dates(all_cities))

        else:
            all_cities = foCommon.db_execute(
                connection=db_connect,
                querydata="SELECT * FROM tbl_city WHERE tc_is_deleted = ?",
                params=(0,),
                fetchData=True,
                log=log,
            )
            redis_client.json().set("all_cities", "$", serialize_dates(all_cities))

        return serialize_dates(all_cities)

    except Exception as e:
        raise ValueError(f"Exception in load_cities: {e}")
