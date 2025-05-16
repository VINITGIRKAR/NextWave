import sys
from flexOps import foLoader
import os
import json
from common_functions import(
    submit_device_channel_images_data,
)

config_path = os.getenv(
    "NEXTWAVE_CONFIG_PATH", "/home/neuralit/Workspace/Nextwave/Nextwave/config.ini"
)

components = foLoader.load_application(
    config_path,
    consumer_needed=True,
    jwt_authentication_needed=True,
    datalake_needed=True,
)
consumer = components["consumer"]
cache = components["cache"]
log = components["log"]


def submit_image_scheduling(message):
    try:
        if isinstance(message, bytes):
                message = message.decode("utf-8")
        if isinstance(message, str):
            message = json.loads(message)
            
        state = message.get("state")
        city = message.get("city")
        operator = message.get("operator")
        batch = message.get("batch")
        updated_images = message.get("updated_images")
        user = message.get("user", {})
        
        result = submit_device_channel_images_data(state, city, operator, batch, updated_images, user)
        return True
    except Exception as e:
        if log:
            log.error(f"Error processing submit_image_scheduling message: {e}", exc_info=True)
        return False
    

if __name__ == "__main__":
    if len(sys.argv) != 2:
        log.error("Usage: python3 consumer.py <queue-name>")
        sys.exit(1)

    queue_name = sys.argv[1]

    if queue_name == "submit-image-scheduling":
        consumer.register_handler(queue_name, submit_image_scheduling)
        consumer.consume(queue_name)
    else:
        if log:
            log.error(f"Unknown queue name: {queue_name}")
        sys.exit(1)
