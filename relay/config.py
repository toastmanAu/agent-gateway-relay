import os


class Settings:
    bind_host = os.environ.get("RELAY_HOST", "127.0.0.1")   # set to the tailnet addr in the unit
    bind_port = int(os.environ.get("RELAY_PORT", "9991"))
    db_path = os.environ.get("RELAY_DB", os.path.expanduser("~/agent-gateway-relay/relay.sqlite"))
    fcm_creds = os.environ.get("RELAY_FCM_CREDS", "")        # path to firebase admin json; empty = FCM disabled


settings = Settings()
