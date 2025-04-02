import json
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from cryptography.fernet import Fernet
from core.utils.env import EnvConfig
from core.utils.state import global_state
from core.utils.logger import logger


# Load the encryption key from the environment variable
CYPHER = EnvConfig.get("CYPHER").encode()  # Ensure it's in bytes
fernet = Fernet(CYPHER)


class GoogleAuthMiddleware(BaseHTTPMiddleware):

    def __init__(self, app, auth_callback, *args, **kwargs):
        super().__init__(app)
        self.db_handler = global_state.get("db_handler")
        self.auth_callback = auth_callback

    async def dispatch(self, request: Request, call_next):
        """Authenticate with Google Drive and Docs before processing the request."""
        logger.info("MCP Route middlare GoogleAuthMiddleware checking credentials")
        try:
            global_state.set("is_authenticated", False, True)
            access_token = request.headers.get("x-access-token", None)

            if not access_token:
                global_state.set(
                    "error_message",
                    f"X-ACCESS-TOKEN is a required header parameter. Please go to {EnvConfig.get('APP_HOST')}/auth/login to get the required paramaters.",
                    True,
                )
                return await call_next(request)

            try:
                cred = self.db_handler.get_credentials(access_token)
            except Exception as e:
                global_state.set(
                    "error_message",
                    f"There has been an error with authenticating, please go to {EnvConfig.get('APP_HOST')}/auth/login and authenticate again",
                    True,
                )
                return await call_next(request)

            if "error" in cred:
                global_state.set(
                    "error_message",
                    f"There has been an error with authenticating, please go to {EnvConfig.get('APP_HOST')}/auth/login and authenticate again",
                    True,
                )
                logger.warning("No credentials found. Redirecting to login.")
                return await call_next(request)  # Proceed without authentication

            # Extract credentials
            credentials = cred["credentials"]
            try:
                creds = Credentials.from_authorized_user_info(credentials)
            except Exception as e:
                logger.error(f"Error initializing credentials: {str(e)}")
                return await call_next(request)

            # Validate credentials
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    logger.info("Refreshing expired credentials.")
                    try:
                        creds = Credentials(
                            None,
                            refresh_token=creds.refresh_token,
                            client_id=creds.client_id,
                            client_secret=creds.client_secret,
                            token_uri="https://oauth2.googleapis.com/token",
                        )
                        creds.refresh(GoogleRequest())
                        id_info = id_token.verify_oauth2_token(
                            creds.id_token,
                            google_requests.Request(),
                            creds.client_id,
                        )
                        user_id = id_info["sub"]
                        logger.info(
                            f"New access token for user {user_id}: {creds.token}"
                        )

                        self.db_handler.update_access_token(user_id, creds.token)

                    except Exception as e:
                        logger.error(
                            f"Error refreshing credentials: {str(e)}", exc_info=True
                        )
                        global_state.set(
                            "error_message",
                            f"There has been an error with authenticating, please go to {EnvConfig.get('APP_HOST')}/auth/login and authenticate again",
                            True,
                        )
                        return await call_next(request)

                else:
                    logger.warning("Invalid credentials.")
                    # self.db_handler.delete_credentials(encrypted_user_id)
                    global_state.set(
                        "error_message",
                        f"There has been an error with authenticating, please deauthenticate the app and go to {EnvConfig.get('APP_HOST')}/auth/login",
                        True,
                    )
                    return await call_next(request)  # Proceed without authentication

            # Attach services to request state
            self.auth_callback()(creds)

            global_state.set("is_authenticated", True, True)
            response = await call_next(request)
            return response

        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            global_state.set(
                "error_message",
                f"There has been an error with authenticating, please go to {EnvConfig.get('APP_HOST')}/auth/login to authenticate",
                True,
            )
            return await call_next(request)  # Proceed without authentication

    @classmethod
    def check_access(returnJsonOnError=False):

        if not global_state.get("is_authenticated"):
            logger.error("User is not authenticated.")

            if returnJsonOnError:
                return json.dumps(
                    {
                        "status": "error",
                        "error": global_state.get(
                            "error_message", "User is not authenticated."
                        ),
                    }
                )

            return "User is not authenticated."

        return None  # Return None if authenticated
