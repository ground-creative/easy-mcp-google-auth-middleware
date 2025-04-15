# Google Auth Middleware For Easy MCP Server

This is a google authentication service middleware for easy mcp python.<br>
The middleware uses sqlite to storage encrypted credentials data.

## Installation

1. Donwload middlewares from the root folder of the easy mcp installation:

```
mkdir app/middleware/google
wget -P app/middleware/google https://raw.githubusercontent.com/ground-creative/easy-mcp-google-auth-middleware/refs/heads/main/GoogleAuthMiddleware.py
wget -P app/middleware/google https://raw.githubusercontent.com/ground-creative/easy-mcp-google-auth-middleware/refs/heads/main/database.py
```

2. Create create a utility to attach credentials to global variables:

```
# app/utils/credentials.py

from core.utils.state import global_state
from googleapiclient.discovery import build

def attach_google_services(credentials):
    """Attach Google API services to the global state."""
    drive_service = build("drive", "v3", credentials=credentials)
    docs_service = build("docs", "v1", credentials=credentials)
    sheets_service = build("sheets", "v4", credentials=credentials)

    global_state.set(
        "google_drive_service", drive_service, True
    )  # Save Drive service to global state
    global_state.set(
        "google_docs_service", docs_service, True
    )  # Save Docs service to global state
    global_state.set(
        "google_sheets_service", sheets_service, True
    )  # Save Sheets service to global state
```

3. Create file app/config/app.py if it does not exists and add the middleware:

```
MIDDLEWARE = {
    "mcp": [
        {
            "middleware": "app.middleware.google.GoogleAuthMiddleware",
            "priority": 1,
            "args": {
                "auth_callback": lambda: getattr(
                    importlib.import_module(
                        "app.utils.credentials.attach_google_services".rsplit(".", 1)[0]
                    ),
                    "app.utils.credentials.attach_google_services".rsplit(".", 1)[-1],
                )
            },
        }
    ]
}
```

4. Install required dependencies:

```
pip install google-auth-oauthlib cryptography google-api-python-client
```

5. Generate encryption key:

```
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

6. Add env variables to .env file:

```
DB_PATH=storage/sqlite_credentials.db
CYPHER=Your Encryption Key Here
```

## Verifying Authentication

Use the class method `check_access` to check if user is authenticated:

```
# app/tools/add.py

from mcp.server.fastmcp import Context      # Use `ctx: Context` as function param to get mcp context
from core.utils.state import global_state   # Use to add and read global vars
from core.utils.logger import logger        # Use to import the logger instance
from app.middleware.google.GoogleAuthMiddleware import check_access

def add_numbers_tool(a: int, b: int) -> int:
    """Add two numbers"""

    # Check authentication
    auth_response = check_access(True)    # Set to true to return the global error message set by the middleware
    if auth_response:
        return auth_response

    return a + b


```

## Database Usage

Refer to the database file for usage
