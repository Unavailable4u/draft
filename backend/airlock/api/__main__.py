import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run("airlock.api.app:app", host=os.environ.get("AIRLOCK_HOST", "127.0.0.1"),
                port=int(os.environ.get("AIRLOCK_PORT", "8000")))
