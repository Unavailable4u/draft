import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run("minilocker.api.app:app", host=os.environ.get("MINILOCKER_HOST", "127.0.0.1"),
                port=int(os.environ.get("MINILOCKER_PORT", "8000")))
