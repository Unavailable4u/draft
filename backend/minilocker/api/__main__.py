import os

import uvicorn

from minilocker.config import load_and_report

if __name__ == "__main__":
    load_and_report()     # before uvicorn imports the app, which reads its settings at import time
    uvicorn.run("minilocker.api.app:app", host=os.environ.get("MINILOCKER_HOST", "127.0.0.1"),
                port=int(os.environ.get("MINILOCKER_PORT", "8000")))
