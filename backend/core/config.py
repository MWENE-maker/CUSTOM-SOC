import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = BASE_DIR / ".env"

load_dotenv(ENV_FILE)


class Settings:
    APP_NAME = os.getenv("APP_NAME", "CUSTOM-SOC")
    APP_ENV = os.getenv("APP_ENV", "development")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    DATABASE_PATH = os.getenv(
        "DATABASE_PATH",
        "database/soc_database.db",
    )


settings = Settings()