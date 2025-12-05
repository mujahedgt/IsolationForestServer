import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    # MySQL Configuration
    MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_PORT = int(os.getenv("MYSQL_PORT", 3306))
    MYSQL_USER = os.getenv("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
    MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "isolation_forest_db")

    # FastAPI Configuration
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", 8000))
    API_RELOAD = os.getenv("API_RELOAD", "True").lower() == "true"

    # Model Configuration
    DEFAULT_CONTAMINATION = float(os.getenv("DEFAULT_CONTAMINATION", 0.1))
    DEFAULT_N_ESTIMATORS = int(os.getenv("DEFAULT_N_ESTIMATORS", 100))
    MIN_TRAINING_SAMPLES = int(os.getenv("MIN_TRAINING_SAMPLES", 100))

    @property
    def DATABASE_URL(self):
        return f"mysql+mysqlconnector://{self.MYSQL_USER}:{self.MYSQL_PASSWORD}@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DATABASE}"


settings = Settings()