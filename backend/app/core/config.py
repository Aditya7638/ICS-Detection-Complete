from pydantic_settings import BaseSettings
from functools import lru_cache
import os

class Settings(BaseSettings):
    DATABASE_URL: str = ""
    JWT_SECRET: str = "insecure-dev-secret-change-me"
    JWT_EXPIRE_MINUTES: int = 480
    MODEL_PATH: str = "ml_models/best_model.joblib"
    FUSION_CONFIG_PATH: str = "config/fusion_config.json"
    SIMULATOR_DATASET: str = "data/ne_data.csv"
    LLM_PROVIDER: str = "groq"
    LLM_API_KEY: str = ""
    LLM_MODEL: str = "openai/gpt-oss-120b"
    CORS_ORIGINS: str = "http://localhost:5173"

    class Config:
        env_file = ".env"
        extra = "ignore"

@lru_cache()
def get_settings() -> Settings:
    return Settings()
