from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"


class Settings(BaseSettings):
    # ------------------------------------------------------------------
    # Gemini / LLM
    # ------------------------------------------------------------------
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.6-flash"
    llm_provider: str = "gemini"
    llm_timeout_seconds: float = 5.0

    # ------------------------------------------------------------------
    # VirusTotal
    # ------------------------------------------------------------------
    virustotal_api_key: str | None = None
    virustotal_timeout_seconds: float = 3.0

    # ------------------------------------------------------------------
    # GeoIP / TOR
    # ------------------------------------------------------------------
    geolite_city_db: str = str(
        DATA_DIR / "GeoLite2-City.mmdb"
    )

    geolite_asn_db: str = str(
        DATA_DIR / "GeoLite2-ASN.mmdb"
    )

    tor_exit_nodes_file: str = str(
        DATA_DIR / "tor_exit_nodes.txt"
    )

    # ------------------------------------------------------------------
    # External intelligence
    # ------------------------------------------------------------------
    bgp_api_url: str = (
        "https://api.hackertarget.com/aslookup/?q="
    )

    # ------------------------------------------------------------------
    # Neo4j
    # ------------------------------------------------------------------
    neo4j_uri: str | None = None
    neo4j_user: str | None = None
    neo4j_password: str | None = None

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    cors_origins: str = "*"
    max_upload_bytes: int = 15_728_640
    enable_external_enrichment: bool = True

    # ------------------------------------------------------------------
    # Local NLP
    # ------------------------------------------------------------------
    trinetra_nlp_model: str | None = None
    trinetra_nlp_local_only: bool = True

    # ------------------------------------------------------------------
    # SQLite
    # ------------------------------------------------------------------
    trinetra_sqlite_path: str = (
        "data/trinetra_runtime.db"
    )

    # ------------------------------------------------------------------
    # Optional API security
    # ------------------------------------------------------------------
    analyst_api_key: str | None = None
    investigator_api_key: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()