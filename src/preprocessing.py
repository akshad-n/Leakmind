"""
LeakMind Phase 1: CERT Data Preprocessing Module
Provides reusable data cleaning, validation, and normalization functions for raw CERT logs:
- logon.csv
- device.csv
- http.csv
- LDAP monthly employee directory
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import pandas as pd
import numpy as np

from .utils.logger import get_logger

logger = get_logger("leakmind.preprocessing")


def normalize_user_id(user_val: Union[str, float]) -> str:
    """
    Standardizes user identifier by removing domain prefix ('DTAA/')
    and stripping whitespace to uppercase.
    Example: 'DTAA/BMS0001' -> 'BMS0001'
    """
    if pd.isna(user_val):
        return "UNKNOWN"
    s = str(user_val).strip()
    if "/" in s:
        s = s.split("/")[-1]
    return s.upper()


def extract_temporal_metadata(
    df: pd.DataFrame,
    date_col: str = "date"
) -> pd.DataFrame:
    """
    Parses timestamp string to datetime and extracts:
    - dt (datetime)
    - day (date object)
    - hour (0-23)
    - day_of_week (0=Mon, 6=Sun)
    - is_weekend (bool)
    - is_after_hours (bool: hour < 7 or hour >= 19, or weekend)
    """
    df = df.copy()
    if date_col not in df.columns:
        raise ValueError(f"Date column '{date_col}' not found in dataframe columns: {df.columns.tolist()}")

    df["dt"] = pd.to_datetime(df[date_col], format="%m/%d/%Y %H:%M:%S", errors="coerce")
    
    # Handle any unparsed dates
    if df["dt"].isna().any():
        logger.warning(f"Found {df['dt'].isna().sum()} unparsed datetime rows in '{date_col}'. Dropping invalid rows.")
        df = df.dropna(subset=["dt"])

    df["day"] = df["dt"].dt.date
    df["hour"] = df["dt"].dt.hour
    df["day_of_week"] = df["dt"].dt.dayofweek
    df["is_weekend"] = df["day_of_week"] >= 5
    df["is_after_hours"] = (df["hour"] < 7) | (df["hour"] >= 19) | df["is_weekend"]
    return df


def load_and_clean_logon(
    filepath: Union[str, Path],
    nrows: Optional[int] = None
) -> pd.DataFrame:
    """
    Loads and standardizes CERT logon.csv:
    Raw Schema: [id, date, user, pc, activity]
    Activity values: 'Logon', 'Logoff'
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Logon file not found: {path}")

    logger.info(f"Loading logon events from {path} (nrows={nrows})...")
    df = pd.read_csv(path, nrows=nrows)
    
    # Validate expected schema
    expected_cols = ["id", "date", "user", "pc", "activity"]
    missing = [c for c in expected_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Logon schema mismatch: missing columns {missing}")

    df["user_clean"] = df["user"].apply(normalize_user_id)
    df = extract_temporal_metadata(df, date_col="date")
    
    # Clean activities
    df["is_logon"] = (df["activity"].str.strip().str.lower() == "logon").astype(int)
    df["is_logoff"] = (df["activity"].str.strip().str.lower() == "logoff").astype(int)

    logger.info(f"Loaded {len(df)} cleaned logon records across {df['user_clean'].nunique()} users.")
    return df


def load_and_clean_device(
    filepath: Union[str, Path],
    nrows: Optional[int] = None
) -> pd.DataFrame:
    """
    Loads and standardizes CERT device.csv (USB storage):
    Raw Schema: [id, date, user, pc, activity]
    Activity values: 'Connect', 'Disconnect'
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Device file not found: {path}")

    logger.info(f"Loading device/USB events from {path} (nrows={nrows})...")
    df = pd.read_csv(path, nrows=nrows)

    expected_cols = ["id", "date", "user", "pc", "activity"]
    missing = [c for c in expected_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Device schema mismatch: missing columns {missing}")

    df["user_clean"] = df["user"].apply(normalize_user_id)
    df = extract_temporal_metadata(df, date_col="date")

    df["is_connect"] = (df["activity"].str.strip().str.lower() == "connect").astype(int)
    df["is_disconnect"] = (df["activity"].str.strip().str.lower() == "disconnect").astype(int)

    logger.info(f"Loaded {len(df)} cleaned device/USB records across {df['user_clean'].nunique()} users.")
    return df


def load_and_clean_http(
    filepath: Union[str, Path],
    chunksize: int = 100000,
    max_chunks: Optional[int] = None
) -> pd.DataFrame:
    """
    Loads CERT http.csv in chunks to prevent memory exhaustion (raw file is ~290MB, 3.4M rows).
    Raw file has no header: [id, date, user, pc, url]
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"HTTP file not found: {path}")

    logger.info(f"Loading HTTP web telemetry in chunks of {chunksize} from {path}...")
    chunks = []
    chunk_count = 0

    col_names = ["id", "date", "user", "pc", "url"]

    for chunk in pd.read_csv(path, header=None, names=col_names, chunksize=chunksize):
        chunk["user_clean"] = chunk["user"].apply(normalize_user_id)
        chunk["dt"] = pd.to_datetime(chunk["date"], format="%m/%d/%Y %H:%M:%S", errors="coerce")
        chunk = chunk.dropna(subset=["dt"])

        chunk["day"] = chunk["dt"].dt.date
        chunk["hour"] = chunk["dt"].dt.hour
        chunk["day_of_week"] = chunk["dt"].dt.dayofweek
        chunk["is_weekend"] = chunk["day_of_week"] >= 5
        chunk["is_after_hours"] = (chunk["hour"] < 7) | (chunk["hour"] >= 19) | chunk["is_weekend"]

        # Aggregate chunk to (user_clean, day) level immediately to keep memory usage minimal
        # Check for external/high-risk destination indicators
        url_lower = chunk["url"].astype(str).str.lower()
        chunk["is_external_highrisk"] = url_lower.str.contains(
            r"(wikileaks|dropbox|mega\.nz|mediafire|job|monster\.com|careerbuilder)",
            regex=True
        ).astype(int)

        agg_chunk = chunk.groupby(["user_clean", "day"]).agg(
            http_activity_count=("url", "count"),
            after_hours_http=("is_after_hours", "sum"),
            external_destination_count=("is_external_highrisk", "sum")
        ).reset_index()

        chunks.append(agg_chunk)
        chunk_count += 1
        if max_chunks and chunk_count >= max_chunks:
            logger.info(f"Reached chunk limit ({max_chunks}). Stopping HTTP chunk ingestion.")
            break

    df_http_agg = pd.concat(chunks, ignore_index=True)
    # Re-aggregate chunks that share the same user and day
    df_http_daily = df_http_agg.groupby(["user_clean", "day"]).agg(
        http_activity_count=("http_activity_count", "sum"),
        after_hours_http=("after_hours_http", "sum"),
        external_destination_count=("external_destination_count", "sum")
    ).reset_index()

    logger.info(f"Aggregated HTTP data into {len(df_http_daily)} user-day records.")
    return df_http_daily


def load_and_clean_ldap(
    ldap_dir: Union[str, Path]
) -> pd.DataFrame:
    """
    Loads LDAP monthly snapshots (e.g. data/raw/r1/r1/LDAP/*.csv)
    Schema: [employee_name, user_id, Domain, Email, Role]
    Maps privileged accounts (IT Admin, Security, Director, VP, Senior Manager).
    """
    ldap_path = Path(ldap_dir)
    if not ldap_path.exists():
        logger.warning(f"LDAP directory not found at {ldap_path}. Returning empty LDAP dataframe.")
        return pd.DataFrame(columns=["user_clean", "role", "is_privileged_account"])

    ldap_files = list(ldap_path.glob("*.csv"))
    if not ldap_files:
        logger.warning(f"No LDAP CSV files found in {ldap_path}.")
        return pd.DataFrame(columns=["user_clean", "role", "is_privileged_account"])

    # Load latest snapshot
    latest_file = sorted(ldap_files)[-1]
    logger.info(f"Loading employee directory from latest LDAP snapshot: {latest_file.name}")
    df_ldap = pd.read_csv(latest_file)

    df_ldap["user_clean"] = df_ldap["user_id"].apply(normalize_user_id)
    
    privileged_roles = {"it admin", "security", "director", "vp", "senior manger", "senior manager"}
    role_series = df_ldap["Role"].astype(str).str.strip().str.lower()
    df_ldap["is_privileged_account"] = role_series.apply(lambda r: 1 if r in privileged_roles else 0)
    df_ldap["role"] = df_ldap["Role"]

    return df_ldap[["user_clean", "role", "is_privileged_account"]].drop_duplicates(subset=["user_clean"])
