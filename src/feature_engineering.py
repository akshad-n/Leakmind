"""
LeakMind Phase 1: Feature Engineering Pipeline
Constructs user/day-level behavioral and contextual features strictly supported by CERT telemetry.
Incorporates data-leakage prevention and chronological train/test splitting.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

from .utils.logger import get_logger
from .preprocessing import (
    load_and_clean_logon,
    load_and_clean_device,
    load_and_clean_http,
    load_and_clean_ldap,
    normalize_user_id
)

logger = get_logger("leakmind.feature_engineering")

# Exact list of features engineered from available raw data
SUPPORTED_FEATURE_COLUMNS = [
    "login_frequency",              # Logon count on that day
    "logoff_count",                # Logoff count on that day
    "after_hours_logon",           # Logons outside 07:00-19:00 or weekends
    "unique_pcs",                  # Distinct workstations accessed
    "new_device",                  # First-time PC usage relative to user history
    "usb_usage",                   # Total device events (connect + disconnect)
    "device_connect_count",        # USB mount count
    "device_disconnect_count",     # USB unmount count
    "after_hours_device",          # USB events outside normal business hours
    "web_activity",                # Total HTTP requests
    "after_hours_activity",        # Sum of all after-hours actions (logon + USB + web)
    "external_destination",        # Visits to cloud upload/file-sharing/wikileaks
    "privileged_account",          # Binary LDAP flag: IT Admin / Security / Director / VP
    "user_historical_activity",    # Expanding mean of user's past daily activity (t-1)
    "activity_spike_ratio"         # Ratio of today's activity to past baseline
]

# Explicit documentation of features not supported in raw CERT r1 schema
UNSUPPORTED_SCHEMA_FEATURES = {
    "files_accessed": "Raw CERT r1 lacks file.csv audit log. Feature omitted.",
    "unique_files": "Raw CERT r1 lacks file.csv audit log. Feature omitted.",
    "copy_activity": "Raw CERT r1 lacks file.csv audit log. Feature omitted.",
    "file_access_frequency": "Raw CERT r1 lacks file.csv audit log. Feature omitted.",
    "email_count": "Raw CERT r1 lacks email.csv log (only LDAP email address exists). Feature omitted."
}


def build_daily_features(
    df_logon: pd.DataFrame,
    df_device: pd.DataFrame,
    df_http_daily: pd.DataFrame,
    df_ldap: pd.DataFrame
) -> pd.DataFrame:
    """
    Aggregates and joins multi-channel telemetry into a unified user-day feature table.
    """
    logger.info("Aggregating daily logon telemetry...")
    daily_logon = df_logon.groupby(["user_clean", "day"]).agg(
        login_frequency=("is_logon", "sum"),
        logoff_count=("is_logoff", "sum"),
        after_hours_logon=("is_after_hours", "sum"),
        unique_pcs=("pc", "nunique"),
        pcs_used=("pc", lambda s: set(s))
    ).reset_index()

    logger.info("Aggregating daily device/USB telemetry...")
    daily_device = df_device.groupby(["user_clean", "day"]).agg(
        usb_usage=("activity", "count"),
        device_connect_count=("is_connect", "sum"),
        device_disconnect_count=("is_disconnect", "sum"),
        after_hours_device=("is_after_hours", "sum")
    ).reset_index()

    logger.info("Merging logon, device, and HTTP daily tables...")
    merged = pd.merge(daily_logon, daily_device, on=["user_clean", "day"], how="outer")
    merged = pd.merge(merged, df_http_daily, on=["user_clean", "day"], how="outer")

    # Fill unobserved counts with 0.0
    count_cols = [
        "login_frequency", "logoff_count", "after_hours_logon", "unique_pcs",
        "usb_usage", "device_connect_count", "device_disconnect_count", "after_hours_device",
        "http_activity_count", "after_hours_http", "external_destination_count"
    ]
    for col in count_cols:
        if col in merged.columns:
            merged[col] = merged[col].fillna(0.0)

    # Standardize column naming
    merged["web_activity"] = merged["http_activity_count"]
    merged["external_destination"] = merged["external_destination_count"]
    
    # Calculate total after-hours activity
    merged["after_hours_activity"] = (
        merged["after_hours_logon"] +
        merged["after_hours_device"] +
        merged["after_hours_http"]
    )

    # Merge LDAP employee directory metadata
    logger.info("Enriching with LDAP privileged account metadata...")
    merged = pd.merge(merged, df_ldap[["user_clean", "is_privileged_account"]], on="user_clean", how="left")
    merged["privileged_account"] = merged["is_privileged_account"].fillna(0).astype(int)

    # Compute total daily activity volume
    merged["total_daily_activity"] = (
        merged["login_frequency"] +
        merged["logoff_count"] +
        merged["usb_usage"] +
        merged["web_activity"]
    )

    # -------------------------------------------------------------------------
    # Data Leakage Prevention: Sequential Historical & New Device Calculation
    # -------------------------------------------------------------------------
    logger.info("Computing strictly past-only historical baselines (t-1 cutoff)...")
    merged = merged.sort_values(["user_clean", "day"]).reset_index(drop=True)

    user_hist_means = []
    spike_ratios = []
    new_device_flags = []

    user_hist_state = {}  # user -> {'activities': [], 'seen_pcs': set()}

    for _, row in merged.iterrows():
        u = row["user_clean"]
        act = row["total_daily_activity"]
        pcs_today = row["pcs_used"] if isinstance(row.get("pcs_used"), set) else set()

        if u not in user_hist_state:
            user_hist_state[u] = {"activities": [], "seen_pcs": set()}

        past_acts = user_hist_state[u]["activities"]
        past_pcs = user_hist_state[u]["seen_pcs"]

        # 1. Historical Activity: Average of past days ONLY (no today, no future)
        if len(past_acts) > 0:
            hist_mean = float(np.mean(past_acts))
            # Ratio of today's volume to historical mean
            ratio = float(act / (hist_mean + 1.0))
        else:
            hist_mean = float(act)  # Day 1 prior is current
            ratio = 1.0

        user_hist_means.append(round(hist_mean, 2))
        spike_ratios.append(round(min(50.0, ratio), 2))

        # 2. New Device Flag: Were any PCs used today never seen before?
        if len(past_pcs) > 0 and len(pcs_today) > 0:
            has_new = 1 if len(pcs_today - past_pcs) > 0 else 0
        else:
            has_new = 0
        new_device_flags.append(has_new)

        # Update historical state for future days
        user_hist_state[u]["activities"].append(act)
        user_hist_state[u]["seen_pcs"].update(pcs_today)

    merged["user_historical_activity"] = user_hist_means
    merged["activity_spike_ratio"] = spike_ratios
    merged["new_device"] = new_device_flags

    # Rename user_clean to user for downstream standard
    merged["user"] = merged["user_clean"]

    final_cols = ["user", "day"] + SUPPORTED_FEATURE_COLUMNS
    df_features = merged[final_cols].copy()

    logger.info(f"Feature matrix construction complete: {df_features.shape[0]} rows, {len(SUPPORTED_FEATURE_COLUMNS)} features.")
    return df_features


def create_chronological_split(
    features_df: pd.DataFrame,
    split_date: str = "2010-12-01"
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Splits features chronologically into Train (< split_date) and Test (>= split_date).
    Guarantees no future temporal information leaks into the training partition.
    """
    df = features_df.copy()
    split_dt = pd.to_datetime(split_date).date()

    train_mask = df["day"] < split_dt
    test_mask = df["day"] >= split_dt

    train_df = df[train_mask].copy().reset_index(drop=True)
    test_df = df[test_mask].copy().reset_index(drop=True)

    logger.info(f"Chronological Split at {split_date}:")
    logger.info(f"  - Train Partition: {len(train_df)} rows ({train_df['day'].min()} to {train_df['day'].max()})")
    logger.info(f"  - Test Partition : {len(test_df)} rows ({test_df['day'].min()} to {test_df['day'].max()})")

    return train_df, test_df
