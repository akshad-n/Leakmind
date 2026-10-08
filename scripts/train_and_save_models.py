import os
import json
import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

def train_and_export():
    models_dir = "models"
    os.makedirs(models_dir, exist_ok=True)
    
    print("[1/3] Training Unsupervised Anomaly Detection (Isolation Forest)...")
    df_features = pd.read_csv("data/processed/leakmind_features.csv")
    feature_cols = [c for c in df_features.columns if c != "user"]
    X_iso = df_features[feature_cols].fillna(0)
    
    iso_scaler = StandardScaler()
    X_iso_scaled = iso_scaler.fit_transform(X_iso)
    
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    iso_forest.fit(X_iso_scaled)
    
    joblib.dump(iso_forest, os.path.join(models_dir, "isolation_forest.joblib"))
    joblib.dump(iso_scaler, os.path.join(models_dir, "isolation_forest_scaler.joblib"))
    print("      Saved isolation_forest.joblib & scaler.")
    
    print("[2/3] Training Supervised Models (XGBoost, Random Forest, Logistic Regression)...")
    X_daily = pd.read_csv("data/processed/X_daily_supervised.csv")
    y_daily = pd.read_csv("data/processed/y_daily_supervised.csv")
    
    # Handle Series or single column dataframe
    if isinstance(y_daily, pd.DataFrame):
        y_daily = y_daily.iloc[:, 0]
        
    sup_scaler = StandardScaler()
    X_daily_scaled = sup_scaler.fit_transform(X_daily)
    
    # Train Logistic Regression
    lr = LogisticRegression(random_state=42, max_iter=1000)
    lr.fit(X_daily_scaled, y_daily)
    joblib.dump(lr, os.path.join(models_dir, "logistic_model.joblib"))
    
    # Train Random Forest
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_daily, y_daily)
    joblib.dump(rf, os.path.join(models_dir, "rf_model.joblib"))
    
    # Train XGBoost
    xgb = XGBClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=4,
        random_state=42,
        eval_metric="logloss"
    )
    xgb.fit(X_daily, y_daily)
    joblib.dump(xgb, os.path.join(models_dir, "xgboost_model.joblib"))
    joblib.dump(sup_scaler, os.path.join(models_dir, "supervised_scaler.joblib"))
    print("      Saved xgboost_model.joblib, rf_model.joblib, logistic_model.joblib & scaler.")
    
    metadata = {
        "isolation_forest_features": feature_cols,
        "supervised_features": X_daily.columns.tolist(),
        "supervised_target": "insider_label",
        "models_available": ["xgboost", "random_forest", "logistic_regression", "isolation_forest"]
    }
    with open(os.path.join(models_dir, "model_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=4)
        
    print("[3/3] Export complete! Model artifacts stored in models/")

if __name__ == "__main__":
    train_and_export()
