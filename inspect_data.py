import pandas as pd

print("Checking logon.csv...")
logon_df = pd.read_csv("data/raw/logon.csv", nrows=5)
print("Logon columns:", logon_df.columns.tolist())
print(logon_df.head(2))

print("\nChecking device.csv...")
device_df = pd.read_csv("data/raw/device.csv", nrows=5)
print("Device columns:", device_df.columns.tolist())
print(device_df.head(2))