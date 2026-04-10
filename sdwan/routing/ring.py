import keyring

# Define your new service name
SERVICE_NAME = "tenant2"

# Replace these with your actual credentials
CLIENT_ID = "YOUR_panserviceaccount.com"
CLIENT_SECRET = "YOUR_SECRET"
TSG_ID = "YOUR_TENANT_ID"

# Store them
keyring.set_password(SERVICE_NAME, "client_id", CLIENT_ID)
keyring.set_password(SERVICE_NAME, "client_secret", CLIENT_SECRET)
keyring.set_password(SERVICE_NAME, "tsg_id", TSG_ID)

print(f"✅ Credentials for '{SERVICE_NAME}' have been stored in the keyring.")

