#!/bin/bash

# Script to generate SSL certificates for the pi-registrar service
# and set up an initial .env file with an API key for Pi registration.
# This script should be run from the project root directory (e.g., ~/AeroScan).

echo "--- AeroScan Server Setup ---"

# --- Configuration: Define base paths ---
# Assumes the script is run from the project root where 'Docker' is a subdirectory.
DOCKER_DIR="./Docker"
CONFIG_DIR="${DOCKER_DIR}/config"
CERTS_DIR="${CONFIG_DIR}/certs"                 # For pi-registrar's own SSL certs
PROM_CERTS_DIR="${CONFIG_DIR}/prometheus_certs" # For certs Prometheus needs to trust
ENV_FILE="${DOCKER_DIR}/.env"                   # For Docker Compose environment variables

# --- Step 0: Ensure necessary directories exist ---
echo "Ensuring configuration directories exist..."
mkdir -p "${CERTS_DIR}"
mkdir -p "${PROM_CERTS_DIR}"
echo "Directories ensured: ${CERTS_DIR}, ${PROM_CERTS_DIR}"

echo ""
echo "--- Step 1: Generating SSL Certificates for pi-registrar service ---"

NEEDS_CERT_GEN=false # Flag to determine if new certificates should be generated

# Check if certificates already exist and prompt user if they want to overwrite.
if [ -f "${CERTS_DIR}/cert.pem" ] && [ -f "${CERTS_DIR}/key.pem" ]; then
  echo "SSL certificates already exist in ${CERTS_DIR}."
  read -p "Do you want to overwrite them? (y/N): " OVERWRITE_CERTS
  if [[ "$OVERWRITE_CERTS" == "y" || "$OVERWRITE_CERTS" == "Y" ]]; then
    echo "Overwriting existing certificates..."
    rm -f "${CERTS_DIR}/cert.pem" "${CERTS_DIR}/key.pem"
    NEEDS_CERT_GEN=true
  else
    echo "Skipping certificate generation. Using existing certificates."
  fi
else
  # Certificates do not exist, so generation is needed.
  echo "No existing SSL certificates found. Generating new ones."
  NEEDS_CERT_GEN=true
fi

# Proceed with certificate generation if flagged.
if [ "$NEEDS_CERT_GEN" = true ]; then
  # Prompt for Common Name (CN) for the SSL certificate.
  # This is used as the primary identifier in the certificate.
  DEFAULT_COMMON_NAME="AeroScan" # Default/Example CN
  read -p "Enter Common Name (CN) for SSL certificate (e.g., your server's FQDN or 'AeroScan') [${DEFAULT_COMMON_NAME}]: " USER_CN
  COMMON_NAME="${USER_CN:-$DEFAULT_COMMON_NAME}" # Use user input or default

  # Prompt for the IP address to include in the Subject Alternative Name (SAN).
  # This is crucial for clients connecting via IP address to avoid hostname mismatch errors.
  DEFAULT_SERVER_IP="10.51.33.17" # Pre-fill with your known server IP
  read -p "Enter the IP address of this server (for SSL certificate SAN) [${DEFAULT_SERVER_IP}]: " SERVER_IP
  SERVER_IP="${SERVER_IP:-$DEFAULT_SERVER_IP}" # Use user input or default

  echo "Generating private key (key.pem)..."
  openssl genpkey -algorithm RSA -out "${CERTS_DIR}/key.pem" -pkeyopt rsa_keygen_bits:2048
  if [ $? -ne 0 ]; then echo "ERROR: Failed to generate private key."; exit 1; fi

  echo "Generating Certificate Signing Request (csr.pem)..."
  openssl req -new -key "${CERTS_DIR}/key.pem" -out "${CERTS_DIR}/csr.pem" \
    -subj "/CN=${COMMON_NAME}"
  if [ $? -ne 0 ]; then echo "ERROR: Failed to generate CSR."; exit 1; fi

  # Create a temporary OpenSSL configuration file to include Subject Alternative Names (SAN).
  # SANs are necessary for modern SSL clients, especially when connecting via IP.
  echo "Creating temporary OpenSSL SAN configuration (openssl_san.cnf)..."
  cat > "${CERTS_DIR}/openssl_san.cnf" <<EOL
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${COMMON_NAME}

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${COMMON_NAME}
IP.1 = ${SERVER_IP}
# If you have other DNS names for this server, add them as DNS.2, DNS.3, etc.
# e.g., DNS.2 = my-server.local
EOL

  # Sign the certificate using the CSR, private key, and SAN configuration.
  # This creates the self-signed public certificate (cert.pem).
  echo "Signing the certificate (cert.pem) with SAN extensions..."
  openssl x509 -req -days 365 -in "${CERTS_DIR}/csr.pem" \
    -signkey "${CERTS_DIR}/key.pem" -out "${CERTS_DIR}/cert.pem" \
    -extfile "${CERTS_DIR}/openssl_san.cnf" -extensions v3_req
  if [ $? -ne 0 ]; then echo "ERROR: Failed to sign certificate."; exit 1; fi

  # Clean up temporary files.
  echo "Cleaning up temporary files (csr.pem, openssl_san.cnf)..."
  rm "${CERTS_DIR}/csr.pem"
  rm "${CERTS_DIR}/openssl_san.cnf"

  echo "SSL Certificates (key.pem, cert.pem) generated successfully in ${CERTS_DIR}/"
fi

# --- Step 1b: Copy public certificate for Prometheus ---
# Prometheus needs to trust the pi-registrar's certificate.
if [ -f "${CERTS_DIR}/cert.pem" ]; then
  echo "Copying public certificate (cert.pem) for Prometheus..."
  cp "${CERTS_DIR}/cert.pem" "${PROM_CERTS_DIR}/pi_registrar_server_public_cert.pem"
  echo "Public certificate copied to ${PROM_CERTS_DIR}/"
else
  # This should not happen if NEEDS_CERT_GEN was true and successful,
  # or if user chose not to overwrite existing valid certs.
  echo "ERROR: Source certificate ${CERTS_DIR}/cert.pem not found. Cannot copy for Prometheus."
  echo "Please ensure certificates were generated or exist."
  exit 1
fi

echo ""
echo "--- Step 2: Setting up .env file for Pi Registration API Key ---"

GENERATED_API_KEY="" # To store the key for display in final instructions

# Check if the .env file already exists.
if [ -f "$ENV_FILE" ]; then
  echo ".env file already exists at ${ENV_FILE}."
  # Check if PI_REGISTER_API_KEY is already defined within the existing .env file.
  if ! grep -q "^PI_REGISTER_API_KEY=" "$ENV_FILE"; then
    echo "PI_REGISTER_API_KEY not found in existing .env file. Appending a new one..."
    GENERATED_API_KEY=$(openssl rand -hex 16) # Generate a 32-character random hex string
    echo "" >> "$ENV_FILE" # Ensure there's a newline before appending
    echo "PI_REGISTER_API_KEY=${GENERATED_API_KEY}" >> "$ENV_FILE"
    echo "A new PI_REGISTER_API_KEY has been generated and added to ${ENV_FILE}."
  else
    # API key already exists, retrieve it for display.
    EXISTING_KEY=$(grep "^PI_REGISTER_API_KEY=" "$ENV_FILE" | cut -d '=' -f2-)
    echo "PI_REGISTER_API_KEY is already set in ${ENV_FILE}."
    GENERATED_API_KEY="$EXISTING_KEY" # Use the existing key for the instruction message
  fi
else
  # .env file does not exist, create it with a new API key.
  echo "Creating new .env file at ${ENV_FILE}..."
  GENERATED_API_KEY=$(openssl rand -hex 16)
  echo "# AeroScan Environment Variables - This file should be in .gitignore" > "$ENV_FILE"
  echo "PI_REGISTER_API_KEY=${GENERATED_API_KEY}" >> "$ENV_FILE"
  echo ".env file created successfully with a new PI_REGISTER_API_KEY."
fi

echo ""
echo "IMPORTANT: The API key for Pi registration is: ${GENERATED_API_KEY}"
echo "You will need this key when configuring your Raspberry Pi(s)."

# --- Final Instructions ---
echo ""
echo "--- Server Setup Complete ---"
echo "Next steps:"
echo "1. Ensure Docker and Docker Compose are installed on this server."
echo "2. Review the generated ${ENV_FILE} file and note the PI_REGISTER_API_KEY."
echo "3. On each Raspberry Pi you want to monitor:"
echo "   a. Copy the server's public certificate from '${CERTS_DIR}/cert.pem' to the Pi."
echo "      A suggested path on the Pi is: /etc/ssl/certs/pi_registrar_server.pem"
echo "   b. Create or edit the file '/var/local/network_monitor_registrar_url.txt' on the Pi."
echo "      Its content should be the HTTPS URL of this server's registrar, e.g.:"
echo "      https://${SERVER_IP:-<YOUR_DOCKER_HOST_IP>}:5001/register"
echo "   c. Create or edit the file '/var/local/network_monitor_api_key.txt' on the Pi."
echo "      Its content should be THE API KEY generated above:"
echo "      ${GENERATED_API_KEY}"
echo "4. If you modified the server IP or API key, ensure dependent configurations (like on the Pis) are updated."
echo "5. From the project root directory on this server (where setup_server.sh is located), run:"
echo "   cd Docker/ && docker-compose up -d --build"
echo "   (Or, from project root: docker-compose -f Docker/docker-compose.yml up -d --build)"
echo "6. Start the main.py script on your Raspberry Pi(s)."
