#!/bin/bash

# -----------------------------------------------------------------------------
# AeroScan Server Setup Script
# -----------------------------------------------------------------------------
# Purpose:
#   - Generates SSL certificates for the pi-registrar service.
#   - Sets up an initial .env file with an API key for Pi registration.
#   - Copies necessary certificates for Prometheus and Ansible dynamic inventory.
#
# Usage:
#   Run this script from the project root directory (e.g., ~/AeroScan).
#   Ensure you have OpenSSL installed.
# -----------------------------------------------------------------------------

echo "--- AeroScan Server Setup ---"

# --- Configuration: Define base paths ---
# These paths assume the script is run from the project root directory
# where 'Docker' and 'ansible' are subdirectories.
DOCKER_DIR="./Docker"
CONFIG_DIR="${DOCKER_DIR}/config"
CERTS_DIR="${CONFIG_DIR}/certs"                 # For pi-registrar's own SSL certs
PROM_CERTS_DIR="${CONFIG_DIR}/prometheus_certs" # For certs Prometheus needs to trust pi-registrar
ANSIBLE_CONFIG_DIR="./ansible/config"           # For config files needed by Ansible on control node
ANSIBLE_CERT_COPY_PATH="${ANSIBLE_CONFIG_DIR}/pi_registrar_server.pem" # Cert copy for Ansible inventory script
ENV_FILE="${DOCKER_DIR}/.env"                   # For Docker Compose environment variables

# --- Step 0: Ensure necessary directories exist ---
# Create configuration directories if they don't already exist to prevent errors later.
echo ""
echo "--- Step 0: Ensuring configuration directories exist ---"
mkdir -p "${CERTS_DIR}"
mkdir -p "${PROM_CERTS_DIR}"
mkdir -p "${ANSIBLE_CONFIG_DIR}"
echo "Directories ensured:"
echo "  pi-registrar certs: ${CERTS_DIR}"
echo "  Prometheus certs:   ${PROM_CERTS_DIR}"
echo "  Ansible config:     ${ANSIBLE_CONFIG_DIR}"

# --- Step 1: Generating SSL Certificates for pi-registrar service ---
echo ""
echo "--- Step 1: Generating SSL Certificates for pi-registrar service ---"

# Flag to determine if new certificates should be generated.
NEEDS_CERT_GEN=false

# Check if certificates (cert.pem and key.pem) already exist.
# If they do, prompt the user to confirm if they want to overwrite them.
if [ -f "${CERTS_DIR}/cert.pem" ] && [ -f "${CERTS_DIR}/key.pem" ]; then
  echo "SSL certificates already exist in ${CERTS_DIR}."
  read -p "Do you want to overwrite them? (y/N): " OVERWRITE_CERTS
  if [[ "$OVERWRITE_CERTS" == "y" || "$OVERWRITE_CERTS" == "Y" ]]; then
    echo "Overwriting existing certificates..."
    # Remove old certificates before generating new ones.
    rm -f "${CERTS_DIR}/cert.pem" "${CERTS_DIR}/key.pem"
    NEEDS_CERT_GEN=true
  else
    echo "Skipping certificate generation. Using existing certificates."
  fi
else
  # Certificates do not exist, so new generation is required.
  echo "No existing SSL certificates found. Generating new ones."
  NEEDS_CERT_GEN=true
fi

# Proceed with certificate generation if the NEEDS_CERT_GEN flag is true.
if [ "$NEEDS_CERT_GEN" = true ]; then
  # Prompt for Common Name (CN) for the SSL certificate.
  # This is a primary identifier in the certificate.
  DEFAULT_COMMON_NAME="AeroScan"
  read -p "Enter Common Name (CN) for SSL certificate (e.g., 'AeroScan' or server FQDN) [${DEFAULT_COMMON_NAME}]: " USER_CN
  # Use user input if provided, otherwise use the default.
  COMMON_NAME="${USER_CN:-$DEFAULT_COMMON_NAME}"

  # Prompt for the server's IP address to include in the Subject Alternative Name (SAN).
  # This is crucial for clients connecting via IP to avoid hostname mismatch SSL errors.
  DEFAULT_SERVER_IP="10.51.33.17" # Pre-fill with a common private IP; user should verify.
  read -p "Enter the IP address of this server (for SSL certificate SAN) [${DEFAULT_SERVER_IP}]: " SERVER_IP_INPUT
  # Use user input if provided, otherwise use the default.
  SERVER_IP="${SERVER_IP_INPUT:-$DEFAULT_SERVER_IP}"

  echo "Generating private key (key.pem)..."
  openssl genpkey -algorithm RSA -out "${CERTS_DIR}/key.pem" -pkeyopt rsa_keygen_bits:2048
  if [ $? -ne 0 ]; then echo "ERROR: Failed to generate private key."; exit 1; fi

  echo "Generating Certificate Signing Request (csr.pem)..."
  openssl req -new -key "${CERTS_DIR}/key.pem" -out "${CERTS_DIR}/csr.pem" \
    -subj "/CN=${COMMON_NAME}"
  if [ $? -ne 0 ]; then echo "ERROR: Failed to generate CSR."; exit 1; fi

  # Create a temporary OpenSSL configuration file (openssl_san.cnf).
  # This file defines extensions, including Subject Alternative Names (SANs),
  # which are essential for modern SSL clients.
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
# For example, if Prometheus will connect to 'pi-registrar' service name:
DNS.2 = pi-registrar
# DNS.3 = localhost # If testing locally and want localhost to be valid
EOL

  # Sign the certificate using the CSR, private key, and the SAN configuration.
  # This creates the self-signed public certificate (cert.pem).
  echo "Signing the certificate (cert.pem) with SAN extensions..."
  openssl x509 -req -days 365 -in "${CERTS_DIR}/csr.pem" \
    -signkey "${CERTS_DIR}/key.pem" -out "${CERTS_DIR}/cert.pem" \
    -extfile "${CERTS_DIR}/openssl_san.cnf" -extensions v3_req
  if [ $? -ne 0 ]; then echo "ERROR: Failed to sign certificate."; exit 1; fi

  # Clean up temporary files (CSR and SAN config).
  echo "Cleaning up temporary files (csr.pem, openssl_san.cnf)..."
  rm "${CERTS_DIR}/csr.pem"
  rm "${CERTS_DIR}/openssl_san.cnf"

  echo "SSL Certificates (key.pem, cert.pem) generated successfully in ${CERTS_DIR}/"
fi # End of NEEDS_CERT_GEN block

# --- Step 1b: Copy public certificate for Prometheus ---
# Prometheus (running in Docker) needs to trust the pi-registrar's certificate
# to scrape its /targets endpoint over HTTPS.
if [ -f "${CERTS_DIR}/cert.pem" ]; then
  echo "Copying public certificate (cert.pem) for Prometheus..."
  cp "${CERTS_DIR}/cert.pem" "${PROM_CERTS_DIR}/pi_registrar_server_public_cert.pem"
  echo "Public certificate copied to ${PROM_CERTS_DIR}/"
else
  # This error condition implies that certificates were expected to exist (either pre-existing or just generated)
  # but were not found. This is a critical failure.
  echo "ERROR: Source certificate ${CERTS_DIR}/cert.pem not found. Cannot copy for Prometheus."
  echo "Please ensure certificates were generated or exist from a previous run."
  exit 1
fi

# --- Step 1c: Copy public certificate for Ansible Dynamic Inventory Script ---
# The Ansible dynamic inventory script (running on this control node) also needs to trust
# the pi-registrar's certificate if it connects over HTTPS.
if [ -f "${CERTS_DIR}/cert.pem" ]; then
  echo "Copying public certificate (cert.pem) for Ansible inventory script..."
  cp "${CERTS_DIR}/cert.pem" "${ANSIBLE_CERT_COPY_PATH}"
  echo "Public certificate copied to ${ANSIBLE_CERT_COPY_PATH}"
else
  # Similar to the Prometheus copy, this is a critical failure if the source cert is missing.
  echo "ERROR: Source certificate ${CERTS_DIR}/cert.pem not found. Cannot copy for Ansible inventory."
  exit 1
fi

# --- Step 2: Setting up .env file for Pi Registration API Key ---
echo ""
echo "--- Step 2: Setting up .env file for Pi Registration API Key ---"

# This variable will store the API key to be displayed in the final instructions.
GENERATED_API_KEY=""

# Check if the .env file already exists in the Docker directory.
if [ -f "$ENV_FILE" ]; then
  echo ".env file already exists at ${ENV_FILE}."
  # If it exists, check if PI_REGISTER_API_KEY is already defined within it.
  if ! grep -q "^PI_REGISTER_API_KEY=" "$ENV_FILE"; then
    echo "PI_REGISTER_API_KEY not found in existing .env file. Appending a new one..."
    # Generate a 32-character random hexadecimal string for the API key.
    GENERATED_API_KEY=$(openssl rand -hex 16)
    # Ensure there's a newline before appending to avoid issues.
    echo "" >> "$ENV_FILE"
    echo "PI_REGISTER_API_KEY=${GENERATED_API_KEY}" >> "$ENV_FILE"
    echo "A new PI_REGISTER_API_KEY has been generated and added to ${ENV_FILE}."
  else
    # API key already exists; retrieve it for display in the instructions.
    EXISTING_KEY=$(grep "^PI_REGISTER_API_KEY=" "$ENV_FILE" | cut -d '=' -f2-)
    echo "PI_REGISTER_API_KEY is already set in ${ENV_FILE}."
    # Use the existing key for the instruction message.
    GENERATED_API_KEY="$EXISTING_KEY"
  fi
else
  # .env file does not exist, so create it with a new API key.
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
echo "2. Review the generated ${ENV_FILE} and note the PI_REGISTER_API_KEY."
echo "3. The public certificate for pi-registrar ('cert.pem') has been copied to:"
echo "   - ${PROM_CERTS_DIR}/pi_registrar_server_public_cert.pem (for Prometheus to trust pi-registrar)"
echo "   - ${ANSIBLE_CERT_COPY_PATH} (for the Ansible dynamic inventory script on this server)"
echo "4. On each Raspberry Pi you want to monitor:"
echo "   a. Copy THIS server's public certificate from '${CERTS_DIR}/cert.pem' to the Pi."
echo "      A suggested path on the Pi is: /etc/ssl/certs/pi_registrar_server.pem"
echo "   b. Create/edit the file '/var/local/network_monitor_registrar_url.txt' on the Pi."
echo "      Its content should be the HTTPS URL of this server's registrar, using the IP/hostname from the certificate's SAN:"
echo "      e.g., https://${SERVER_IP:-<YOUR_DOCKER_HOST_IP_AS_IN_CERT>}:5001/register  OR  https://${COMMON_NAME:-AeroScan}:5001/register"
echo "   c. Create/edit the file '/var/local/network_monitor_api_key.txt' on the Pi."
echo "      Its content should be THE API KEY generated by this script:"
echo "      ${GENERATED_API_KEY}"
echo "5. If you modified the server IP or API key during setup, ensure dependent configurations (like on the Pis) reflect these changes."
echo "6. To start the services, navigate to the Docker directory and run docker-compose:"
echo "   cd ${DOCKER_DIR}"
echo "   docker-compose up -d --build"
echo "   (Alternatively, from project root: docker-compose -f ${DOCKER_DIR}/docker-compose.yml up -d --build)"
echo "7. Start the main.py script on your Raspberry Pi(s)."
