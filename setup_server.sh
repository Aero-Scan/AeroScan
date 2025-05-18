#!/bin/bash

# setup_server.sh - Script to generate SSL certs and initial .env file

echo "--- AeroScan Server Setup ---"

# Define paths relative to the Docker directory
DOCKER_DIR="./Docker"
CONFIG_DIR="${DOCKER_DIR}/config" # General config dir
CERTS_DIR="${CONFIG_DIR}/certs"
PROM_CERTS_DIR="${CONFIG_DIR}/prometheus_certs"
ENV_FILE=".env" # In project root, next to docker-compose.yml

# Create directories if they don't exist
mkdir -p "${CERTS_DIR}"
mkdir -p "${PROM_CERTS_DIR}"

echo ""
echo "Step 1: Generating SSL Certificates for pi-registrar..."

NEEDS_CERT_GEN=false
if [ -f "${CERTS_DIR}/cert.pem" ] && [ -f "${CERTS_DIR}/key.pem" ]; then
  read -p "Certificates already exist in ${CERTS_DIR}. Overwrite? (y/N): " OVERWRITE_CERTS
  if [[ "$OVERWRITE_CERTS" == "y" || "$OVERWRITE_CERTS" == "Y" ]]; then
    echo "Removing existing certificates..."
    rm -f "${CERTS_DIR}/cert.pem" "${CERTS_DIR}/key.pem"
    NEEDS_CERT_GEN=true
  else
    echo "Skipping certificate generation. Using existing certificates."
  fi
else
  NEEDS_CERT_GEN=true
fi

if [ "$NEEDS_CERT_GEN" = true ]; then
  # Default Common Name for the certificate
  COMMON_NAME="pi-registrar-internal"
  read -p "Enter Common Name (CN) for SSL certificate (e.g., your server's FQDN or an internal name) [${COMMON_NAME}]: " USER_CN
  if [ ! -z "$USER_CN" ]; then
    COMMON_NAME="$USER_CN"
  fi

  openssl genpkey -algorithm RSA -out "${CERTS_DIR}/key.pem" -pkeyopt rsa_keygen_bits:2048
  openssl req -new -key "${CERTS_DIR}/key.pem" -out "${CERTS_DIR}/csr.pem" \
    -subj "/CN=${COMMON_NAME}"
  openssl x509 -req -days 365 -in "${CERTS_DIR}/csr.pem" \
    -signkey "${CERTS_DIR}/key.pem" -out "${CERTS_DIR}/cert.pem"
  rm "${CERTS_DIR}/csr.pem" # Clean up CSR

  if [ $? -eq 0 ]; then
    echo "SSL Certificates generated successfully in ${CERTS_DIR}/"
  else
    echo "ERROR: SSL Certificate generation failed."
    exit 1
  fi
fi

# Copy cert.pem for Prometheus to use
if [ -f "${CERTS_DIR}/cert.pem" ]; then
  cp "${CERTS_DIR}/cert.pem" "${PROM_CERTS_DIR}/pi_registrar_server_public_cert.pem"
  echo "Copied public certificate for Prometheus to ${PROM_CERTS_DIR}/"
else
  echo "ERROR: Source certificate ${CERTS_DIR}/cert.pem not found. Cannot copy for Prometheus."
  exit 1
fi


echo ""
echo "Step 2: Setting up .env file for API Key..."

GENERATED_API_KEY=""
if [ -f "$ENV_FILE" ]; then
  echo ".env file already exists."
  if ! grep -q "^PI_REGISTER_API_KEY=" "$ENV_FILE"; then
    echo "PI_REGISTER_API_KEY not found in .env. Appending a new one."
    GENERATED_API_KEY=$(openssl rand -hex 16) # Generate a 32-char random hex string
    echo "" >> "$ENV_FILE" # Ensure newline before appending
    echo "PI_REGISTER_API_KEY=${GENERATED_API_KEY}" >> "$ENV_FILE"
    echo "A new PI_REGISTER_API_KEY has been generated and added to .env."
  else
    EXISTING_KEY=$(grep "^PI_REGISTER_API_KEY=" "$ENV_FILE" | cut -d '=' -f2-)
    echo "PI_REGISTER_API_KEY already set in .env."
    GENERATED_API_KEY="$EXISTING_KEY" # Use existing key for instructions
  fi
else
  echo "Creating .env file..."
  GENERATED_API_KEY=$(openssl rand -hex 16)
  echo "# AeroScan Environment Variables - This file should be in .gitignore" > "$ENV_FILE"
  echo "PI_REGISTER_API_KEY=${GENERATED_API_KEY}" >> "$ENV_FILE"
  echo ".env file created with a new PI_REGISTER_API_KEY."
fi

echo "IMPORTANT: The API key for Pi registration is: ${GENERATED_API_KEY}"
echo "You will need this key when configuring your Raspberry Pi(s)."


echo ""
echo "--- Server Setup Complete ---"
echo "Next steps:"
echo "1. Ensure you have Docker and Docker Compose installed."
echo "2. Review the generated .env file (in the project root)."
echo "3. On each Raspberry Pi:"
echo "   a. Copy '${CERTS_DIR}/cert.pem' (the public certificate from the server) to the Pi."
echo "      Suggested path on Pi: /etc/ssl/certs/pi_registrar_server.pem"
echo "   b. Create/edit '/var/local/network_monitor_registrar_url.txt' on the Pi and put the URL:"
echo "      https://<YOUR_DOCKER_HOST_IP_OR_DNS>:5001/register"
echo "   c. Create/edit '/var/local/network_monitor_api_key.txt' on the Pi and put THE API KEY:"
echo "      ${GENERATED_API_KEY}"
echo "4. Run 'docker-compose up -d' in the project root on your server to start the services."
echo "5. Start the main.py script on your Raspberry Pi(s)."
