from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Assume 'cert_pem' is the PEM-encoded certificate
certificate = x509.load_pem_x509_certificate(cert_pem)

# Extract the public key
public_key = certificate.public_key()
