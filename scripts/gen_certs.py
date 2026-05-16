from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Root CA
ca_key = rsa.generate_private_key(65537, 2048)
ca_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Polyglot Root CA")])
ca_cert = x509.CertificateBuilder().subject_name(ca_subj).issuer_name(ca_subj).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=3650)).sign(ca_key, hashes.SHA256())
with open("/certs/ca.key", "wb") as f: f.write(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
with open("/certs/ca.crt", "wb") as f: f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

# Server cert (nginx)
srv_key = rsa.generate_private_key(65537, 2048)
srv_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nginx")])
srv_cert = x509.CertificateBuilder().subject_name(srv_subj).issuer_name(ca_subj).public_key(srv_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=365)).sign(ca_key, hashes.SHA256())
with open("/certs/server.key", "wb") as f: f.write(srv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
with open("/certs/server.crt", "wb") as f: f.write(srv_cert.public_bytes(serialization.Encoding.PEM))

# Client cert (gateway)
cli_key = rsa.generate_private_key(65537, 2048)
cli_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gateway")])
cli_cert = x509.CertificateBuilder().subject_name(cli_subj).issuer_name(ca_subj).public_key(cli_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=365)).sign(ca_key, hashes.SHA256())
with open("/certs/client.key", "wb") as f: f.write(cli_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
with open("/certs/client.crt", "wb") as f: f.write(cli_cert.public_bytes(serialization.Encoding.PEM))

print("All certificates generated successfully")
