"""
Certificate Manager for SSL/TLS Interception

Handles:
- CA certificate generation for mitmproxy
- Certificate details extraction
- Certificate validation tracking
- Certificate chain information
"""

import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
import structlog

logger = structlog.get_logger()


class CertificateManager:
    """
    Manages SSL/TLS certificates for the proxy
    
    Handles CA certificate generation, certificate validation,
    and extraction of certificate details from connections.
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = logger.bind(component="certificate_manager")
        self.ca_cert_dir = Path(config.proxy.ca_cert_dir)
        self.ca_cert_dir.mkdir(parents=True, exist_ok=True)
    
    def get_ca_cert_path(self) -> Path:
        """
        Get the path to the CA certificate
        
        mitmproxy automatically generates the CA cert on first run.
        This returns the expected path.
        
        Returns:
            Path to the CA certificate PEM file
        """
        return self.ca_cert_dir / f"{self.config.proxy.ca_cert_name}.pem"
    
    def ca_cert_exists(self) -> bool:
        """Check if CA certificate exists"""
        return self.get_ca_cert_path().exists()
    
    def get_ca_cert_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the CA certificate
        
        Returns:
            Dictionary with CA cert information or None if not found
        """
        cert_path = self.get_ca_cert_path()
        if not cert_path.exists():
            return None
        
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            return {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat(),
                "serial_number": cert.serial_number,
                "fingerprint": hashlib.sha256(cert.public_bytes(
                    encoding=serialization.Encoding.DER
                )).hexdigest()
            }
        except Exception as e:
            self.logger.error("Failed to load CA certificate", error=str(e))
            return None
    
    def extract_cert_info(self, cert_data: bytes) -> Dict[str, Any]:
        """
        Extract detailed information from a certificate
        
        Args:
            cert_data: Raw certificate data (DER or PEM format)
        
        Returns:
            Dictionary with certificate details
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization
            
            # Try to load as PEM first, then DER
            try:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            except:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            # Extract subject and issuer
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            
            # Calculate fingerprint
            fingerprint = hashlib.sha256(cert.public_bytes(
                encoding=serialization.Encoding.DER
            )).hexdigest()
            
            # Extract SANs (Subject Alternative Names)
            sans = []
            try:
                san_ext = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                sans = [str(name) for name in san_ext.value]
            except:
                pass
            
            return {
                "subject": subject,
                "issuer": issuer,
                "fingerprint": fingerprint,
                "serial_number": cert.serial_number,
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat(),
                "subject_alternative_names": sans,
                "version": cert.version.name,
                "is_self_signed": subject == issuer
            }
        
        except Exception as e:
            self.logger.error("Failed to extract certificate info", error=str(e))
            return {}
    
    def validate_cert(self, cert_data: bytes, hostname: str) -> Dict[str, Any]:
        """
        Validate a certificate
        
        Args:
            cert_data: Raw certificate data
            hostname: Hostname to validate against
        
        Returns:
            Dictionary with validation results
        """
        validation_errors = []
        warnings = []
        
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            # Load certificate
            try:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            except:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            # Check expiration
            now = datetime.utcnow()
            if cert.not_valid_before > now:
                validation_errors.append("Certificate not yet valid")
            if cert.not_valid_after < now:
                validation_errors.append("Certificate expired")
            elif (cert.not_valid_after - now).days < 30:
                warnings.append("Certificate expires soon (< 30 days)")
            
            # Check hostname match
            subject = cert.subject.rfc4514_string()
            sans = []
            try:
                san_ext = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                sans = [str(name) for name in san_ext.value]
            except:
                pass
            
            hostname_matches = False
            if hostname in subject or hostname in sans:
                hostname_matches = True
            # Check wildcard matches
            for san in sans:
                if san.startswith("*.") and hostname.endswith(san[2:]):
                    hostname_matches = True
                    break
            
            if not hostname_matches:
                validation_errors.append(f"Hostname '{hostname}' does not match certificate")
            
            # Check if self-signed
            if subject == cert.issuer.rfc4514_string():
                warnings.append("Certificate is self-signed")
            
            return {
                "valid": len(validation_errors) == 0,
                "errors": validation_errors,
                "warnings": warnings,
                "hostname_matches": hostname_matches
            }
        
        except Exception as e:
            self.logger.error("Certificate validation failed", error=str(e))
            return {
                "valid": False,
                "errors": [f"Validation error: {str(e)}"],
                "warnings": [],
                "hostname_matches": False
            }
    
    def extract_cert_chain_info(self, cert_chain: List[bytes]) -> List[Dict[str, Any]]:
        """
        Extract information from certificate chain
        
        Args:
            cert_chain: List of certificates in the chain (DER or PEM)
        
        Returns:
            List of certificate information dictionaries
        """
        chain_info = []
        
        for i, cert_data in enumerate(cert_chain):
            info = self.extract_cert_info(cert_data)
            info["position_in_chain"] = i
            chain_info.append(info)
        
        return chain_info
    
    def get_installation_instructions(self) -> Dict[str, str]:
        """
        Get CA certificate installation instructions for various platforms
        
        Returns:
            Dictionary with installation instructions per platform
        """
        cert_path = self.get_ca_cert_path()
        
        return {
            "windows": f"""
Windows:
1. Double-click the certificate file: {cert_path}
2. Click "Install Certificate"
3. Select "Local Machine" and click "Next"
4. Select "Place all certificates in the following store"
5. Click "Browse" and select "Trusted Root Certification Authorities"
6. Click "Next" and "Finish"
""",
            "macos": f"""
macOS:
1. Double-click the certificate file: {cert_path}
2. Enter your password when prompted
3. In Keychain Access, find the certificate
4. Double-click it and expand "Trust"
5. Set "When using this certificate" to "Always Trust"
""",
            "linux": f"""
Linux (Ubuntu/Debian):
1. sudo cp {cert_path} /usr/local/share/ca-certificates/mitmproxy-ca.crt
2. sudo update-ca-certificates

Linux (CentOS/RHEL):
1. sudo cp {cert_path} /etc/pki/ca-trust/source/anchors/
2. sudo update-ca-trust
""",
            "firefox": f"""
Firefox:
1. Open Firefox Settings
2. Go to Privacy & Security > Certificates > View Certificates
3. Go to Authorities tab
4. Click Import
5. Select: {cert_path}
6. Check "Trust this CA to identify websites"
""",
            "curl": f"""
curl:
Add to curl commands: --cacert {cert_path}
Or set environment variable: export CURL_CA_BUNDLE={cert_path}
""",
            "python_requests": f"""
Python requests:
import requests
requests.get(url, verify='{cert_path}')

Or set environment variable: export REQUESTS_CA_BUNDLE={cert_path}
"""
        }
