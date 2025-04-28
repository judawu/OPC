import hashlib
import pickle
import os
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import uuid
import logging
class _DVLicManager_:
# License type dictionary
        def __init__(self):
            self._system_license_type = {
                "Simluate 1 hour License": 1,
                "Simluate 4 hour License": 2,
                 "Demo License": 3,     
                "Simluate 3 minute test License": 5,
                "Simluate 10 minute and 100 DST test License": 6,
                "Simluate 30 minute and 500 DST test License": 7,
                "Simluate 60 minute and 1000 DST test License": 8,
                "Simluate 1 day and 10000 DST test License": 9,
                "Simluate 1 day License": 10,
                "Perpetual License": 100,
                "Unlimit 100000 DST License": 99,
                "Unlimit 50000 DST License": 98,
                "Unlimit 20000 DST License": 97,
                "Unlimit 10000 DST License": 96,
                "Unlimit 5000 DST License": 95,
                "Unlimit 3000 DST License": 94,
                "Unlimit 1000 DST License": 93,            
                "Subscription 3 year 100000 DST License": 89,
                "Subscription 2 year 100000 DST License": 88,
                "Subscription 1 year 100000 DST License": 87,
                "Subscription 6 month 100000 DST License": 86,
                "Subscription 3 month 100000 DST License": 85,
                "Subscription 3 year 50000 DST License": 79,
                "Subscription 2 year 50000 DST License": 78,
                "Subscription 1 year 50000 DST License": 77,
                "Subscription 6 month 50000 DST License": 76,
                "Subscription 3 year 20000 DST License": 59,
                "Subscription 2 year 20000 DST License": 58,
                "Subscription 1 year 20000 DST License": 57,
                "Subscription 6 month 20000 DST License": 56,
                "Subscription 3 year 10000 DST License": 49,
                "Subscription 2 year 10000 DST License": 48,
                "Subscription 1 year 10000 DST License": 47,
                "Subscription 6 month 10000 DST License": 46,
                "Subscription 3 year 5000 DST License": 39,
                "Subscription 2 year 5000 DST License": 38,
                "Subscription 1 year 5000 DST License": 37,
                "Subscription 6 month 5000 DST License": 36,
                "Subscription 3 year 3000 DST License": 29,
                "Subscription 2 year 3000 DST License": 28,
                "Subscription 1 year 3000 DST License": 27,
                "Subscription 6 month 3000 DST License": 26,
                "Subscription 3 year 1000 DST License": 19,
                "Subscription 2 year 1000 DST License": 18,
                "Subscription 1 year 1000 DST License": 17,
            }
            self._license_type=None

        # Function to retrieve hardware ID using os and uuid
        def _get_hardware_id(self):
            try:
                # Get OS version and platform
                os_version = os.sys.platform  # e.g., 'win32'
                os_name = os.name  # e.g., 'nt' for Windows
                
                # Get MAC address
                mac_address = hex(uuid.getnode())[2:].zfill(12)  # Format as 12-digit hex
                
                # Combine identifiers
                combined_id = f"{os_version}:{os_name}:{mac_address}"
                return combined_id
            except Exception as e:
                print(f"_DVLicManager_:Error retrieving hardware ID: {e}")
                # Fallback to mock ID
                return "mock-hardware-serial-1234567890"

        # Generate hardware code by hashing hardware ID
        def _generate_hardware_code(self):
            hardware_id = self._get_hardware_id()
            return hashlib.sha256(hardware_id.encode()).hexdigest()

        # Client generates software code using hardware code and PO number
        def _generate_software_code(self,  hardware_code,po_number):
         
            combined = hardware_code + po_number
            
            return hashlib.sha256(combined.encode()).hexdigest()

        # Client decodes and verifies authorization code
        def _client_verify_auth_code(self,auth_code,  hardware_code,po_number):
            try:
                decoded = base64.b64decode(auth_code).decode().split(":")
                received_auth_code, license_key,po_part = decoded
                logging.debug(f"_DVLicManager_ DEBUG: Received license_key: {license_key}")
                # Verify hardware code by regenerating software code
                software_code = self._generate_software_code( hardware_code,po_number)
                expected_auth_code = hashlib.sha256((software_code + license_key + po_part).encode()).hexdigest()
                # Debug prints to diagnose mismatch
                logging.debug(f"_DVLicManager_ DEBUG: Received auth_code: {received_auth_code}")
                logging.debug(f"_DVLicManager_ DEBUG: Software code: {software_code}")
                logging.debug(f"_DVLicManager_ DEBUG: License key: {license_key}")
                #logging.debug(f"_DVLicManager_ DEBUG: Expected auth_code: {expected_auth_code}")
                return received_auth_code == expected_auth_code, license_key
            except Exception as e:
                logging.error(f"Error verifying auth code: {e}")
                return False, None

        # Generate encryption key from hardware code
        def _generate_encryption_key(self,hardware_code):
            # Use PBKDF2 to derive a key from the hardware code
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'salt_',  # Fixed salt for simplicity; in production, use a random salt and store it
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(hardware_code.encode()))
            return key

        # Save license file with encryption, including MAC address
        def _save_license_file(self,hardware_code, license_key):
            # Get MAC address for storage
            mac_address = hex(uuid.getnode())[2:].zfill(12)  # Format as 12-digit hex
            license_data = {
                "hardware_code": hardware_code,
                "license_key": license_key,
                "mac_address": mac_address,  # Store MAC address
                "timestamp": datetime.now().isoformat()
            }
            # Create clientlicense directory if it doesn't exist
            base_dir = os.path.dirname(os.path.abspath(__file__))
            lic_dir = os.path.join(base_dir, "clientlicense")
            os.makedirs(lic_dir, exist_ok=True)
            file_path = os.path.join(lic_dir, "clientlicense.bin")
            
            # Serialize data with pickle
            pickled_data = pickle.dumps(license_data)
            
            # Encrypt the pickled data
            key = self._generate_encryption_key(hardware_code)
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(pickled_data)
            
            # Save encrypted data
            with open(file_path, "wb") as f:
                f.write(encrypted_data)
            return file_path

        # Load and verify license file with decryption, using stored MAC address
        def _load_license_file(self):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            lic_dir = os.path.join(base_dir, "clientlicense")
            file_path = os.path.join(lic_dir, "clientlicense.bin")
            if not os.path.exists(file_path):
                return None
            try:
                # Read encrypted data
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()
                
                # Decrypt data
                hardware_code = self._generate_hardware_code()
                key = self._generate_encryption_key(hardware_code)
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(encrypted_data)
                
                # Unpickle data
                license_data = pickle.loads(decrypted_data)
                
                # Reconstruct hardware ID using stored MAC address
                os_version = os.sys.platform  # e.g., 'win32'
                os_name = os.name  # e.g., 'nt'
                stored_mac_address = license_data.get("mac_address", "unknown")
                mac_address = hex(uuid.getnode())[2:].zfill(12)  # Format as 12-digit hex
                if mac_address == stored_mac_address:
                    reconstructed_hardware_id = f"{os_version}:{os_name}:{mac_address}"
                    reconstructed_hardware_code = hashlib.sha256(reconstructed_hardware_id.encode()).hexdigest()
                      # Verify hardware code
                    if license_data["hardware_code"] == reconstructed_hardware_code:
                        return license_data["license_key"]
                    else:
                        logging.debug("Hardware mismatch in license file")
                        return None
                else:
                     logging.debug("Hardware mac address not mathc with the stored mac address, use simluate license")
                     return None
              
            except Exception as e:
                logging.error(f"Error loading license file: {e}")
                return None

        # Main program
        def _activate_license(self,auth_code,po_number):
             # If no valid license, proceed with authentication
            hardware_code = self._generate_hardware_code()
            is_valid, license_key = self._client_verify_auth_code(auth_code, hardware_code, po_number)
            if is_valid and license_key:
                # Save license file
                self._save_license_file(hardware_code, license_key)
              
                license_type = self._system_license_type.get(license_key, 1)
                logging.info(f"License authenticated and saved. Running with license key: {license_key}")
            else:
                logging.info(f"Authorization code verification failed, license_key is {license_key} not load, use simulate key ")
                license_type = self._system_license_type["Simluate 1 hour License"]  # Use simulate license on failure
            return (license_key,license_type)
        def run(self):
          
            
                # Check for existing license file
            license_key = self._load_license_file()
            if license_key:
                    self._license_type = self._system_license_type.get(license_key, 1)
                    logging.info(f"licnese {license_key} fonund, and will continue with main program start ")
            else:
                po=input("please input Purchase Order No:")
                hardware_code=self._generate_hardware_code()
                software_code=self. _generate_software_code( hardware_code,po) 
                authorization_code=input(f"please send \n {software_code} \n to the vendor to get the iauthorization_code, and input the authorization code\n")
                license_key,license_type = self._activate_license(authorization_code,po)
                self._license_type=license_type
                logging.info(f"licnese activate {license_key} loaded, and will continue with main program start ")
def main():
             license_manager=_DVLicManager_()
             license_manager.run()    

           

if __name__ == "__main__":
    logging.basicConfig(
  
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s')
    main()
        