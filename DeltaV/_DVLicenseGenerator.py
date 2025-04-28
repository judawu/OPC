import hashlib

import base64

class _DVLicGenerator_:
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
            self.PO_LOOKUP_TABLE = {
            "P100000": "Simluate 3 minute test License",
            
            "P100001": "Simluate 10 minute and 100 DST test License",
                 
            "P100002":  "Simluate 30 minute and 500 DST test License",
            "P100003":   "Simluate 60 minute and 1000 DST test License",
            "P100004":   "Simluate 1 day and 10000 DST test License",
          
            "P100009" :"Simluate 4 hour License",   
            "P100010" : "Simluate 1 day License",
            "PO00000": "Demo License",    
            "PO00002": "Unlimit 100000 DST License",
            "PO00003": "Unlimit 50000 DST License",
            "PO00004": "Unlimit 20000 DST License",
            "PO00005": "Unlimit 10000 DST License",
            "PO00006":"Unlimit 5000 DST License",
            "PO00007":"Unlimit 3000 DST License",
            "PO00008":"Unlimit 1000 DST License",
       
            "PO00012": "Subscription 3 year 100000 DST License",
            "PO00013":  "Subscription 2 year 100000 DST License",
            "PO00014":  "Subscription 1 year 100000 DST License",
            "PO00015":  "Subscription 6 month 100000 DST License",
            "PO00016":  "Subscription 3 month 100000 DST License",
            "PO00017":  "Subscription 3 year 50000 DST License",
            "PO00018":  "Subscription 2 year 50000 DST License",
            "PO00019":  "Subscription 1 year 50000 DST License",
            "PO00020":  "Subscription 6 month 50000 DST License",
            "PO00021": "Subscription 3 year 20000 DST License",
            "PO00022": "Subscription 2 year 20000 DST License",
            "PO00023":  "Subscription 1 year 20000 DST License",
            "PO00024":  "Subscription 6 month 20000 DST License",
            "PO00025":  "Subscription 3 year 10000 DST License",
            "PO00026":  "Subscription 2 year 10000 DST License",
            "PO00027":  "Subscription 1 year 10000 DST License",
            "PO00028":  "Subscription 6 month 10000 DST License",
            "PO00029":  "Subscription 3 year 5000 DST License",
            "PO00030":  "Subscription 2 year 5000 DST License",
            "PO00031":  "Subscription 1 year 5000 DST License",
            "PO00032": "Subscription 6 month 5000 DST License",
            "PO00033": "Subscription 3 year 3000 DST License",
            "PO00034": "Subscription 2 year 3000 DST License",
            "PO00035": "Subscription 1 year 3000 DST License",
            "PO00036": "Subscription 6 month 3000 DST License",
            "PO00037":  "Subscription 3 year 1000 DST License",
            "PO00038": "Subscription 2 year 1000 DST License",
            "PO00039": "Subscription 1 year 1000 DST License",
            "PO12345": "Perpetual License",
            
    
        }


# Simulated server-side function to generate authorization code
    def _server_lookup_license_key(self,po_number):
        #SHOULD BE IN A DATABASE      
        license_key=self.PO_LOOKUP_TABLE.get(po_number,  "Simluate 1 hour License")
        #print(license_key)
        return license_key
    def add_PO(self,po,license_key):
        #SHOULD BE IN A DATABASE
        
        self.PO_LOOKUP_TABLE[po]=license_key
    def remove_PO(self,po):
        #SHOULD BE IN A DATABASE
        if po in self.PO_LOOKUP_TABLE:
          del  self.PO_LOOKUP_TABLE[po]

    def _server_generate_auth_code(self,software_code, po_number):
        # Simulate server looking up PO number and selecting license type


        license_key=self. _server_lookup_license_key(po_number)
        print(f"you new license key is {license_key}")
        if license_key not in self._system_license_type:
            return None
       
        # Combine software code and license key to create auth code
        combined = software_code + license_key + po_number[-2:]
        auth_code = hashlib.sha256(combined.encode()).hexdigest()
       
        # Encode to make it transmittable
        return base64.b64encode((auth_code + ":" + license_key+ ":"+po_number[-2:]).encode()).decode()


# Main program
def main():
            license_generetor=_DVLicGenerator_()
            print("What you want to do ? ")
            po=input("Please input your purchase order:")
            if po not in license_generetor.PO_LOOKUP_TABLE:
                 while True:
                     license_key =input("PO not existed in system , Please input your licensne key type:")
                     if license_key  in license_generetor._system_license_type:
                        break
                     
                 license_generetor.add_PO(po,license_key)
            auth_license_key=license_generetor._server_lookup_license_key(po)
            print(f"you auth license key is {auth_license_key}")
            software_code=input("Please input your software_code:")
            auth_code = license_generetor._server_generate_auth_code(software_code, po)
            print("you auth_code is :\n")
            print(auth_code)

if __name__ == "__main__":
    main()
  