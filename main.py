"""
This is an add-on to search a document for PII create private annotations on what pages these exist on, it will additionally alert you to sensitive PII like social security numbers, IBANs, or credit card numbers by sending you an e-mail when one is detected.  
"""
from documentcloud.addon import AddOn
from commonregex import CommonRegex
import requests

class Detector(AddOn):
    def main(self):
        alert = self.data.get('alert')
        detect_PII = False

        detect_address = self.data.get('address')
        detect_dob = self.data.get('dob')
        detect_email = self.data.get('email')
        detect_phone = self.data.get('phone')
        detect_zip = self.data.get('zip')
        
        dob_detection = ['dob', 'DOB', 'DOB:', 'dob:']
        ssn_detection = ['ssn', 'SSN', 'SSN:', 'ssn:'] 
        
        for document in self.get_documents():
            for page in range(1,document.pages+1):
                # Extract a page of text & parse it with CommonRegex
                text=document.get_page_text(page)
                parsed_text = CommonRegex(text)

                # Generate mandatory PII Detection List
                ssn_list = parsed_text.ssn_number
                # ssn_list = list(set(CR.ssn_number(text)))
                cc_list = parsed_text.credit_cards
                # cc_list = list(set(CR.credit_cards(text)))
                
                address_list = []
                email_list = []
                phone_list = []
                zipcode_list = []  
                
                # Pull page position JSON data. 
                positions = document.get_page_position_json(page)
                
                # If the optional detection categories are marked, the lists are generated. 
                if detect_address is True:
                    address_list = address_list + list(set(parsed_text.street_addresses)) + list(set(parsed_text.po_boxes))
                if detect_email is True:
                    email_list = email_list + list(set(parsed_text.emails))
                if detect_phone is True:
                    phone_list = phone_list + list(set(parsed_text.phones)) + list(set(parsed_text.phones_with_exts))
                    phone_list = list(set(phone_list))
                if detect_zip is True:
                    zipcode_list = zipcode_list + list(set(parsed_text.zip_codes)) 
              
                # Catches possible SSN fields by field detection. If DOB detection is toggled on, it will field detect for DOB as well. 
                for info in positions:
                    if any(x in info['text'] for x in ssn_detection):
                        document.annotations.create(f"Possible SSN found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                        detect_PII = True
                    if detect_dob is True:
                       if any(x in info['text'] for x in dob_detection):
                            document.annotations.create(f"Possible DOB found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            detect_PII = True

                # Catches SSN values by regex detection if not caught by field detection.
                for ssn in ssn_list:
                    for info in positions:
                       if ssn in info['text']:
                            document.annotations.create(f"SSN found",page-1,x1=info["x2"]-0.08,y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            detect_PII = True

                # Catches CC values by regex detection
                for cc in cc_list:
                    for info in positions:
                        if cc[-4:] in info['text']:
                            document.annotations.create("CC Found", page-1, x1=info["x2"]-0.13,y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            detect_PII = True

                # Catches emails by regex detection
                for email in email_list:
                    for info in positions:
                        if email in info['text']:
                            document.annotations.create(f"Email found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            detect_PII = True

                # Catches phone numbers by regex detection
                for phone in phone_list:
                    for info in positions:
                        if phone in info['text']:
                            document.annotations.create(f"Phone # found",page-1,x1=info['x1'],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            positions.remove(info)
                            detect_PII = True
                        elif phone[-4:] in info['text']:
                            document.annotations.create(f"Phone # found",page-1,x1=info['x2']-0.09,y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            positions.remove(info)
                            detect_PII = True

                # Catches addresses by regex detection
                for address in address_list:
                    document.annotations.create("Address found on this page", page-1, content=address)
                    detect_PII = True

                # Catches zip codes by regex detection
                for zipcode in zipcode_list:
                    for info in positions:
                        if zipcode in info['text']:
                            document.annotations.create(f"Zip Code Found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
        
        # If the user selected to be alerted and PII was detected in the document, then an email alert will be sent. 
        if alert and detect_PII is True:
            self.send_mail("PII Detected", f"Personally identifying information was found in {document.canonical_url} please open the document to view more detail.")
       
if __name__ == "__main__":
    Detector().main()
