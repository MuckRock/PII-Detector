"""
This is an add-on to search a document for PII create private annotations on what pages these exist on, it will additionally alert you to sensitive PII like social security numbers, IBANs, or credit card numbers by sending you an e-mail when one is detected.  
"""
from documentcloud.addon import AddOn
import commonregex as CR
import requests

class Detector(AddOn):
    def main(self):
        alert = self.data.get('alert')
        detect_PII = False

        detect_address = self.data.get('address')
        detect_email = self.data.get('email')
        detect_phone = self.data.get('phone')
        detect_zip = self.data.get('zip')
        
        for document in self.get_documents():
            for page in range(1,document.pages+1):
                # Extract a page of text
                text=document.get_page_text(page)
                parsed_text = CR(text)
                # Generate mandatory PII Detection List
                ssn_list = parsed_text.ssn_number
                # ssn_list = list(set(CR.ssn_number(text)))
                cc_list = parsed_text.credit_cards
                # cc_list = list(set(CR.credit_cards(text)))
                # iban_list = list(set(CR.iban_numbers(text)))

                # Pull page position JSON data. 
                positions = document.get_page_position_json(page)
                
                # If the optional detection categories are marked, the lists are generated. 
                if detect_address is True:
                    address_list = address_list + list(set(parsed_text.street_addresses)) + list(set(parsed_text.po_boxes))
                    # address_list = address_list + CR.street_addresses(text) + CR.po_boxes(text)
                    for i in address_list:
                        print(i)
                if detect_email is True:
                    email_list = email_list + list(set(parsed_text.emails))
                    # email_list = email_list + list(set(CR.emails(text)))
                if detect_phone is True:
                    # phone_list = phone_list + CR.phones(text) + CR.phones_with_exts(text)
                    phone_list = phone_list + list(set(parsed_text.phones)) + list(set(parsed_texts.phones_with_exts))
                    phone_list = list(set(phone_list))
                if detect_zip is True:
                    zipcode_list = parsed_text.zip_codes
                    # zipcode_list = CR.zip_codes(text)
              
                for ssn in ssn_list:
                    for info in positions:
                       if ssn in info['text']:
                            document.annotations.create(f"SSN found",page-1,x1=info["x2"]-0.08,y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            detect_PII = True
                for cc in cc_list:
                    for info in positions:
                        if cc[-4:] in info['text']:
                            document.annotations.create("CC Found", page-1, x1=info["x2"]-0.13,y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            detect_PII = True
                """for iban in iban_list:
                    for info in positions:
                        if iban in info['text']:
                            document.annotations.create("IBAN # Found", page-1, x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            detect_PII = True"""
                for email in email_list:
                    for info in positions:
                        if email in info['text']:
                            document.annotations.create(f"Email found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            detect_PII = True
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
                for address in address_list:
                    document.annotations.create("Address found on this page", page-1, content=address)
                    detect_PII = True
                for zipcode in zipcode_list:
                    for info in positions:
                        if zipcode in info['text']:
                            document.annotations.create(f"Zip Code Found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                
        if alert and detect_PII is True:
            self.send_mail("PII Detected", f"Personally identifying information was found in {document.canonical_url} please open the document to view more detail.")
       
if __name__ == "__main__":
    Detector().main()
