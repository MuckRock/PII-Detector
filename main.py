"""
This is an add-on to search a document for PII create private annotations on what pages these exist on, it will additionally alert you to sensitive PII like social security numbers, IBANs, or credit card numbers by sending you an e-mail when one is detected.  
"""
from documentcloud.addon import AddOn
import crim as CR
from listcrunch import uncrunch
import requests

class Detector(AddOn):
    def main(self):
        detect_address = self.data.get('address')
        detect_phone = self.data.get('phone')
        detect_email = self.data.get('email')
        detect_PII = False
        alert = self.data.get('alert')
        
        for document in self.get_documents():
            for page in range(1,document.pages+1):
                text=document.get_page_text(page)
                ssn_list = list(set(CR.ssn_numbers(text)))
                cc_list = list(set(CR.credit_cards(text)))
                iban_list = list(set(CR.iban_numbers(text)))
                positions = document.get_page_position_json(page)
              
                for cc in cc_list:
                    for info in positions:
                        if cc[-4] in info['text']:
                            document.annotations.create("CC Found", page-1, x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            detect_PII = True
                
                for iban in iban_list:
                    for info in positions:
                        if iban in info['text']:
                            document.annotations.create("IBAN # Found", page-1, x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            detect_PII = True

                if detect_email is True:
                    email_list = CR.emails(text)
                    email_list = list(set(email_list))
                    for email in email_list:
                        for info in positions:
                            if email in info['text']:
                                document.annotations.create(f"Email found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                                detect_PII = True

                if detect_phone is True:
                    phone_list = CR.phones(text) + CR.phones_with_exts(text)
                    phone_list = list(set(phone_list))
                    for phone in phone_list:
                        for info in positions:
                            if phone[-4] in info['text']:
                                document.annotations.create(f"Phone # found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                                detect_PII = True
                
                if detect_address is True:
                    address_list = CR.street_addresses(text)
                    for address in address_list:
                        document.annotations.create("Address found on this page", (page-1), content=address)
                        detect_PII = True
                     
                for ssn in ssn_list:
                    for info in positions:
                       if ssn[-4] in info['text']:
                            document.annotations.create(f"SSN found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                            detect_PII = True

        if alert and detect_PII is True:
            self.send_mail("PII Detected", f"Personally identifying information was found in {document.canonical_url} please open the document to view more detail.")
       
if __name__ == "__main__":
    Detector().main()
