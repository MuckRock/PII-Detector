"""
This is an add-on to search a document for PII create private annotations on what pages these exist on, it will additionally alert you to sensitive PII like social security numbers, IBANs, or credit card numbers by sending you an e-mail when one is detected.  
"""
from documentcloud.addon import AddOn
import commonregex as CommonRegex

class Detector(AddOn):
    def main(self):
        detect_address = self.data.get('address')
        detect_phone = self.data.get('phone')
        detect_email = self.data.get('email')
        
        for document in self.get_documents():
            for page in range(1,document.pages+1):
                text=document.get_page_text(page)
                ssn_list = CommonRegex.ssn_numbers(text)
                cc_list = CommonRegex.credit_cards(text)
                iban_list = CommonRegex.iban_numbers(text)
                
                for ssn in ssn_list:
                    document.annotations.create("SSN Found", (page-1), content=ssn)
                    self.send_mail("Sensitive PII Detected", f"SSN found in {document.canonical_url} on page # {page}")
                for cc in cc_list:
                    document.annotations.create("CC Found", (page-1), content=cc)
                    self.send_mail("Sensitive PII Detected", f"Credit Card # found in {document.canonical_url} on page # {page}") 
                for iban in iban_list:
                    document.annotations.create("IBAN # Found", (page-1), content=iban)
                    self.send_mail("Sensitive PII Detected", f"IBAN # found in {document.canonical_url} on page # {page}")
           
                if detect_email is True:
                    email_list = CommonRegex.emails(text)
                    for email in email_list:
                        document.annotations.create("Email Found", (page-1), content=email)
                if detect_phone is True:
                    phone_list = CommonRegex.phones(text)
                    phone_with_ext_list = CommonRegex.phones_with_exts(text)            
                    for phone in phone_list:
                        document.annotations.create("Phone # Found", (page-1), content=phone)
                    for phone_with_ext in phone_with_ext_list:
                        document.annotations.create("Phone # Found", (page-1), content=phone_with_ext)
                if detect_address is True:
                    address_list = CommonRegex.street_addresses(text)
                    for address in address_list:
                        document.annotations.create("Address Found", (page-1), content=address)
                
if __name__ == "__main__":
    Detector().main()
