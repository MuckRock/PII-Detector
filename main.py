"""
This is an add-on to search a document for credit cards and social security numbers and create annotations on what pages these exist on. 
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
                for cc in cc_list:
                    document.annotations.create("CC Found", (page-1), content=cc)
                for iban in iban_list:
                    document.annotations.create("IBAN # Found", (page-1), content=iban)
           
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
