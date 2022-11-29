"""
This is an add-on to search a document for PII create private annotations on what pages these exist on, it will additionally alert you to sensitive PII like social security numbers, IBANs, or credit card numbers by sending you an e-mail when one is detected.  
"""
from documentcloud.addon import AddOn
import commonregex as CR
from listcrunch import uncrunch
import requests

class Detector(AddOn):
    def main(self):
        detect_address = self.data.get('address')
        detect_phone = self.data.get('phone')
        detect_email = self.data.get('email')
        send_ssn_mail = False
        send_cc_mail = False
        send_iban_mail = False
        
        for document in self.get_documents():
            for page in range(1,document.pages+1):
                text=document.get_page_text(page)
                ssn_list = CR.ssn_numbers(text)
                cc_list = CR.credit_cards(text)
                iban_list = CR.iban_numbers(text)
                url = (document.asset_url + f"documents/{document.id}/pages/" + f"{document.slug}-p{page}.position.json")
                resp = requests.get(url, timeout=10)
                positions = resp.json()
                
                for ssn in ssn_list:
                    for info in positions:
                        if ssn in info['text']:
                            document.annotations.create(f"SSN found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                
                for cc in cc_list:
                    document.annotations.create("CC Found", (page-1), content=f"Last four digits: {cc[-4:]}")
                
                for iban in iban_list:
                    document.annotations.create("IBAN # Found", (page-1), content=f"Last two digits: {iban[-2:]}")

                if detect_email is True:
                    email_list = CR.emails(text)
                    email_list = list(set(email_list))
                    for email in email_list:
                        for info in positions:
                            if email in info['text']:
                                document.annotations.create(f"Email found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])

                if detect_phone is True:
                    phone_list = CR.phones(text) + CommonRegex.phones_with_exts(text)
                    phone_list = list(set(phone_list))
                    for phone in phone_list:
                        for info in positions:
                            if phone in info['text']:
                                document.annotations.create(f"Phone # found",page-1,x1=info["x1"],y1=info["y1"],x2=info["x2"],y2=info["y2"])
                
                if detect_address is True:
                    address_list = CR.street_addresses(text)
                    for address in address_list:
                        document.annotations.create("Address found on this page", (page-1), content=address)
                                
                """text=document.get_page_text(page)
                ssn_list = CommonRegex.ssn_numbers(text)
                cc_list = CommonRegex.credit_cards(text)
                iban_list = CommonRegex.iban_numbers(text)
                for ssn in ssn_list:
                    document.annotations.create("SSN Found", (page-1), content=ssn)
                    send_ssn_mail=True
                for cc in cc_list:
                    document.annotations.create("CC Found", (page-1), content=cc)
                    send_cc_mail=True
                for iban in iban_list:
                    document.annotations.create("IBAN # Found", (page-1), content=iban)
                    send_iban_mail=True
           
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
        
        if send_cc_mail is True:
            self.send_mail("Sensitive PII Detected", f"Credit Card # found in {document.canonical_url}")
        if send_ssn_mail is True:
            self.send_mail("Sensitive PII Detected", f"SSN found in {document.canonical_url}")
        if send_iban_mail is True:
            self.send_mail("Sensitive PII Detected", f"IBAN # found in {document.canonical_url} on page # {page}")
        """
if __name__ == "__main__":
    Detector().main()
