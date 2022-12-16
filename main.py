"""
This is an add-on to search a document for PII.
It will create private annotations on pages PII exists on.
It will additionally alert you to sensitive PII like social security numbers or credit card numbers
by sending you an e-mail when one is detected.
"""
import json
import crim as CR
from commonregex import CommonRegex
from documentcloud.addon import AddOn

class Detector(AddOn):
    """Detector AddOn class which has methods you can call"""
    detect_pii = False
    def address_detect(self, document, page, text):
        """Catches addresses by regex detection"""
        address_list = []
        address_list = (address_list+
                            list(set(CR.street_addresses(text)))
                            +list(set(CR.po_boxes(text))))
        for address in address_list:
            document.annotations.create(
                "Address found on this page", page - 1, content=address
            )
            self.detect_pii = True

    def credit_card_detect(self, document, page, parsed, positions):
        """Catches credit_card values by regex detection"""
        credit_card_list = parsed.credit_cards
        for credit_card in credit_card_list:
            for info in positions:
                if credit_card[-4:] in info["text"]:
                    document.annotations.create(
                        "credit_card Found",
                        page - 1,
                        x1=info["x1"],
                        y1=info["y1"],
                        x2=info["x2"],
                        y2=info["y2"],
                    )
                    self.detect_pii = True

    def dob_detect(self, document, page, positions):
        """Uses basic DOB field detection"""
        dob_detection = ['dob', 'DOB', 'DOB:', 'dob:']
        for info in positions:
            if any(x in info["text"] for x in dob_detection):
                document.annotations.create(
                    "Possible DOB found",
                    page - 1,
                    x1=info["x1"],
                    y1=info["y1"],
                    x2=info["x2"],
                    y2=info["y2"],
                )
                self.detect_pii = True

    def email_detect(self, document, page, parsed, positions):
        """Catches emails by regex detection"""
        email_list = []
        email_list = email_list + list(set(parsed.emails))
        for email in email_list:
            for info in positions:
                if email in info["text"]:
                    document.annotations.create(
                        "Email found",
                        page - 1,
                        x1=info["x1"],
                        y1=info["y1"],
                        x2=info["x2"],
                        y2=info["y2"],
                    )
                    self.detect_pii = True

    def phone_detect(self, document, page, parsed, positions):
        """Catches phone numbers by regex detection"""
        phone_list = []
        phone_list = phone_list + list(set(parsed.phones))
        for phone in phone_list:
            for info in positions:
                if phone in info["text"]:
                    document.annotations.create(
                        "Phone # found",
                        page - 1,
                        x1=info["x1"],
                        y1=info["y1"],
                        x2=info["x2"],
                        y2=info["y2"],
                    )
                    positions.remove(info)
                    self.detect_pii = True
                elif phone[-4:] in info["text"]:
                    document.annotations.create(
                        "Phone # found",
                        page - 1,
                        x1=info["x1"],
                        y1=info["y1"],
                        x2=info["x2"],
                        y2=info["y2"],
                    )
                    positions.remove(info)
                    self.detect_pii = True

    def ssn_detect(self, document, page, parsed, positions):
        """Catches possible SSNs using field detection and regex detection"""
        ssn_list = parsed.ssn_number
        ssn_detection = ["ssn", "SSN", "SSN:", "ssn:"]
        for info in positions:
            if any(x in info["text"] for x in ssn_detection):
                document.annotations.create(
                    "Possible SSN found",
                    page - 1,
                    x1=info["x1"],
                    y1=info["y1"],
                    x2=info["x2"],
                    y2=info["y2"],
                )
                self.detect_pii = True
        #Catches SSN values by regex detection.
        for ssn in ssn_list:
            for info in positions:
                if ssn in info["text"]:
                    document.annotations.create(
                        "SSN found",
                        page - 1,
                        x1=info["x1"],
                        y1=info["y1"],
                        x2=info["x2"],
                        y2=info["y2"],
                    )
                    self.detect_pii = True

    def zipcode_detect(self, document, page, parsed, positions):
        """Catches zip codes by regex detection"""
        zipcode_list = []
        zipcode_list = zipcode_list + list(set(parsed.zip_codes))
        for zipcode in zipcode_list:
            for info in positions:
                if zipcode in info["text"]:
                    document.annotations.create(
                        "Zip Code Found",
                        page - 1,
                        x1=info["x1"],
                        y1=info["y1"],
                        x2=info["x2"],
                        y2=info["y2"],
                    )
                    self.detect_pii = True

    def main(self):
        """Will run the detection methods based on selection by the user"""
        alert = self.data.get("alert")
        for document in self.get_documents():
            for page in range(1, document.pages + 1):
                # Extract a page of text & parse it with CommonRegex
                text = document.get_page_text(page)
                parsed_text = CommonRegex(text)

                # Tries to pull page position JSON data and run the detection methods.
                # Some older documents will throw a JSON Decode Error,
                # So they will need to be re-processed before the Add-On can run.
                try:
                    text_positions = document.get_page_position_json(page)
                    # If the optional detection categories are marked, the lists are generated.
                    if self.data.get("address") is True:
                        self.address_detect(document, page, text)
                    if self.data.get("credit_card") is True:
                        self.credit_card_detect(document, page, parsed_text, text_positions)
                    if self.data.get("dob") is True:
                        self.dob_detect(document, page, text)
                    if self.data.get("email") is True:
                        self.email_detect(document, page, parsed_text, text_positions)
                    if self.data.get("phone") is True:
                        self.phone_detect(document, page, parsed_text, text_positions)
                    if self.data.get("zip") is True:
                        self.zipcode_detect(document, page, parsed_text, text_positions)
                except json.decoder.JSONDecodeError:
                    self.set_message(
                        "The document you tried to run must be force re-processed in order for this Add-On to work"
                    )

                # If the user selected to be alerted and PII is detected
                # an email alert will be sent.
                if alert and self.detect_pii is True:
                    self.send_mail(
                        "PII Detected",
                        f"Personally identifying information was found in {document.canonical_url} please open the document to view more detail.",
                    )


if __name__ == "__main__":
    Detector().main()
