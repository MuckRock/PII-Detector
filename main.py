"""
This is an add-on to search a document for PII.
It will create private annotations on pages PII exists on.
"""
import json
import logging
from commonregex import CommonRegex
from documentcloud.addon import AddOn
from documentcloud.exceptions import APIError, DoesNotExistError

import crim as CR


class Detector(AddOn):
    """Detector AddOn class which has methods you can call"""
    logging.basicConfig(level=logging.ERROR)
    document_detected = []
    document_failures = []
    def address_detect(self, document, page, text):
        """Catches addresses by regex detection"""
        self.set_message("Detecting addresses in the document...")
        address_set = set(CR.street_addresses(text)) | set(CR.po_boxes(text))
        for address in address_set:
            try:
                document.annotations.create(
                    "Address found on this page", page - 1, content=address, access=self.data.get('access')
                )
            except APIError as e:
                logging.error("API Error: %s", e)

            if document.canonical_url not in self.document_detected:
                self.document_detected.append(document.canonical_url)
            if self.data.get("project_id"):
                project = self.client.projects.get(self.data.get("project_id"))
                if document not in project.document_list:
                    project.document_list.append(document)
                    project.put()

    def detect(self, name, document, page, parsed, positions):
        """Method to detect different types of regex"""
        self.set_message(f"Detecting {name} information in the document...")
        for word in set(parsed):
            for info in positions:
                # is it important to do an in comparison here instead of equal?
                if word in info["text"] and 1>=info["x1"]>=0.0 and 1>=info["y1"]>=0.0 and 1>=info["x2"]>=0.0 and 1>=info["y2"]>=0.0:
                    try:
                        document.annotations.create(
                            f"{name} found",
                            page - 1,
                            access=self.data.get('access'),
                            x1=info["x1"],
                            y1=info["y1"],
                            x2=info["x2"],
                            y2=info["y2"],
                        )
                    except APIError as e:
                        logging.error("API Error: %s", e)

                    # remove from positions to not create multiple annotations
                    # on one word
                    positions.remove(info)
                    if document.canonical_url not in self.document_detected:
                        self.document_detected.append(document.canonical_url)
                    if self.data.get("project_id"):
                        project = self.client.projects.get(self.data.get("project_id"))
                        if document not in project.document_list:
                            project.document_list.append(document)
                            project.put()

    data_types = [
        # This contains the information needed to check for each type of PII
        # There is one 4-tuple for each type of data:
        # * Data name - the name of the boolean flag to fetch from self.data to enable
        #   this check
        # * Name - used in messages and emails to the user about this data
        # * Attribute name - The attribute name that corresponds to this data
        #   on the parsed text object returned from the common regex parser
        # * Transformer - Function which transform the list of items returned
        #   by the common regex parser before checking them against the word
        #   position file
        (
            "credit card",
            "Credit card",
            "credit_cards",
            lambda x: [c[-4:] for c in x],
        ),
        ("email", "Email", "emails", lambda x: x),
        ("phone", "Phone number", "phones", lambda x: x + [p[-4:] for p in x]),
        ("ssn", "SSN", "ssn_number", lambda x: x),
        ("ssn", "Posible SSN", "", lambda x: ["SSN", "ssn"]),
        ("zip", "Zip code", "zip_codes", lambda x: x),
    ]

    def main(self):
        """Will run the detection methods based on selection by the user"""
        if self.get_document_count() is None:
            self.set_message("Please select at least one document.")
            return
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
                except json.decoder.JSONDecodeError:
                    if document.canonical_url not in self.document_failures:
                        self.document_failures.append(document.canonical_url)
                except DoesNotExistError as d:
                    logging.error("API Error: %s", d)
                    self.set_message(
                        f"No text positions file found- document {document.id} needs"
                        "to be OCR'd before running this Add-On"
                    )
                    continue
                else:
                    # If the optional detection categories are marked, the lists are generated.
                    if self.data.get("address"):
                        self.address_detect(document, page, text)
                    for data, name, attr, transform in self.data_types:
                        if self.data.get(data):
                            parsed = transform(getattr(parsed_text, attr, None))
                            self.detect(name, document, page, parsed, text_positions)
        self.set_message("Completed PII detection")

        # Send email if alert is true and PII was detected
        if alert and self.document_detected:
            detected_prefix = "PII Detected in the following documents:\n"
            detected_list = "\n".join(self.document_detected)
            detected_msg = detected_prefix + detected_list
            self.send_mail("PII Detection Summary", detected_msg)

        if self.document_failures:
            failure_prefix = (
                "\nThe following documents do not have a word position file. \n"
                "You will need to select Edit -> Force Reprocess "
                "to generate the word position file "
                "and then run the Add-On again. \n"
            )
            failure_list = "\n".join(self.document_failures)
            failure_msg = failure_prefix + failure_list
            self.send_mail("PII Detection Failure", failure_msg)


if __name__ == "__main__":
    Detector().main()
