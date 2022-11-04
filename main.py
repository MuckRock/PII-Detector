"""
This is an add-on to search a document for credit cards and social security numbers and create annotations on what pages these exist on. 
"""
from documentcloud.addon import AddOn
import commonregex as CommonRegex

class Detector(AddOn):
    def main(self):
        if not self.documents:
            self.set_message("Please select at least one document")
            return
 
        for document in self.get_documents(): 
            for page in range(1,document.pages+1):
                text=document.get_page_text(page)
                ssn_list = CommonRegex.ssn_numbers(text)
                cc_list = CommonRegex.credit_cards(text)
                
                for ssn in ssn_list:
                    document.annotations.create("SSN Found", (page-1), content=ssn_list[ssn].text)
          
        # list matches in an output CSV file record.
        """ with open("matches.csv", "w+") as file_:

            writer = csv.writer(file_)
            writer.writerow(["pattern", "match", "url"])

            # find all examples of each supplied pattern.
            for regex_pattern in pattern_list:
                pattern = re.compile(regex_pattern)

                for document in self.client.documents.list(id__in=self.documents):
                    writer.writerows(
                        [regex_pattern, m, document.canonical_url]
                        for m in pattern.findall(document.full_text)
                    )

            self.upload_file(file_)
            """ 

if __name__ == "__main__":
    Detector().main()
