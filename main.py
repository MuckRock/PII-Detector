"""
This is an add-on to search a document for a regex and output all of the matches
"""

import csv
import re

from documentcloud.addon import AddOn


class Regex(AddOn):
    def main(self):
        if not self.documents:
            self.set_message("Please select at least one document")
            return

        # patterns that are passed as parameters
        # to this add-on when we run it.
        pattern_list = self.data["regex"]

        # patterns that are available in the neighbor CSV file.
        with open("patterns.csv", "r+") as pattern_file:
            csvreader = csv.reader(pattern_file)
            for row in csvreader:
                pattern_list.append(row[0])

        # ensure that there is at fewest 1 pattern to search for.
        if len(pattern_list) < 1:
            self.set_message("Please provide at least one regular expression.")
            return

        # list matches in an output CSV file record.
        with open("matches.csv", "w+") as file_:

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


if __name__ == "__main__":
    Regex().main()
