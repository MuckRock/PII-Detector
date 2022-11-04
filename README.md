
# DocumentCloud Multiple Regex with Defaults Add-On

With this DocumentCloud Add-On one can use multiple Regular Expressions (Regex) as parameters and find all examples of those patterns in the specified documents. The Regex's are passed as parameters to the main.py script.

The add-on is an extension of "multiple-regex-pattern". In addition to the ability to pass regular expressions to the script on invocation,
this add-on has a default list of regular expressions that are always used and match to an assortment of potential examples of 
personally identifiable and confidential information.

The output of this add-on is a CSV of all of the incidences of patterns matching text in the documents specified.

Included are a couple of patterns for typical Personally Identifiable Information such as Credit Card Number, SSN, and Telephone Number.

### Included patterns in order:
ref: https://digitalfortress.tech/tips/top-15-commonly-used-regex/

- Credit card numbers
- Common phone number formats
- Social Security Number
- Common email format
- Uncommon email format
- IPv4 IP address
- IPv6 IP address
- Passport Number
