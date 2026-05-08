# Test PII Document

## Personal info
Hello, my name is Jane Doe. I live in Springfield, USA, and I work for ACME. My personal email is jane.doe@example.com and my work email is jane.doe@acme.example. You can reach me on +1 555 123 45 67 or 555-123 45 67.

## Family
My partner is Mary Smith. My brother John Doe lives in Riverside with his wife Linda. My sister Anna Doe lives in Lakeside with her husband Mark. My nephew Adam is twelve. My niece Eve turns nine in June.

## Friends mentioned in passing
Caroline Bartholomew (also "Carrie") will pick up Mary in Riverside on Wednesday. Alex from work is on parental leave. Rita and Tom are coming to the party.

## Government IDs
Swedish personnummer: 850712-1234
US SSN equivalent (test): 123-45-6789
Driver's license number: SE-DL-99887766

## Financial
Credit card 4111 1111 1111 1111, expires 12/27, CVV 123.
Swedish bank account: Nordea 1234 56 78901
IBAN: GB29 NWBK 6016 1331 9268 19
Stripe customer id: cus_NffrFeUfNV2Hib

## Tokens / API keys (fake)
GitHub token: ghp_abcdefghijklmnopqrstuvwxyz0123456789
OpenAI key: sk-proj-AbC123dEf456GhI789jKl0mNo1pQ2rS3tU4vW5xY6zA7
Stripe secret: sk_test_4eC39HqLyjWDarjtT1zdp7dcabcdefghijklmnop
AWS key id: AKIAIOSFODNN7EXAMPLE
JWT-ish: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abc123def

## Addresses
Hemvägen 12, 441 30 Storby
1 Apple Park Way, Cupertino, CA 95014, USA

## URLs / IPs
Personal site: https://example.com
LinkedIn: https://www.linkedin.com/in/jane-doe/
GitHub: https://github.com/janedoe
Home IP: 192.168.1.42
Public IP: 81.226.119.45
IPv6: 2001:db8::8a2e:370:7334

## Dates of birth
Jane: 1980-04-15
Mary: 1982-09-23

## License plates / VIN
Car plate: ABC 123
VIN: 1HGBH41JXMN109186

## Edge cases
- Name in middle of sentence: "Yesterday Caroline Bartholomew and Jane Doe drove to Riverside."
- Name with title: "Dr. Mary Smith reviewed the chart."
- All-caps name: "JANE DOE"
- Lowercase name: "jane doe"
- Name in URL: "janedoe.example"
- Name as filename: "jane_doe_resume.pdf"
- Phone in parens: "(call me at (555) 123-4567)"
- Phone international: "+1-555-123-0100"
- Email obfuscated: "jane [dot] doe [at] example [dot] com"
- SSN with no hyphens: "123456789"
- Two emails on one line: "jane.doe@example.com and jane.doe@acme.example"
- Mixed: "Reach Mary at mary.smith@example.com or +1 555 123 88 77."
- Quoted name: "She said, 'I'm Jane,' and walked off."
- Name followed by punctuation: "Jane! Jane? Jane, Jane."
- Bare first name only: "Jane made dinner."
- Bare surname only: "Doe arrived first."
- Possessive: "Jane's keys are on Mary's desk."
- Ambiguous (could be name or word): "The doe of the matter..."

## Multilingual edge cases
- Swedish: "Jag heter Jane Doe och bor på Hemvägen 12 i Storby."
- Norwegian: "Jeg heter Jane Doe."
- Mixed text: "Mary said hej to her bror."

## Places that might overlap with names
- Springfield, Riverside, Lakeside, Westview, Eastfield, Northbrook, Southbay
- "I went to Jane's, then to Mary's."

End of test document.
