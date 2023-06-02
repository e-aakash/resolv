## DNS Spec: https://datatracker.ietf.org/doc/html/rfc1035

User/user program interacts with resolver, which queries foreign name servers (NS) to answer the query. There can be many queries to NS, and can take arbitrarily long.

The following syntax will result in fewer problems with many applications that use domain names (e.g., mail, TELNET).

```
<domain> ::= <subdomain> | " "
<subdomain> ::= <label> | <subdomain> "." <label>
<label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]
<ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
<let-dig-hyp> ::= <let-dig> | "-"
<let-dig> ::= <letter> | <digit>
<letter> ::= any one of the 52 alphabetic characters A through Z in
upper case and a through z in lower case
<digit> ::= any one of the ten digits 0 through 9
```

Note that while upper and lower case letters are allowed in domain names, no significance is attached to the case.  That is, two names with the same spelling but different case are to be treated as if identical.

Labels must be 63 characters or less.

### Limits

- labels          63 octets or less

- names           255 octets or less

- TTL             positive values of a signed 32 bit number.

- UDP messages    512 octets or less


### Format

https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.1

### Message format

https://datatracker.ietf.org/doc/html/rfc1035#section-4.1

All messages contain header
