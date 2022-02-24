# howmail

This is a simple webservice that provides mail server information for a domain.
It queries MX records from DNS. If a domain is not an ETLD+1, it will also
provide results for that domain too.

If you would like an API, you can query DNS yourself. This is intended for
human consumption only.
