Wordpress-SRP
=============

#### WARNING: This module is in heavy development and not ready for production servers. 

Why SRP
--------------

Most web applications use simple login forms, transmitting users' passwords as plain text over unencrypted connections. These communiques can be easily intercepted. The most popular way to secure this communication is to add an SSL/TLS certificate to the web server to enable a secure connection between the web browser clients and the server -- this is seen in the address bar as starting with "https://", with most browsers offering additional information about the certificate.

Secure Remote Protocol (SRP) gets around this problem by never transmitting the password to the server. Instead, the browser uses JavaScript to derive /password verifiers/ that are sent to the server. The server responds with its own verifiers. The server- and client-side cryptography that follows confirms that the user's password is correct. 

The important part is that the server never knows the users password. SRP is an important step in bringing about Zero-confidence Web Applications, that is, the user is not forced to trust the remote server with their password. If the remote server is compromised, your password can never be derived. Additionally, if the verifier keys are used to encrypt data on the server, your personal data will always be safe from interception, sniffing, etc. The only way to decrypt the data is to know your password.

This idea of controlling transmission and knowledge of your login secret (password) is important as our world walks towards more SAAS and cloud-hosted services. Users, not vendors, should control their data.


Login framework for WordPress
---------------

[WordPress][wordpress] is one of the most prolific blogging platforms available today. Because of its wide usage, it is the target of many hackers. WordPress already includes reasonable security measures such as encrypting its users' passwords and strictly managing file permissions. Plugins provide even more - I highly recommend checking out [Better WP Security][wpsec].

The login page for WordPress still suffers from the same vulnerability that other web apps do -- the password is transmitted in plain text to the server. While many techies might propose simply adding SSL certificates, some users may not have that option, host in a single-IP configuration, or not have the technical skill to do so. The goal of the WordPress SRP project is to easily replace WordPress's built-in authentication with a JavaScript-based SRP login. For more recent browsers, this will allow a much more secure way to login to WordPress installations.

<em>Credit: Much original code and ideas were derived from sqs's project [WordPress TLS-SRP Authentication][ghtls].</em>


More Links
===============

* [Stanford's initial recommendation][stanford], first developed in 1999
* [SRP on Wikipedia][wiki]
* SRP [explained in layman terms][so] on StackOverflow


[wordpress]: http://wordpress.org/ "WordPress Blog Tool"
[wpsec]: http://wordpress.org/extend/plugins/better-wp-security/ "Better WP Security: WordPress Plugin"
[ghtls]: https://github.com/sqs/wordpress-tls-srp-authentication/ "WordPress TLS-SRP Authentication"
[stanford]: http://srp.stanford.edu/ "Stanford SRP Homepage"
[wiki]: http://en.wikipedia.org/wiki/Secure_Remote_Password_protocol "Secure Remote Password Protocol"
[so]: http://stackoverflow.com/questions/4638967/secure-remote-password-srp-in-laymen-terms "SRP in Laymen Terms"
