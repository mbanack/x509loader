x509loader
==========

Test go library loading of clientAuth SSL certs


Certs generated with the following:
<pre>
openssl req -new -x509 -days 3650 -extensions v3_ca -keyout ca.key -out ca.crt
openssl req -passout pass:garbage -new -keyout client.pass.key -out client.csr
openssl rsa -passin pass:garbage -in client.pass.key -out client.key
openssl x509 -req -in client.csr -out client.crt -signkey client.key -CA ca.crt -CAkey ca.key -CAcreateserial -days 365
openssl x509 -req -in client.csr -out client.clientAuth.crt -signkey client.key -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -addtrust clientAuth
</pre>
