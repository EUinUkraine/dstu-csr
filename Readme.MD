openssl req -inform DER -in melashchenko.csr -noout -pubkey

openssl dgst -sha256 -sign private-key.pem -out sign.txt.sha256 sign.txt
openssl dgst -sha256 -verify public.pem -signature sign.txt.sha256 sign.txt

openssl pkcs12 -export -out keyStore.p12 -inkey myKey.pem -in certs.pem