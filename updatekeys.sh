#!/bin/sh

rm testring.pgp testring.pgp.rev testimport.pgp testimport.pgp.rev testcertimport.pgp
sq key generate --userid="Testi McTest" --userid="<testi@test.com>" --export=testring.pgp
sq key generate --userid="Bubba Blue" --userid="<bubba@shrimps.com>" --export=testimport.pgp
sq key extract-cert --output=testcertimport.pgp testimport.pgp

# lets create some encrypted keys
# rm secret.pgp secret.pgp.rev encrypted.pgp
# sq key generate --userid="Testi McTest" --userid="<testi@test.com>" --export=secret.pgp
# This doesn't work since we need to set the password, we need a tool that takes password
# from the terminal
# sq key password < secret.pgp > encrypted.pgp
