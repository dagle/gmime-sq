#!/bin/sh

rm testring.pgp testring.pgp.rev testimport.pgp testimport.pgp.rev testcertimport.pgp
sq key generate --userid="Testi McTest" --userid="<testi@test.com>" --export=testring.pgp
sq key generate --userid="Bubba Blue" --userid="<bubba@shrimps.com>" --export=testimport.pgp
sq key extract-cert --output=testcertimport.pgp testimport.pgp
