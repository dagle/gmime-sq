#! /usr/bin/python3

import gi
gi.require_version("GaloreSq", "0.1")
from gi.repository import GaloreSq

sq = GaloreSq.Context.new()
print(sq.do_get_encryption_protocol(sq))
