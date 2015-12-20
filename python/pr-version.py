#!/usr/bin/env python

import getdns

ctx = getdns.Context()
print("getdns library version : %s" % 
      ctx.get_api_information()['version_string'])
print("python bindings version: %s" % getdns.__version__)
