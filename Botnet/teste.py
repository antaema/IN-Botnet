import ifcfg
import json

for name, interface in ifcfg.interfaces().items():
    # do something with interface
    print interface['device']
    print interface['inet']
    print interface['inet6']
    print interface['netmask']
    print interface['broadcast']

default = ifcfg.default_interface()