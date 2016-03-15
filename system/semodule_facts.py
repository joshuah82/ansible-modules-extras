#!/usr/bin/python

# (c) 2016, Joshua Heilman <joshuah82@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: semodule_facts
short_description: Gather facts about SELinux policy modules.
description:
     - Gather facts about SELinux policy modules.
version_added: '2.0'
options:
  name:
    description:
      - Name of the module to gather facts about
    required: false
    default: null
  names:
    description:
      - List of names of the modules to gather facts about
    required: false
    default: null
requirements: [ 'policycoreutils-python' ]
author: "Joshua Heilman <joshuah82@gmail.com>"
'''

EXAMPLES = '''
# Gather facts about the xen policy module
- semodule_facts: name=xen

# Gather facts about the mysql and xen policy modules
- semodule_facts:
    names:
      - mysql
      - xen

# Gather facts about all policy modules
- action: semodule_facts
'''

def get_module_facts(module, obj, *names):
    module_facts = {}
    for mod in obj.get_all():
        if mod[0] in names:
            module_facts[mod[0]]['version'] = mod[1]
            module_facts[mod[0]]['enabled'] = bool(mod[2])

    return module_facts

try:
    import seobject
    HAS_POLICYCOREUTILS = True
except ImportError:
    HAS_POLICYCOREUTILS = False

def main():
    module = AnsibleModule(
        argument_spec = dict(
            name  = dict(type='str',  required=False, default=None),
            names = dict(type='list', required=False, default=None),
        ),
        supports_check_mode=True
    )

    if not HAS_POLICYCOREUTILS:
        module.fail_json(msg='This module requires policycoreutils-python support')

    name  = module.params['name']
    names = module.params['names']

    try:
        obj = seobject.moduleRecords(store)

        if name != None:

    except Exception, e:
        # Primarily catching ValueErrors from this and the seobject module, but
        # keeping the scope wide just in case. ValueErrors provided by seobject
        # are fairly specific and useful.
        module.fail_json(msg='Failed to manage module %s: %s' % (name, str(e)))

    module.exit_json(changed=changed)

# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
