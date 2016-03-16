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
module: semodule
short_description: Manage SELinux policy modules.
description:
     - Manage SELinux policy modules.
version_added: '2.1'
options:
  name:
    description:
      - Name of the module to configure
    required: true
  path:
    description:
      - Path to the module package
      - (required I(state) is set to C(present))
    required: false
    default: null
  state:
    description:
      - Whether a module should be C(enabled), C(disabled), installed (C(present)) or removed (C(absent)).
    required: true
    choices: [ 'enabled', 'disabled', 'present', 'absent' ]
  store:
    description:
      - Name of the policy store to use
    required: false
    default: null
requirements:
  - policycoreutils-python 2.0.83 or greater (package name differs by distro)
author: "Joshua Heilman <joshuah82@gmail.com>"
notes:
  - Tested on Ubuntu 12.04 LTS, Ubuntu 14.04 LTS, CentOS 6.7 and CentOS 7
'''

EXAMPLES = '''
# Disable the xen policy module
- semodule: name=xen state=disabled

# Enable the xen policy module
- semodule: name=xen state=enabled

# Remove the xen policy module
- semodule: name=xen state=absent

# Install the xen policy module
- semodule: name=xen path=/usr/share/selinux/default/xen.pp.bz2 state=present
'''

RETURN = '''
'''

try:
    from semanage import *
    HAS_SEMANAGE = True
except ImportError:
    HAS_SEMANAGE = False

def get_module_list(sh):
    """Return a list of all modules"""
    modules = []

    (rc, module_list, num) = semanage_module_list(sh)
    if rc < 0:
        raise ValueError('Could not list SELinux modules')

    for i in range(num):
        module = semanage_module_list_nth(module_list, i)
        modules.append((semanage_module_get_name(module), semanage_module_get_version(module), semanage_module_get_enabled(module)))

    return modules

def get_module_enabled(sh, name):
    """Return whether a module is enabled"""
    for module in get_module_list(sh):
        if module[0] == name:
            # Return enabled state
            return bool(module[2])

    raise ValueError('Could not get enabled status of module %s (not installed)' % name)

def get_module_installed(sh, name):
    """Return whether a module is installed"""
    for module in get_module_list(sh):
        if module[0] == name:
            # Module was in the module list
            return True

    # Module wasn't in the module list
    return False

def commit_change(sh):
    rc = semanage_commit(sh)
    if rc < 0:
        raise ValueError('Could not commit semanage transaction')

def main():
    module = AnsibleModule(
        argument_spec = dict(
            name       = dict(type='str',  required=True),
            path       = dict(type='str',  required=False, default=None),
            state      = dict(type='str',  required=True,  choices=[ 'enabled', 'disabled', 'present', 'absent' ]),
            store      = dict(type='str',  required=False, default='')
        ),
        required_if = [ [ 'state', 'present',  [ 'path' ] ] ],
        supports_check_mode=True
    )

    if not HAS_SEMANAGE:
        module.fail_json(msg='This module requires policycoreutils-python 2.0.83 or greater')

    name       = module.params['name']
    path       = module.params['path']
    state      = module.params['state']
    store      = module.params['store']

    # Should only ever be set to True if an semanage transaction succeeds.
    changed = False

    try:
        # Prepare a handle and connect to semanage
        sh = semanage_handle_create()
        if not sh:
            raise ValueError('Could not create semanage handle')

        if store != '':
            semanage_select_store(sh, store, SEMANAGE_CON_DIRECT)

        if not semanage_is_managed(sh):
            semanage_handle_destroy(sh)
            raise ValueError('SELinux policy is not managed or store cannot be accessed')

        if semanage_access_check(sh) < SEMANAGE_CAN_WRITE:
            semanage_handle_destroy(sh)
            raise ValueError('Cannot write policy store')

        if semanage_connect(sh) < 0:
            semanage_handle_destroy(sh)
            raise ValueError('Could not establish semanage connection')

        # Perform the task operations.
        #
        # This code is based on the seobject Python module provided in
        # policycoreutils-python 2.1.10 and up. Implementing the semanage
        # calls directly ended up providing a much wider list of supported
        # distribution releases than relying on seobject.
        if state == 'enabled':
            if not get_module_enabled(sh, name):
                if not module.check_mode:
                    need_commit = False

                    rc = semanage_module_enable(sh, name)
                    if rc < 0 and rc != -3:
                        raise ValueError('Could not enable module %s' % name)
                    if rc != -3:
                        need_commit = True

                    if need_commit:
                        commit_change(sh)

                changed = True

        elif state == 'disabled':
            if get_module_enabled(sh, name):
                if not module.check_mode:
                    need_commit = False

                    rc = semanage_module_disable(sh, name)
                    if rc < 0 and rc != -3:
                        raise ValueError('Could not disable module %s' % name)
                    if rc != -3:
                        need_commit = True

                    if need_commit:
                        commit_change(sh)

                changed = True

        elif state == 'present':
            if not get_module_installed(sh, name):
                if not module.check_mode:
                    rc = semanage_module_install_file(sh, path)
                    if rc >= 0:
                        commit_change(sh)
                        changed = True
                    else:
                        raise ValueError('Could not install module %s from %s' % (name, path))
                else:
                    changed = True

        elif state == 'absent':
            if get_module_installed(sh, name):
                if not module.check_mode:
                    rc = semanage_module_remove(sh, name)
                    if rc < 0 and rc != -2:
                        raise ValueError('Could not remove module %s' % name)

                    commit_change(sh)

                changed = True

        semanage_handle_destroy(sh)

    except Exception, e:
        # Casting a wider net on exceptions just in case
        semanage_handle_destroy(sh)
        module.fail_json(msg='Failed to manage module %s: %s' % (name, str(e)))

    module.exit_json(changed=changed)

# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
