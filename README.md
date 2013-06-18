yourls-authmgr-plugin
=====================

This plugin adds role-based access controls (RBAC) to YOURLS. By assigning users to roles like "Editor" and "Contributor" you can limit the changes they are permitted to make.

With access controls enabled, you can safely delegate access to the admin pages.

Installation
------------
1. Download the [latest release](https://github.com/nicwaller/yourls-authmgr-plugin/tags) of yourls-authmgr-plugin.
1. Copy the plugin folder into your `user/plugins` folder for YOURLS.
1. Set up the parameters for authmgr (details below)
1. Activate the plugin with the plugin manager in the YOURLS admin interface.

Default Roles
-------------
The default roles are set up as follows:

Role          | Capabilities
--------------|-------------------------------------------------
Administrator | No Limits
Editor        | Cannot manage plugins
Contributor   | Cannot manage plugins, edit URLs, or delete URLs

Configuration
-------------
Add role assignments to your `user/config.php` file.

```
$authmgr_role_assignment = array(
  'administrator' => array(
    'your_username',
  ),
  'editor' => array(
    'your_close_friend',
  ),
  'contributor' => array(
    'your_other_friend',
  ),
);
```

You can also designate a range of IP addresses that will automatically be granted all capabilities. By default, all accesses from IPv4 localhost (127.0.0.0/8) are granted full access.

```
$authmgr_admin_ipranges = array(
    '127.0.0.0/8',
);
```

License
-------
Copyright 2013 Nicholas Waller (code@nicwaller.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
