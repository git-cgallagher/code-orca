"""Ansible plugins shipped with code-orca. ``callback/`` is handed to ``ansible-playbook`` through
``ANSIBLE_CALLBACK_PLUGINS``; the modules in there import only the standard library and ``ansible`` (they run
inside the playbook process, where ``codeorca`` may not be installed)."""
