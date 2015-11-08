import logging
# Set default logging handler to avoid "No handler found" warnings.
try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

from user import DomainUser
from password_policy import DomainPasswordPolicy, GranularPasswordPolicy
from attribute import ActiveDirectoryAttribute
from ldap_connection import ActiveDirectoryLDAPConnection

logging.getLogger(__name__).addHandler(NullHandler())

__all__ = ['DomainUser', 'DomainPasswordPolicy', 'GranularPasswordPolicy', 'ActiveDirectoryAttribute', 'ActiveDirectoryLDAPConnection']
