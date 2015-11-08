import ldap
from ldap.ldapobject import ReconnectLDAPObject
import re

import logging
logger = logging.getLogger(__name__)

class ActiveDirectoryLDAPConnection(ReconnectLDAPObject, object):
    # https://msdn.microsoft.com/en-us/library/ms684291(v=vs.85).aspx
    DOMAIN_FUNCTIONALITY_MAP = dict(
            WIN2000=0,
            WIN2003_INTERIM=1,
            WIN2003=2,
            WIN2008=3,
            WIN2008R2=4)

    def __init__(self, *args, **kwargs):
        '''
        All args/kwargs except ldap_base are passed to ldap.ldapobject.ReconnectLDAPObject.

        New cls class object is returned with created ldapobject and ldap_base.
        '''
        ldap_base = kwargs.pop('ldap_base', '')
        bind_dn = kwargs.pop('bind_dn', '')
        bind_password = kwargs.pop('bind_password', '')
        super(ActiveDirectoryLDAPConnection, self).__init__(*args, **kwargs)
        self.rootdse = self._get_rootdse()
        self._domainlevel_int = int(self.rootdse.get('domainFunctionality', '0'))
        self.domainlevel = self._get_domainlevel_str(self._domainlevel_int)
        self.ldap_base = ldap_base or self.rootdse.get('defaultNamingContext')
        self.domain_password_policy = None
        self.granular_password_policies = None
        if bind_dn and bind_password:
            self.authenticate(bind_dn, bind_password)
            self.load_all_password_policies()

    def authenticate(self, user_dn, password):
        try:
           self.simple_bind_s(user_dn, password)
        except ldap.INVALID_CREDENTIALS as e:
            raise self.INVALID_CREDENTIALS(e)

    def get_user(self, username, ldap_base=''):
        available_attributes = DomainUser._get_available_attributes(DomainUser.ATTRIBUTE_LEVEL_MAP, self)
        ldap_filter = '(samaccountname={0})'.format(username)
        ldap_base = ldap_base or self.ldap_base
        result = self.search_s_flatgen(ldap_base, ldap.SCOPE_SUBTREE, ldap_filter, attrlist=available_attributes)
        (user_dn, user_dict) = next(result)
        return DomainUser(user_dict, user_dn)

    def load_all_password_policies(self):
        try:
            self.domain_password_policy = DomainPasswordPolicy.get_policy(self)
            self.granular_password_policies = GranularPasswordPolicy.get_all_policies(self)
        except ldap.OPERATIONS_ERROR as e:
            # Not bound or not bound as someone who can read fgpp.
            pass

    def search_s_flatgen(*args, **kwargs):
        result = self.search_s(*args, **kwargs)
        return self._flattened_result_generator(result)

    def check_domainlevel(self, domainlevel_str):
        '''
        Return true if the integer value of domainFunctionality covers
        self._domainlevel_str.

        DOMAIN_FUNCTIONALITY_MAP is used to convert domainlevel_str to integer value.
        '''
        return True if int(self._domainlevel_int) >= self.DOMAIN_FUNCTIONALITY_MAP[domainlevel_str] else False

    def _get_rootdse(self):
        '''
        Query the Root DSE (blank search base, base scope, no authn required).
        '''
        result = self.search_s_flatgen('', ldap.SCOPE_BASE)
        (dn, rootdse) = next(result)
        return rootdse

    @classmethod
    def _get_domainlevel_str(cls, level_int):
        '''
        Return name of domain functionality level given integer value from RootDSE domainFunctionality.
        '''
        domainFunctionality_map_inv = dict((level, name) for (name, level) in cls.DOMAIN_FUNCTIONALITY_MAP.iteritems())
        return domainFunctionality_map_inv[level_int]

    @classmethod
    def _flattened_result_generator(cls, result):
        '''
        Wrapper to _flatten_attributes that processes and returns the first result.
        '''
        for (dn, attributes) in result:
            attributes = cls._flatten_attributes(attributes)
            yield (dn, attributes)

    @classmethod
    def _flatten_attributes(cls, d):
        '''
        Wrapper to _flatten_list, this returns a new result attributes dict
        with the dict values "flattened".

        If no attributes are returned, d will be a list.
        '''
        if isinstance(d, list):
            return
        for (key, value) in d.iteritems():
            d[key] = cls._flatten_list(value)
        return d

    @classmethod
    def _flatten_list(cls, l):
        '''
        Shamelessly stolen from https://github.com/meyersh/mldap/blob/master/functions.py
        Given a list of no elements, return None.
        Given a list of one element, return just the element.
        given a list of more than one element, return the list.
        '''
        if not l:
            return None
        if isinstance(l, list):
            if len(l) > 1:
                return l
            else:
                return l[0]
        return l

class CONSTRAINT_VIOLATION(ldap.CONSTRAINT_VIOLATION, ActiveDirectoryLDAPConnection):
    CONSTRAINT_VIOLATION_MAP = {
            '00000056': 'incorrect_current_password',
            '0000052D': 'policy_violation'}

    def __init__(self, e):
        super(ActiveDirectoryLDAPConnection.CONSTRAINT_VIOLATION, self).__init__(*e.args)
        self.ad_reason = self._parse_constraint_violation()
        self.args[0]['ad_reason'] = self.ad_reason

    def _parse_constraint_violation(self):
        '''
        Attempt to get additional information from an ldap.CONSTRAINT_VIOLATION.
        AD returns a specific string with additional information that starts with a numeric code.
        '''
        ldapcode_pattern = r'^(?P<ldapcode>[0-9]+)'
        try:
            ldapcode_errstr = self.args[0]['info']
        except (IndexError, KeyError) as e:
            return 'Failed to find info key in {0}'.format(self.args)
        m = re.match(ldapcode_pattern, ldapcode_errstr)
        try:
            ldapcode = m.group('ldapcode')
        except (AttributeError, IndexError) as e:
            return 'Failed to parse code from {0}'.format(ldapcode_errstr)
        try:
            description = self.CONSTRAINT_VIOLATION[ldapcode]
        except KeyError:
            return 'Code {0} invalid per http://www-01.ibm.com/support/docview.wss?uid=swg21290631'.format(ldapcode)
        return description

class INVALID_CREDENTIALS(ldap.INVALID_CREDENTIALS, ActiveDirectoryLDAPConnection):
    # Code 49 (Invalid Credentials) Data Codes: http://www-01.ibm.com/support/docview.wss?uid=swg21290631
    INVALID_CREDENTIALS_MAP = {
            '525': 'user_not_found',  # This does not get returned when you bind with invalid user_dn.
            '530': 'login_time_restricted',
            '531': 'login_workstation_restricted',
            '52e': 'password_incorrect',
            '532': 'password_expired_natural',
            '733': 'password_expired_forced',
            '533': 'account_disabled',
            '701': 'account_expired',
            '775': 'account_locked'}

    # These are user-configurable and should probably go elsewhere.
    PASSWORD_CHANGE_ALLOWED = [
            'password_expired_natural',
            'password_expired_forced']


    def __init__(self, e):
        super(ActiveDirectoryLDAPConnection.INVALID_CREDENTIALS, self).__init__(*e.args)
        self.ad_reason = self._parse_invalid_credentials()
        self.ad_can_change_password = True if self.ad_reason in self.PASSWORD_CHANGE_ALLOWED else False
        self.args[0]['ad_reason'] = self.ad_reason
        self.args[0]['ad_can_change_password'] = self.ad_can_change_password

    def _parse_invalid_credentials(self):
        '''
        Attempt to get additional information from an ldap.INVALID_CREDENTIALS.
        AD returns a specific string with additional information after 'data'.
        The codes are detailed here: http://www-01.ibm.com/support/docview.wss?uid=swg21290631
        '''
        ldapcode_pattern = r'.*AcceptSecurityContext error, data (?P<ldapcode>[^,]+),'
        try:
            ldapcode_errstr = self.args[0]['info']
        except (IndexError, KeyError) as e:
            return 'Failed to find info key in {0}'.format(self.args)
        m = re.match(ldapcode_pattern, ldapcode_errstr)
        try:
            ldapcode = m.group('ldapcode')
        except (AttributeError, IndexError) as e:
            return 'Failed to parse code from {0}'.format(ldapcode_errstr)
        try:
            description = self.INVALID_CREDENTIALS_MAP[ldapcode]
        except KeyError:
            return 'Code {0} invalid per http://www-01.ibm.com/support/docview.wss?uid=swg21290631'.format(ldapcode)
        return description
