import re

import logging
logger = logging.getLogger(__name__)

class PasswordPolicy(object):
    '''
    This is the base class for AD Password Policies.
    It expects to be subclassed with POLICY_ATTRIBUTE_MAP modified.
    The keys   of POLICY_ATTRIBUTE_MAP should remain unchanged.
    The values of POLICY_ATTRIBUTE_MAP should be the source LDAP attribute.
    If a policy attribute requires special processing, it should be done in the subclass.
    '''
    POLICY_ATTRIBUTE_MAP = dict(
            password_min_length=None,
            password_min_age=None,
            password_max_age=None,
            password_history_length=None,
            password_complexity_enforced=None,
            password_cleartext_available=None,
            authfail_lockout_threshold=None,
            authfail_lockout_window=None,
            authfail_lockout_duration=None)

    NUMERIC_ATTRIBUTES = [
            'password_min_length',
            'password_history_length',
            'authfail_lockout_threshold']

    BOOLEAN_ATTRIBUTES = [
            'password_complexity_enforced',
            'password_cleartext_available']

    RELATIVE_INTERVAL_ATTRIBUTES = [
            'password_min_age',
            'password_max_age',
            'authfail_lockout_window',
            'authfail_lockout_duration']

    def __init__(self, policy_dict, policy_dn):
        '''
        Determine which keys in policy_dict map to the correct attribute.
        Set the resulting values as attributes of this class.
        '''
        self._policy_raw = policy_dict
        for (policy_key, dict_key) in self.POLICY_ATTRIBUTE_MAP.iteritems():
            value = policy_dict.get(dict_key, None)
            if value is not None and policy_key in self.NUMERIC_ATTRIBUTES:
                value = int(value)
            if value is not None and policy_key in self.BOOLEAN_ATTRIBUTES:
                value = ActiveDirectoryAttribute.string_to_boolean(value)
            if value is not None and policy_key in self.RELATIVE_INTERVAL_ATTRIBUTES:
                value = ActiveDirectoryAttribute.relative_adinterval_to_timedelta(value)
            setattr(self, policy_key, value)
        self.policy_dn = policy_dn

    def __repr__(self):
        return '<{0} for {1} at 0x{2:x}>'.format(self.__class__.__name__, self.policy_dn, id(self))

    def __str__(self):
        '''
        Return dict of policy keys and values.
        '''
        policy = dict((policy_key, getattr(self, policy_key)) for policy_key in self.POLICY_ATTRIBUTE_MAP.iterkeys())
        policy['policy_dn'] = self.policy_dn
        return str(policy)

    def validate_password(self, password, username, displayname):
        '''
        Length and complexity are what we can check for here.
        TODO: Check password minimum age. Tricky since we also need user pwdLastSet.

        Raises ValueError if password does not validate. TODO: CONSTRAINT_VIOLATION instead?
        '''
        if len(password) < self.password_min_length:
            raise ValueError('Password must be at least {0} characters.'.format(self, self.password_min_length))

        if self.password_complexity_enforced:
            self.validate_complexity(password, username, displayname)

    @classmethod
    def validate_complexity(cls, password, username, displayname):
        '''
        Complexity Rules: https://technet.microsoft.com/en-us/library/cc786468(v=ws.10).aspx
            - If sAMAccountName is longer than 2 characters, it cannot be a part of the password (case insensitive).
            - If a tokenized segment of displayName is longer than 2 characters, it cannot be part of the password (case insensitive).
                - Token delimiters: ,.-_ #\t
            - The password must contain 3 of 5 character classes:
                - Uppercase
                - Lowercase
                - Number
                - Non-alphanumeric: ~!@#$%^&*_-+=`|\(){}[]:;"'<>,.?/
                - Unicode categorized as alpha but not upper or lowercase. (Unicode from Asian languages)
                    - This class is not currently implemented.
        '''
        username = username.lower()
        if len(username) > 2 and username in password.lower():
            raise ValueError('Usernames longer than 2 characters ({0}) cannot be part of a password.'.format(username))

        token_chars = ',.-_ #\t'
        split_pattern = '[{0}]+(?i)'.format(token_chars)  # account for re.split case-sensitivity
        displayname_tokenized = [token for token in re.split(split_pattern, displayname) if len(token) > 2]
        for token in displayname_tokenized:
            if token.lower() in password.lower():
                raise ValueError('Parts of your display name longer than 2 characters ({0}) cannot be part of a password.'.format(token))

        patterns = [r'(?P<digit>[0-9])', r'(?P<lowercase>[a-z])', r'(?P<uppercase>[A-Z])', r'(?P<non_alphanumeric>[~!@#$%^&*_\-+=`|\\(){}\[\]:;"\'<>,.?/])']
        matches = []
        for pattern in patterns:
            match = re.search(pattern, password)
            try:
                matches.append(match.groupdict().keys()[0])
            except AttributeError:
                # No match!
                pass
        if len(matches) < 3:
            raise ValueError('Password must contain 3 or 4 character types (lowercase, uppercase, digit, non_alphanumeric), only found {0}.'.format(', '.join(matches)))


    @classmethod
    def get_policy(cls, adldap_obj, policy_dn):
        '''
        Get password policy. This will only work on subclasses that set values() on POLICY_ATTRIBUTE_MAP
        '''
        policy_ldap_attributes = cls.POLICY_ATTRIBUTE_MAP.values()
        result = adldap_obj.search_s_flatgen(policy_dn, ldap.SCOPE_BASE, attrlist=policy_ldap_attributes)
        (policy_dn, policy_dict) = next(result)
        if not policy_dict:
            return None  # raise exception?
        return cls(policy_dict, policy_dn)


class DomainPasswordPolicy(PasswordPolicy):
    '''
    Domain-wide password policy (pre-2008):
     - LDAP objectclass: https://msdn.microsoft.com/en-us/library/ms682209(v=vs.85).aspx
    '''
    POLICY_ATTRIBUTE_MAP = dict(
            password_min_length='minPwdLength',
            password_min_age='minPwdAge',
            password_max_age='maxPwdAge',
            password_history_length='pwdHistoryLength',
            password_complexity_enforced='pwdProperties',
            password_cleartext_available='pwdProperties',
            authfail_lockout_threshold='lockoutThreshold',
            authfail_lockout_window='lockoutObservationWindow',
            authfail_lockout_duration='lockoutDuration')

    PWDPROPERTIES_FLAGS = dict(
            DOMAIN_PASSWORD_COMPLEX=1,
            DOMAIN_PASSWORD_NO_ANON_CHANGE=2,
            DOMAIN_PASSWORD_NO_CLEAR_CHANGE=4,
            DOMAIN_LOCKOUT_ADMINS=8,
            DOMAIN_PASSWORD_STORE_CLEARTEXT=16,
            DOMAIN_REFUSE_PASSWORD_CHANGE=32)

    def __init__(self, policy_dict, policy_dn):
        super(DomainPasswordPolicy, self).__init__(policy_dict, policy_dn)
        self.password_complexity_enforced = self._is_complexity_enabled(self.password_complexity_enforced)
        self.password_cleartext_available = self._is_cleartext_available(self.password_cleartext_available)

    @classmethod
    def get_policy(cls, adldap_obj, policy_dn=''):
        policy_dn = policy_dn or adldap_obj.ldap_base
        return super(DomainPasswordPolicy, cls).get_policy(adldap_obj, policy_dn)

    @classmethod
    def _is_complexity_enabled(cls, pwdproperties):
        properties_dict = cls._process_pwdproperties(pwdproperties)
        return properties_dict['DOMAIN_PASSWORD_COMPLEX']

    @classmethod
    def _is_cleartext_available(cls, pwdproperties):
        properties_dict = cls._process_pwdproperties(pwdproperties)
        return properties_dict['DOMAIN_PASSWORD_STORE_CLEARTEXT']

    @classmethod
    def _process_pwdproperties(cls, pwdproperties):
        '''
        Take an string representation of integer comprised of bit flags from:

        https://msdn.microsoft.com/en-us/library/ms679431(v=vs.85).aspx

        and return dict of each setting and corresponding boolean value.
        '''
        properties_int = int(pwdproperties)
        properties_dict = dict()
        for (key, value) in cls.PWDPROPERTIES_FLAGS.iteritems():
            properties_dict[key] = True if properties_int & value else False
        return properties_dict


class GranularPasswordPolicy(PasswordPolicy):
    '''
    Fine Grained Password Policy (fgpp):
      - LDAP objectclass: https://msdn.microsoft.com/en-us/library/hh338661(v=vs.85).aspx

    Container for Fine Grained Password Policies:
      - LDAP objectclass: https://msdn.microsoft.com/en-us/library/hh338662(v=vs.85).aspx

    Requires domain functional level 2008+ (requires all 2008+ DCs).

    By default, only members of "Domain Admins" can run CRUD ops on fgpp.
    This means that adldap_obj must be authn'd by a user that is either
    a member of "Domain Admins" or has been granted read access on the
    Password Settings Container object and children.
    '''

    POLICY_ATTRIBUTE_MAP = dict(
            password_min_length='msDS-MinimumPasswordLength',
            password_min_age='msDS-MinimumPasswordAge',
            password_max_age='msDS-MaximumPasswordAge',
            password_history_length='msDS-PasswordHistoryLength',
            password_complexity_enforced='msDS-PasswordComplexityEnabled',
            password_cleartext_available='msDS-PasswordReversibleEncryptionEnabled',
            authfail_lockout_threshold='msDS-LockoutThreshold',
            authfail_lockout_window='msDS-LockoutObservationWindow',
            authfail_lockout_duration='msDS-LockoutDuration')

    def __init__(self, policy_dict, policy_dn):
        super(GranularPasswordPolicy, self).__init__(policy_dict, policy_dn)

    @classmethod
    def _is_fgpp_supported(cls, adldap_obj):
        '''
        Return true if Fine-Grained Password Policies are supported, false otherwise.
        '''
        return adldap_obj._check_domainlevel('WIN2008')

    @classmethod
    def get_all_policies(cls, adldap_obj, ldap_base=''):
        '''
        Make sure we can query fgpp container, then load all its child policies.
        '''
        if not cls._is_fgpp_supported(adldap_obj):
            return None
        ldap_base = ldap_base or adldap_obj.ldap_base
        fgpp_container_base = 'cn=Password Settings Container,cn=System,{0}'.format(ldap_base)
        result = adldap_obj.search_s_flatgen(fgpp_container_base, ldap.SCOPE_BASE, '(objectclass=msDS-PasswordSettingsContainer)')
        if not result:
            print 'FGPP supported but container could not be found. Likely because you are not bound as a user with permissions to read fgpp.'
            return None
        # FGPP supported and container located. Safe to query for policies.
        result = adldap_obj.search_s_flatgen(fgpp_container_base, ldap.SCOPE_SUBTREE, '(objectclass=msDS-PasswordSettings)')
        policies = dict()
        for (policy_dn, ignored) in result:
            policies[policy_dn] = super(GranularPasswordPolicy, cls).get_policy(adldap_obj, policy_dn)
        return policies
