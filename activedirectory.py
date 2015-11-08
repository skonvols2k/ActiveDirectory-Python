# External Dependencies
import ldap
from ldap.ldapobject import ReconnectLDAPObject

# Stdlib Dependencies
from datetime import timedelta, datetime
from collections import OrderedDict
import struct
import itertools
import pytz
import re

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

    class CONSTRAINT_VIOLATION(ldap.CONSTRAINT_VIOLATION):
        CONSTRAINT_VIOLATION_MAP = {
                '00000056': 'incorrect_current_password',
                '0000052D': 'policy_violation'}

        def __init__(self, e):
            super(PasswordPolicy.CONSTRAINT_VIOLATION, self).__init__(*e.args)
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

    class INVALID_CREDENTIALS(ldap.INVALID_CREDENTIALS):
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


class ActiveDirectoryAttribute(object):
    # https://msdn.microsoft.com/en-us/library/ms677840(v=vs.85).aspx and
    # https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx
    USERACCOUNTCONTROL_FLAGS = dict(
            UF_SCRIPT=0x00000001,
            UF_ACCOUNTDISABLE=0x00000002,
            UF_HOMEDIR_REQUIRED=0x00000008,
            UF_LOCKOUT=0x00000010,
            UF_PASSWD_NOTREQD=0x00000020,
            UF_PASSWD_CANT_CHANGE=0x00000040,
            UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED=0x00000080,
            UF_TEMP_DUPLICATE_ACCOUNT=0x00000100,
            UF_NORMAL_ACCOUNT=0x00000200,
            UF_INTERDOMAIN_TRUST_ACCOUNT=0x00000800,
            UF_WORKSTATION_TRUST_ACCOUNT=0x00001000,
            UF_SERVER_TRUST_ACCOUNT=0x00002000,
            UF_DONT_EXPIRE_PASSWD=0x00010000,
            UF_MNS_LOGON_ACCOUNT=0x00020000,
            UF_SMARTCARD_REQUIRED=0x00040000,
            UF_TRUSTED_FOR_DELEGATION=0x00080000,
            UF_NOT_DELEGATED=0x00100000,
            UF_USE_DES_KEY_ONLY=0x00200000,
            UF_DONT_REQUIRE_PREAUTH=0x00400000,
            UF_PASSWORD_EXPIRED=0x00800000,
            UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION=0x01000000,
            UF_PARTIAL_SECRETS_ACCOUNT=0x4000000,
            UF_USE_AES_KEYS=0x8000000)

    # https://msdn.microsoft.com/en-us/library/ee808210.aspx
    # TODO: parse msDS-SupportedEncryptionTypes

    # https://msdn.microsoft.com/en-us/library/ms679637(v=vs.85).aspx
    SAMACCOUNTTYPE_MAP = dict(
            SAM_DOMAIN_OBJECT=0x0,
            SAM_GROUP_OBJECT=0x10000000,
            SAM_NON_SECURITY_GROUP_OBJECT=0x10000001,
            SAM_ALIAS_OBJECT=0x20000000,
            SAM_NON_SECURITY_ALIAS_OBJECT=0x20000001,
            SAM_USER_OBJECT=0x30000000,
            SAM_NORMAL_USER_ACCOUNT=0x30000000,
            SAM_MACHINE_ACCOUNT=0x30000001,
            SAM_TRUST_ACCOUNT=0x30000002,
            SAM_APP_BASIC_GROUP=0x40000000,
            SAM_APP_QUERY_GROUP=0x40000001,
            SAM_ACCOUNT_TYPE_MAX=0x7fffffff)

    @classmethod
    def relative_adinterval_to_timedelta(cls, adinterval):
        '''
        Converts Relative AD Interval (https://msdn.microsoft.com/en-us/library/ms684426(v=vs.85).aspx)
        to positive Python timedelta.

        Returns None if the interval represents 'never'.

        :param adinterval: string of negative long int representing 100-nanosecond intervals
        '''
        relative_never = [0, -0x8000000000000000]
        adinterval_int = int(adinterval)
        if adinterval_int in relative_never:
            return None
        seconds = abs(adinterval_int / 10000000)
        return timedelta(seconds=seconds)

    @classmethod
    def absolute_adinterval_to_datetime(cls, adinterval):
        '''
        Converts Absolute AD Interval (https://msdn.microsoft.com/en-us/library/ms684426(v=vs.85).aspx)
        to Python datetime in UTC.

        Returns None if the interval represents 'never'.

        :param adinterval: string of long int representing 100-nanosecond intervals since Jan 1, 1601 UTC
        '''
        absolute_never = [0, 0x7FFFFFFFFFFFFFFF]
        if int(adinterval) in absolute_never:
            return None
        delta = cls.relative_adinterval_to_timedelta(adinterval)
        ad_epoch = datetime(1601, 1, 1, tzinfo=pytz.utc)
        return ad_epoch + delta

    @classmethod
    def string_to_boolean(cls, bool_str):
        '''
        Returns boolean value of string, accepting true/false, t/f, or 0/1
        '''
        string_true = ['true', 't', '1']
        string_false = ['false', 'f', '0']
        string_boolean = string_true + string_false
        bool_str = str(bool_str).lower()
        if bool_str not in string_boolean:
            raise ValueError('%s not boolean string. (true/false, t/f, 0/1)' % (value))
        return bool_str in string_true

    @classmethod
    def password_to_utf16le(cls, password):
        return unicode('\"' + password + '\"').encode('utf-16-le')
    
    @classmethod
    def parse_useraccountcontrol(cls, uac):
        uac_int = int(uac)
        uac_dict = dict()
        for (flag, value) in cls.USERACCOUNTCONTROL_FLAGS.iteritems():
            uac_dict[flag] = True if uac_int & value else False
        return uac_dict

    @classmethod
    def parse_samaccounttype(cls, samaccounttype):
        samaccounttype_map_inv = dict((sam_type, sam_name) for (sam_name, sam_type) in cls.SAMACCOUNTTYPE_MAP.iteritems())
        return samaccounttype_map_inv[int(samaccounttype)]

    @classmethod
    def parse_logonhours(cls, logonhours):
        '''
        From: https://anlai.wordpress.com/2010/09/07/active-directory-permitted-logon-times-with-c-net-3-5-using-system-directoryservices-accountmanagement/
            - logonhours is 21-byte field.
            - Each day of the week is 3 bytes.
            - Each hour is 1 bit.
            - The first byte is actually Saturday 1600 - 0000, swap with last byte.

        Python 2.7 or RHEL/CentOS python-libs >= 2.6.6-43 has required collections.OrderedDict.
        '''
        byte_list = list(struct.unpack('21B', logonhours))
        byte_list[0] = byte_list[0] ^ byte_list[20]
        byte_list[20] = byte_list[0] ^ byte_list[20]
        byte_list[0] = byte_list[0] ^ byte_list[20]
        weekdays = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        hour_masks = [2**i for i in xrange(24)]  # every bit in 3 bytes
        logonhours_dict = OrderedDict()
        for day in weekdays:
            for (morning, midday, evening) in itertools.izip(byte_list, itertools.islice(byte_list, 1, None), itertools.islice(byte_list, 2, None)):
                logonhours_today = morning | (midday << 8) | (evening << 16)
                logonhours_dict[day] = dict()
                today = logonhours_dict[day]
                for hour in xrange(24):
                    today[hour] = True if logonhours_today & hour_masks[hour] else False
        return logonhours_dict


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


class DomainUser(object):
    # What user attributes do we want and in what domain levels of AD are they available
    # I broke the dict() convention since some keys have '-' characters.
    ATTRIBUTE_LEVEL_MAP = {
            'sAMAccountName': 'WIN2000',
            'sAMAccountType': 'WIN2000',
            'displayName': 'WIN2000',
            'pwdLastSet': 'WIN2000',
            'lockoutTime': 'WIN2000',
            'accountExpires': 'WIN2000',
            'userAccountControl': 'WIN2000',
            'logonHours': 'WIN2000',
            'userWorkstations': 'WIN2000',
            'lastLogonTimestamp': 'WIN2003',
            'msDS-User-Account-Control-Computed': 'WIN2003',
            'msDS-UserPasswordExpiryTimeComputed': 'WIN2008',
            'msDS-ResultantPSO': 'WIN2008',
            'msDS-FailedInteractiveLogonCount': 'WIN2008',
            'msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon': 'WIN2008'}

    ABSOLUTE_INTERVAL_ATTRIBUTES = [
            'accountExpires',
            'lastLogonTimestamp',
            'msDS-UserPasswordExpiryTimeComputed',
            'lockoutTime',
            'pwdLastSet']

    def __init__(self, user_dict, user_dn):
        self._user_raw = dict(user_dict)  # copy
        self.user_dn = user_dn
        for (key, value) in user_dict.iteritems():
            if value is not None:
                if key in self.ABSOLUTE_INTERVAL_ATTRIBUTES:
                    value = ActiveDirectoryAttribute.absolute_adinterval_to_datetime(value)
                if key == 'logonHours':
                    value = ActiveDirectoryAttribute.parse_logonhours(value)
                if key == 'sAMAccountType':
                    value = ActiveDirectoryAttribute.parse_samaccounttype(value)
                if key == 'userAccountControl':
                    # If available, combine msDS-User-Account-Control-Computed into userAccountControl
                    uac_int = int(value)
                    uaccomputed_int = int(user_dict.get('msDS-User-Account-Control-Computed', 0))
                    uac_combined = uac_int | uaccomputed_int
                    value = ActiveDirectoryAttribute.parse_useraccountcontrol(uac_combined)
            user_dict[key] = value
        self.user_dict = user_dict

    def __repr__(self):
        return '<{0} {1} at 0x{2:x}>'.format(self.__class__.__name__, self.user_dn, id(self))

    def __str__(self):
        return str(self.user_dict)

    def change_password(self, current_password, new_password, adldap_obj):
        '''
        Details: https://msdn.microsoft.com/en-us/library/cc223248.aspx
            - User can delete then add unicodePwd with current_password and new_password.
            - Must adhere to user's password policy.
        '''
        # Preserve bind credentials, authn user on new LDAP connection.
        user_adldap_obj = ActiveDirectoryLDAPConnection(adldap_obj._uri)
        try:
            user_adldap_obj.authenticate(self.user_dn, current_password)
        except ActiveDirectoryLDAPConnection.INVALID_CREDENTIALS as e:
            if not e.ad_can_change_password:
                raise e
        # current_password is correct.
        user_pso = self.get_user_password_policy(adldap_obj)
        user_pso.validate_password(new_password, self.user_dict['sAMAccountName'], self.user_dict['displayName'])
        # new_password should be valid.
        old_entry = dict(unicodePwd=ActiveDirectoryAttribute.password_to_utf16le(current_password))
        new_entry = dict(unicodePwd=ActiveDirectoryAttribute.password_to_utf16le(new_password))
        password_modlist = ldap.modlist.modifyModlist(old_entry, new_entry)
        try:
            adldap_obj.modify_s(self.user_dn, password_modlist)
        except ldap.CONSTRAINT_VIOLATION as e:
            raise ActiveDirectoryLDAPConnection.CONSTRAINT_VIOLATION(e)

    def admin_set_password(self, new_password, adldap_obj):
        '''
        Details: https://msdn.microsoft.com/en-us/library/cc223248.aspx
            - Priv'd user can replace unicodePwd with new_password.
            - Must adhere to user's password policy.
        '''
        user_pso = self.get_user_password_policy(adldap_obj)
        user_pso.validate_password(new_password, self.user_dict['sAMAccountName'], self.user_dict['displayName'])
        # new_password should be valid.
        new_password = ActiveDirectoryAttribute.password_to_utf16le(new_password)
		password_modlist = [(ldap.MOD_REPLACE, 'unicodePwd', [new_password])]
        try:
            adldap_obj.modify_s(self.user_dn, password_modlist)
        except ldap.CONSTRAINT_VIOLATION as e:
            raise ActiveDirectoryLDAPConnection.CONSTRAINT_VIOLATION(e)

    def get_user_password_policy(self, adldap_obj):
        '''
        Prefer msDS-ResultantPSO, fall back to domain policy.
        '''
        user_pso = self.user_dict.get('msDS-ResultantPSO', None)
        if user_pso:
            return adldap_obj.granular_password_policies[user_pso]
        else:
            return adldap_obj.domain_password_policy

    @classmethod
    def _get_available_attributes(cls, attribute_level_dict, adldap_obj):
        available_attributes = list()
        for (attribute, level) in attribute_level_dict.iteritems():
            if adldap_obj._check_domainlevel(level):
                available_attributes.append(attribute)
        return available_attributes

