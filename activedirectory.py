# External Dependencies
import ldap

# Internal Dependencies
from datetime import timedelta, datetime
from collections import OrderedDict
import struct
import itertools
import pytz
import re

class ActiveDirectoryPasswordController(object):
    # https://msdn.microsoft.com/en-us/library/ms684291(v=vs.85).aspx
    _domainFunctionality_map = dict(
            WIN2000=0,
            WIN2003_INTERIM=1,
            WIN2003=2,
            WIN2008=3,
            WIN2008R2=4)

    # Code 49 (Invalid Credentials) Data Codes: http://www-01.ibm.com/support/docview.wss?uid=swg21290631
    _invalid_credentials_codes = dict(
            user_not_found='525',
            login_time_restricted='530',
            login_workstation_restricted='531',
            password_incorrect='52e',
            password_expired_natural='532',
            password_expired_forced='733',
            account_disabled='533',
            account_expired='701',
            account_locked='775')

    # What user attributes do we want and in what domain levels of AD are they available
    # I broke the dict() convention since some keys have '-' characters.
    _user_attribute_level_map = {
            'sAMAccountName': 0,
            'sAMAccountType': 0,
            'pwdLastSet': 0,
            'lastLogonTimestamp': 2,
            'lockoutTime': 0,
            'accountExpires': 0,
            'msDS-UserPasswordExpiryTimeComputed': 3,
            'msDS-User-Account-Control-Computed': 2,
            'logonHours': 0,
            'userWorkstations': 0,
            'msDS-ResultantPSO': 3,
            'msDS-FailedInteractiveLogonCount': 3,
            'msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon': 3}

    # https://msdn.microsoft.com/en-us/library/ms679637(v=vs.85).aspx
    _samaccounttype_map = dict(
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

    _absolute_interval_attributes = [
            'accountExpires',
            'lastLogonTimestamp',
            'msDS-UserPasswordExpiryTimeComputed',
            'pwdLastSet']

    def __init__(self, ldap_obj, ldap_base=''):
        self.ldap_obj = ldap_obj
        self.rootdse = self._get_rootdse(ldap_obj)
        self.domainlevel_int = self._get_domainfunctionality_int(self.rootdse)
        self.domainlevel_str = self._get_domainfunctionality_str(self.domainlevel_int)
        if not self._is_uaccomputed_supported(ldap_obj):
            print 'I really rely on msDS-User-Account-Control-Computed which is only available in domain level 2003+'
            return None
        if not ldap_base:
            ldap_base = self._get_defaultnamingcontext(ldap_obj)
        self.ldap_base = ldap_base
        self.domain_policy = self.DomainPasswordPolicy.get_policy(ldap_obj, ldap_base)
        self.fgpp_supported = self._is_fgpp_supported(ldap_obj)
        if self.fgpp_supported:
            self.granular_policies = self.GranularPasswordPolicy.get_all_policies(ldap_obj, ldap_base)

    '''
    Things I still need to do:
        - Look up user information by username
            - msDS-User-Account-Control-Computed (domain level 2003+)
        - Let users change their password using their current password
            - unless something prevents them from doing it themselves
        - Let admins reset user passwords
    '''
    def get_user_info(self, username):
        available_attributes = self._get_available_attributes(self._user_attribute_level_map, self.domainlevel_int)
        ldap_filter = '(samaccountname={0})'.format(username)
        result = self.ldap_obj.search_s(self.ldap_base, ldap.SCOPE_SUBTREE, ldap_filter, attrlist=available_attributes)
        (dn, attributes) = next(self._flattened_result_generator(result))
        user_info = self._process_user_info(attributes)
        return attributes

    # "Helper" functions follow. They don't need instantiated class.
    @classmethod
    def _process_user_info(cls, user_info):
        '''
        Attributes that need extra processing, if present:
            - absolute interval attributes
            - logonHours
            - sAMAccountType

        TODO: This mapping could/should be controlled in a dict.
        '''
        for key in set(cls._absolute_interval_attributes) & set(user_info.iterkeys()):
            user_info[key] = cls._absolute_adinterval_to_datetime(user_info[key])
        user_info['logonHours'] = cls._parse_logonhours(user_info['logonHours'])
        user_info['sAMAccountType'] = cls._parse_samaccounttype(user_info['sAMAccountType'])

    @classmethod
    def _parse_samaccounttype(cls, samaccounttype):
        samaccounttype_map_inv = dict((sam_type, sam_name) for (sam_name, sam_type) in cls._samaccounttype_map.iteritems())
        return samaccounttype_map_inv[int(samaccounttype)]

    @classmethod
    def _parse_logonhours(cls, logonhours):
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


    @classmethod
    def _get_available_attributes(cls, attribute_level_dict, domainlevel_int):
        available_attributes = list()
        for (attribute, level) in attribute_level_dict.iteritems():
            if domainlevel_int >= level:
                available_attributes.append(attribute)
        return available_attributes

    @classmethod
    def _get_defaultnamingcontext(cls, ldap_obj):
        rootdse = cls._get_rootdse(ldap_obj)
        return rootdse['defaultNamingContext']

    @classmethod
    def _get_domainfunctionality_int(cls, rootdse):
        return int(rootdse.get('domainFunctionality', '0'))

    @classmethod
    def _get_domainfunctionality_str(cls, level_int):
        '''
        Return name of domain functionality level given integer value from RootDSE domainFunctionality.
        '''
        domainFunctionality_map_inv = dict((level, name) for (name, level) in cls._domainFunctionality_map.iteritems())
        return domainFunctionality_map_inv[level_int]

    @classmethod
    def _get_rootdse(cls, ldap_obj):
        '''
        Anonymous bind to our computed LDAP URI and query the Root DSE.
        '''
        result = ldap_obj.search_s('', ldap.SCOPE_BASE)
        (dn, rootdse) = next(cls._flattened_result_generator(result))
        return rootdse

    @classmethod
    def _is_uaccomputed_supported(cls, ldap_obj):
        '''
        Return true if dynamic/computed User Account Control is available, false otherwise.
        '''
        rootdse = cls._get_rootdse(ldap_obj)
        domainlevel_int = cls._get_domainfunctionality_int(rootdse)
        return cls._check_domain_level(domainlevel_int, 'WIN2003')

    @classmethod
    def _is_fgpp_supported(cls, ldap_obj):
        '''
        Return true if Fine-Grained Password Policies are supported, false otherwise.
        '''
        rootdse = cls._get_rootdse(ldap_obj)
        domainlevel_int = cls._get_domainfunctionality_int(rootdse)
        return cls._check_domain_level(domainlevel_int, 'WIN2008')

    @classmethod
    def _check_domain_level(cls, domainlevel_int, domainlevel_str):
        '''
        Return true if the integer value of domainFunctionality covers
        domainlevel_str.

        _domainFunctionality_map is used to convert domainlevel_str to integer value.
        '''
        return True if int(domainlevel_int) >= cls._domainFunctionality_map[domainlevel_str] else False

    @classmethod
    def _relative_adinterval_to_timedelta(cls, adinterval):
        '''
        Converts Relative AD Interval (https://msdn.microsoft.com/en-us/library/ms684426(v=vs.85).aspx)
        to positive Python timedelta.

        Returns None if the interval represents 'never'.

        :param adinterval: string of negative long int representing 100-nanosecond intervals
        '''
        relative_never = [-0x8000000000000000]
        adinterval_int = int(adinterval)
        if adinterval_int in relative_never:
            return None
        seconds = abs(adinterval_int / 10000000)
        return timedelta(seconds=seconds)

    @classmethod
    def _absolute_adinterval_to_datetime(cls, adinterval):
        '''
        Converts Absolute AD Interval (https://msdn.microsoft.com/en-us/library/ms684426(v=vs.85).aspx)
        to Python datetime in UTC.

        Returns None if the interval represents 'never'.

        :param adinterval: string of long int representing 100-nanosecond intervals since Jan 1, 1601 UTC
        '''
        absolute_never = [0, 0x7FFFFFFFFFFFFFFF]
        if int(adinterval) in absolute_never:
            return None
        delta = cls._relative_adinterval_to_timedelta(adinterval)
        ad_epoch = datetime(1601, 1, 1, tzinfo=pytz.utc)
        return ad_epoch + delta

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
    # End "helper functions"

	def user_authn_pwd_verify(self, user, user_pwd):
		# Attempt to bind but only throw an exception if the password is incorrect or the account
		# is in a state that would preclude changing the password.
		try:
			self.user_authn(user, user_pwd)
		except (self.authn_failure_time, self.authn_failure_workstation, \
			(self.authn_failure_pwd_expired_natural if 'acct_pwd_expired' in self.can_change_pwd_states else None),
			(self.authn_failure_pwd_expired_admin if 'acct_pwd_expired' in self.can_change_pwd_states else None),
			(self.authn_failure_acct_disabled if 'acct_disabled' in self.can_change_pwd_states else None),
			(self.authn_failure_acct_expired if 'acct_expired' in self.can_change_pwd_states else None),
			(self.authn_failure_acct_locked if 'acct_locked' in self.can_change_pwd_states else None)):
			return True
		except Exception, e:
			return False
		return True
			
	def user_authn(self, user, user_pwd):
		# Look up DN for user, bind using current_pwd.
		# Return true on success, exception on failure.
		try:
			status = self.get_user_status(user)
			bind_dn = status['user_dn']
			user_conn = ldap.initialize(self.uri)
			user_conn.simple_bind_s(bind_dn, user_pwd)
		except ldap.INVALID_CREDENTIALS, e:
			raise self.parse_invalid_credentials(e, bind_dn)
		except ldap.LDAPError, e:
			raise self.ldap_error(e)
		return True

	def change_pwd(self, user, current_pwd, new_pwd):
		# Change user's account using their own creds
		# This forces adherence to length/complexity/history
		# They must exist, not be priv'd, and can change pwd per can_change_pwd_states
		status = self.get_user_status(user)
		user_dn = status['user_dn']
		if self.is_admin(user_dn):
			raise self.user_protected(user)
		if not status['acct_can_change_pwd']:
			raise self.user_cannot_change_pwd(user, status, self.can_change_pwd_states)
		# The new password must respect policy
		if not len(new_pwd) >= status['acct_pwd_policy']['pwd_length_min']:
			msg = 'New password for %s must be at least %d characters, submitted password has only %d.' % (user, status['acct_pwd_policy']['pwd_length_min'], len(new_pwd))
			raise self.pwd_vette_failure(user, new_pwd, msg, status)
		# Check Complexity - 3of4 and username/displayname check
		if status['acct_pwd_policy']['pwd_complexity_enforced']:
			patterns = [r'.*(?P<digit>[0-9]).*', r'.*(?P<lowercase>[a-z]).*', r'.*(?P<uppercase>[A-Z]).*', r'.*(?P<special>[~!@#$%^&*_\-+=`|\\(){}\[\]:;"\'<>,.?/]).*']
			matches = []
			for pattern in patterns:
				match = re.match(pattern, new_pwd)
				if match and match.groupdict() and match.groupdict().keys():
					matches.append(match.groupdict().keys()[0])
			if len(matches) < 3:
				msg = 'New password for %s must contain 3 of 4 character types (lowercase, uppercase, digit, special), only found %s.' % (user, (', ').join(matches))
				raise self.pwd_vette_failure(user, new_pwd, msg, status)
			# The new password must not contain user's username
			if status['user_id'].lower() in new_pwd.lower():
				msg = 'New password for %s must not contain their username.' % (user)
				raise self.pwd_vette_failure(user, new_pwd, msg, status)
			# The new password must not contain word from displayname
			for e in status['user_displayname_tokenized']:
				if len(e) > 2 and e.lower() in new_pwd.lower():
					msg = 'New password for %s must not contain a word longer than 2 characters from your name in our system (%s), found %s.' % (user, (', ').join(status['user_displayname_tokenized']), e)
					raise self.pwd_vette_failure(user, new_pwd, msg, status)
		# Encode password and attempt change. If server is unwilling, history is likely fault.
		current_pwd = unicode('\"' + current_pwd + '\"').encode('utf-16-le')
		new_pwd = unicode('\"' + new_pwd + '\"').encode('utf-16-le')
		pass_mod = [(ldap.MOD_DELETE, 'unicodePwd', [current_pwd]), (ldap.MOD_ADD, 'unicodePwd', [new_pwd])]
		try:
			self.conn.modify_s(user_dn, pass_mod)
		except ldap.CONSTRAINT_VIOLATION, e:
			# If the exceptions's 'info' field begins with:
			#  00000056 - Current passwords do not match
			#  0000052D - New password violates length/complexity/history
			msg = e[0]['desc']
			if e[0]['info'].startswith('00000056'):
				# Incorrect current password.
				raise self.authn_failure(user, self.uri)
			elif e[0]['info'].startswith('0000052D'):
				msg = 'New password for %s must not match any of the past %d passwords.' % (user, status['acct_pwd_policy']['pwd_history_depth'])
			raise self.pwd_vette_failure(user, new_pwd, msg, status)
		except ldap.LDAPError, e:
			raise self.ldap_error(e)

	def set_pwd(self, user, new_pwd):
		# Change the user's password using priv'd creds
		# They must exist, not be priv'd
		status = self.get_user_status(user)
		user_dn = status['user_dn']
		if self.is_admin(user_dn):
			raise self.user_protected(user)
		# Even priv'd user must respect min password length.
		if not len(new_pwd) >= status['acct_pwd_policy']['pwd_length_min']:
			msg = 'New password for %s must be at least %d characters, submitted password has only %d.' % (user, status['acct_pwd_policy']['pwd_length_min'], len(new_pwd))
			raise self.pwd_vette_failure(user, new_pwd, msg, status)
		new_pwd = unicode('\"' + new_pwd + '\"', "iso-8859-1").encode('utf-16-le')
		pass_mod = [((ldap.MOD_REPLACE, 'unicodePwd', [new_pwd]))]
		try:
			self.conn.modify_s(user_dn, pass_mod)
		except ldap.LDAPError, e:
			raise self.ldap_error(e)

	def force_change_pwd(self, user):
		# They must exist, not be priv'd
		status = self.get_user_status(user)
		user_dn = status['user_dn']
		if self.is_admin(user_dn):
			raise self.user_protected(user)
		if status['acct_pwd_expiry_enabled']:
			mod = [(ldap.MOD_REPLACE, 'pwdLastSet', [0])]
			try:
				self.conn.modify_s(user_dn, mod)
			except ldap.LDAPError, e:
				raise self.ldap_error(e)

	def get_user_status(self, user):
		user_base = "CN=Users,%s" % (self.base)
		user_filter = "(sAMAccountName=%s)" % (user)
		user_scope = ldap.SCOPE_SUBTREE
		status_attribs = ['pwdLastSet', 'accountExpires', 'userAccountControl', 'memberOf', 'msDS-User-Account-Control-Computed', 'msDS-UserPasswordExpiryTimeComputed', 'msDS-ResultantPSO', 'lockoutTime', 'sAMAccountName', 'displayName']
		user_status = {'user_dn':'', 'user_id':'', 'user_displayname':'', 'acct_pwd_expiry_enabled':'', 'acct_pwd_expiry':'', 'acct_pwd_last_set':'', 'acct_pwd_expired':'', 'acct_pwd_policy':'', 'acct_disabled':'', 'acct_locked':'', 'acct_locked_expiry':'', 'acct_expired':'', 'acct_expiry':'',  'acct_can_change_pwd':'', 'acct_bad_states':[]}
		bad_states = ['acct_locked', 'acct_disabled', 'acct_expired', 'acct_pwd_expired']
		try:
			# search for user
			results = self.conn.search_s(user_base, user_scope, user_filter, status_attribs)
		except ldap.LDAPError, e:
			raise self.ldap_error(e)
		if len(results) != 1: # sAMAccountName must be unique
			raise self.user_not_found(user)
		result = results[0]
		user_dn = result[0]
		user_attribs = result[1]
		uac = int(user_attribs['userAccountControl'][0])
		uac_live = int(user_attribs['msDS-User-Account-Control-Computed'][0])
		s = user_status
		s['user_dn'] = user_dn
		s['user_id'] = user_attribs['sAMAccountName'][0]
		s['user_displayname'] = user_attribs['displayName'][0]
		# AD complexity will not allow a word longer than 2 characters as part of displayName
		s['user_displayname_tokenized'] = [a for a in re.split('[,.\-_ #\t]+', s['user_displayname']) if len(a) > 2]
		# uac_live (msDS-User-Account-Control-Computed) contains current locked, pwd_expired status
		s['acct_locked'] = (1 if (uac_live & 0x00000010) else 0)
		s['acct_disabled'] = (1 if (uac & 0x00000002) else 0)
		s['acct_expiry'] = self.ad_time_to_unix(user_attribs['accountExpires'][0])
		s['acct_expired'] = (0 if datetime.datetime.fromtimestamp(s['acct_expiry']) > datetime.datetime.now() or s['acct_expiry'] == 0 else 1)
		s['acct_pwd_last_set'] = self.ad_time_to_unix(user_attribs['pwdLastSet'][0])
		s['acct_pwd_expiry_enabled'] = (0 if (uac & 0x00010000) else 1)
		# For password expiration need to determine which policy, if any, applies to this user.
		# msDS-ResultantPSO will be present in Server 2008+ and if the user has a PSO applied.
		# If not present, use the domain default.
		if 'msDS-ResultantPSO' in user_attribs and user_attribs['msDS-ResultantPSO'][0] in self.granular_pwd_policy:
			s['acct_pwd_policy'] = self.granular_pwd_policy[user_attribs['msDS-ResultantPSO'][0]]
		else:
			s['acct_pwd_policy'] = self.domain_pwd_policy
		# If account is locked, expiry comes from lockoutTime + policy lockout ttl.
		# lockoutTime is only reset to 0 on next successful login.
		s['acct_locked_expiry'] = (self.ad_time_to_unix(user_attribs['lockoutTime'][0]) + s['acct_pwd_policy']['pwd_lockout_ttl'] if s['acct_locked'] else 0)
		# msDS-UserPasswordExpiryTimeComputed is when a password expires. If never it is very high.
		s['acct_pwd_expiry'] = self.ad_time_to_unix(user_attribs['msDS-UserPasswordExpiryTimeComputed'][0])
		s['acct_pwd_expired'] = (1 if (uac_live & 0x00800000) else 0)
		for state in bad_states:
			if s[state]:
				s['acct_bad_states'].append(state)
		# If there is something in s['acct_bad_states'] not in self.can_change_pwd_states, they can't change pwd.
		s['acct_can_change_pwd'] = (0 if (len(set(s['acct_bad_states']) - set(self.can_change_pwd_states)) != 0) else 1)
		return s

	def get_pwd_policies(self):
		default_policy_container = self.base
		default_policy_attribs = ['maxPwdAge', 'minPwdLength', 'pwdHistoryLength', 'pwdProperties', 'lockoutThreshold', 'lockOutObservationWindow', 'lockoutDuration']
		default_policy_map = {'maxPwdAge':'pwd_ttl', 'minPwdLength':'pwd_length_min', 'pwdHistoryLength':'pwd_history_depth', 'pwdProperties':'pwd_complexity_enforced', 'lockoutThreshold':'pwd_lockout_threshold', 'lockOutObservationWindow':'pwd_lockout_window', 'lockoutDuration':'pwd_lockout_ttl'}
		granular_policy_container = 'CN=Password Settings Container,CN=System,%s' % (self.base)
		granular_policy_filter = '(objectClass=msDS-PasswordSettings)'
		granular_policy_attribs = ['msDS-LockoutDuration', 'msDS-LockoutObservationWindow', 'msDS-PasswordSettingsPrecedence', 'msDS-MaximumPasswordAge', 'msDS-LockoutThreshold', 'msDS-MinimumPasswordLength', 'msDS-PasswordComplexityEnabled', 'msDS-PasswordHistoryLength']
		granular_policy_map = {'msDS-MaximumPasswordAge':'pwd_ttl', 'msDS-MinimumPasswordLength':'pwd_length_min', 'msDS-PasswordComplexityEnabled':'pwd_complexity_enforced', 'msDS-PasswordHistoryLength':'pwd_history_depth', 'msDS-LockoutThreshold':'pwd_lockout_threshold', 'msDS-LockoutObservationWindow':'pwd_lockout_window', 'msDS-LockoutDuration':'pwd_lockout_ttl','msDS-PasswordSettingsPrecedence':'pwd_policy_priority'}
		if not self.conn:
			return None
		try:
			# Load domain-wide policy.
			results = self.conn.search_s(default_policy_container, ldap.SCOPE_BASE)
		except ldap.LDAPError, e:
			raise self.ldap_error(e)
		dpp = dict([(default_policy_map[k], results[0][1][k][0]) for k in default_policy_map.keys()])
		dpp["pwd_policy_priority"] = 0 # 0 Indicates don't use it in priority calculations
		self.domain_pwd_policy = self.sanitize_pwd_policy(dpp)
		# Server 2008r2 only. Per-group policies in CN=Password Settings Container,CN=System
		results = self.conn.search_s(granular_policy_container, ldap.SCOPE_ONELEVEL, granular_policy_filter, granular_policy_attribs)
		for policy in results:
			gpp = dict([(granular_policy_map[k], policy[1][k][0]) for k in granular_policy_map.keys()])
			self.granular_pwd_policy[policy[0]] = self.sanitize_pwd_policy(gpp)
			self.granular_pwd_policy[policy[0]]['pwd_policy_dn'] = policy[0]

	def sanitize_pwd_policy(self, pwd_policy):
		valid_policy_entries = ['pwd_ttl', 'pwd_length_min', 'pwd_history_depth', 'pwd_complexity_enforced', 'pwd_lockout_threshold', 'pwd_lockout_window', 'pwd_lockout_ttl', 'pwd_policy_priority']
		if len(set(valid_policy_entries) - set(pwd_policy.keys())) != 0:
			return None
		pwd_policy['pwd_history_depth'] = int(pwd_policy['pwd_history_depth'])
		pwd_policy['pwd_length_min'] = int(pwd_policy['pwd_length_min'])
		pwd_policy['pwd_complexity_enforced'] = (int(pwd_policy['pwd_complexity_enforced']) & 0x1 if pwd_policy['pwd_complexity_enforced'] not in ['TRUE', 'FALSE'] else int({'TRUE':1, 'FALSE':0}[pwd_policy['pwd_complexity_enforced']]))
		pwd_policy['pwd_ttl'] = self.ad_time_to_seconds(pwd_policy['pwd_ttl'])
		pwd_policy['pwd_lockout_ttl'] = self.ad_time_to_seconds(pwd_policy['pwd_lockout_ttl'])
		pwd_policy['pwd_lockout_window'] = self.ad_time_to_seconds(pwd_policy['pwd_lockout_window'])
		pwd_policy['pwd_lockout_threshold'] = int(pwd_policy['pwd_lockout_threshold'])
		pwd_policy['pwd_policy_priority'] = int(pwd_policy['pwd_policy_priority'])
		return pwd_policy

	def is_admin(self, search_dn, admin = 0):
		# Recursively look at what groups search_dn is a member of.
		# If we find a search_dn is a member of the builtin Administrators group, return true.
		if not self.conn:
			return None
		try:
			results = self.conn.search_s(search_dn, ldap.SCOPE_BASE, '(memberOf=*)', ['memberOf'])
		except ldap.LDAPError, e:
			raise self.ldap_error(e)
		if not results:
			return 0
		if ('CN=Administrators,CN=Builtin,'+self.base).lower() in [g.lower() for g in results[0][1]['memberOf']]:
			return 1
		for group in results[0][1]['memberOf']:
				admin |= self.is_admin(group)
				# Break early once we detect admin
				if admin:
					return admin
		return admin

	# Exception creators
	def parse_invalid_credentials(self, e, user_dn):
		if not isinstance(e, ldap.INVALID_CREDENTIALS):
			return None
		ldapcode_pattern = r".*AcceptSecurityContext error, data (?P<ldapcode>[^,]+),"
		m = re.match(ldapcode_pattern, e[0]['info'])
		if not m or not len(m.groups()) > 0 or m.group('ldapcode') not in ldapcodes:
			return self.authn_failure(e, user_dn, self.uri)
		code = m.group('ldapcode')
		if code == '525':
			return self.user_not_found(user_dn, code)
		if code == '52e':
			return self.authn_failure(user_dn, self.uri)
		if code == '530':
			return self.authn_failure_time(user_dn, self.uri)
		if code == '531':
			return self.authn_failure_workstation(user_dn, self.uri)
		if code == '532':
			return self.authn_failure_pwd_expired_natural(user_dn, self.uri)
		if code == '533':
			return self.authn_failure_acct_disabled(user_dn, self.uri)
		if code == '701':
			return self.authn_failure_acct_expired(user_dn, self.uri)
		if code == '773':
			return self.authn_failure_pwd_expired_admin(user_dn, self.uri)
		if code == '775':
			return self.authn_failure_acct_locked(user_dn, self.uri)


    class PasswordPolicy(object):
        '''
        This is the base class for AD Password Policies.
        It expects to be subclassed with _policy_attributes modified.
        The keys   to _attribute_map should remain unchanged.
        The values of _attribute_map should be the source LDAP attribute.
        If the Policy key requires special processing, it should be done in the subclass.
        '''
        _attribute_map = dict(password_min_length=None,
                              password_min_age=None,
                              password_max_age=None,
                              password_history_length=None,
                              password_complexity_enforced=None,
                              password_cleartext_available=None,
                              authfail_lockout_threshold=None,
                              authfail_lockout_window=None,
                              authfail_lockout_duration=None)
        _relative_interval_attributes = ['password_min_age',
                                         'password_max_age',
                                         'authfail_lockout_window',
                                         'authfail_lockout_duration']

        def __init__(self, policy_dict, policy_dn):
            '''
            Determine which keys in policy_dict map to the correct attribute.
            Set the resulting values as attributes of this class.
            '''
            for (policy_key, dict_key) in self._attribute_map.iteritems():
                value = policy_dict.get(dict_key, None)
                if value is not None and policy_key in self._relative_interval_attributes:
                    value = ActiveDirectoryPasswordController._relative_adinterval_to_timedelta(value)
                setattr(self, policy_key, value)
            self.policy_dn = policy_dn

        @classmethod
        def get_policy(cls, ldap_obj, policy_dn):
            '''
            Get password policy.
            '''
            policy_ldap_attributes = cls._attribute_map.values()
            result = ldap_obj.search_s(policy_dn, ldap.SCOPE_BASE, attrlist=policy_ldap_attributes)
            (policy_dn, policy_dict) = next(ActiveDirectoryPasswordController._flattened_result_generator(result))
            if not policy_dict:
                return None  # raise exception?
            return cls(policy_dict, policy_dn)


    class DomainPasswordPolicy(PasswordPolicy):
        '''
        Domain-wide password policy (pre-2008):
         - LDAP objectclass: https://msdn.microsoft.com/en-us/library/ms682209(v=vs.85).aspx
        '''
        _attribute_map = dict(password_min_length='minPwdLength',
                              password_min_age='minPwdAge',
                              password_max_age='maxPwdAge',
                              password_history_length='pwdHistoryLength',
                              password_complexity_enforced='pwdProperties',
                              password_cleartext_available='pwdProperties',
                              authfail_lockout_threshold='lockoutThreshold',
                              authfail_lockout_window='lockoutObservationWindow',
                              authfail_lockout_duration='lockoutDuration')
        _pwdproperties_options = dict(DOMAIN_PASSWORD_COMPLEX=1,
                                      DOMAIN_PASSWORD_NO_ANON_CHANGE=2,
                                      DOMAIN_PASSWORD_NO_CLEAR_CHANGE=4,
                                      DOMAIN_LOCKOUT_ADMINS=8,
                                      DOMAIN_PASSWORD_STORE_CLEARTEXT=16,
                                      DOMAIN_REFUSE_PASSWORD_CHANGE=32)

        def __init__(self, policy_dict, policy_dn):
            super(ActiveDirectoryPasswordController.DomainPasswordPolicy, self).__init__(policy_dict, policy_dn)
            self.password_complexity_enforced = self._is_complexity_enabled(self.password_complexity_enforced)
            self.password_cleartext_available = self._is_cleartext_available(self.password_cleartext_available)

        @classmethod
        def get_policy(cls, ldap_obj, policy_dn=''):
            if not policy_dn:
                policy_dn = ActiveDirectoryPasswordController._get_defaultnamingcontext(ldap_obj)
            return super(ActiveDirectoryPasswordController.DomainPasswordPolicy, cls).get_policy(ldap_obj, policy_dn)

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
            for (key, value) in cls._pwdproperties_options.iteritems():
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
        This means that ldap_obj must be authn'd by a user that is either
        a member of "Domain Admins" or has been granted read access on the
        Password Settings Container object and children.
        '''

        _attribute_map = dict(password_min_length='msDS-MinimumPasswordLength',
                              password_min_age='msDS-MinimumPasswordAge',
                              password_max_age='msDS-MaximumPasswordAge',
                              password_history_length='msDS-PasswordHistoryLength',
                              password_complexity_enforced='msDS-PasswordComplexityEnabled',
                              password_cleartext_available='msDS-PasswordReversibleEncryptionEnabled',
                              authfail_lockout_threshold='msDS-LockoutThreshold',
                              authfail_lockout_window='msDS-LockoutObservationWindow',
                              authfail_lockout_duration='msDS-LockoutDuration')

        def __init__(self, policy_dict, policy_dn):
            super(ActiveDirectoryPasswordController.GranularPasswordPolicy, self).__init__(policy_dict, policy_dn)

        @classmethod
        def get_all_policies(cls, ldap_obj, ldap_base=''):
            '''
            Make sure we can query fgpp container, then load all its child policies.
            '''
            if not ActiveDirectoryPasswordController._is_fgpp_supported(ldap_obj):
                print 'Fine Grained Password Policies not supported on your effective domain level.'
                return None
            if not ldap_base:
                ldap_base = ActiveDirectoryPasswordController._get_defaultnamingcontext(ldap_obj)
            fgpp_container_base = 'cn=Password Settings Container,cn=System,{0}'.format(ldap_base)
            result = ldap_obj.search_s(fgpp_container_base, ldap.SCOPE_BASE, '(objectclass=msDS-PasswordSettingsContainer)')
            if not result:
                print 'FGPP supported but container could not be found. Likely because you are not bound as a user with permissions to read fgpp.'
                return None
            # FGPP supported and container located. Safe to query for policies.
            result = ldap_obj.search_s(fgpp_container_base, ldap.SCOPE_SUBTREE, '(objectclass=msDS-PasswordSettings)')
            policies = dict()
            for (policy_dn, ignored) in result:
                policies[policy_dn] = super(ActiveDirectoryPasswordController.GranularPasswordPolicy, cls).get_policy(ldap_obj, policy_dn)
            return policies
