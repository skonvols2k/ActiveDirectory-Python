from .attribute import ActiveDirectoryAttribute

import logging
logger = logging.getLogger(__name__)

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
        old_entry = dict(unicodePwd=ActiveDirectoryAttribute.string_to_utf16le(current_password))
        new_entry = dict(unicodePwd=ActiveDirectoryAttribute.string_to_utf16le(new_password))
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
        # I don't know how to generate a MOD_REPLACE modlist except by hand.
        password_modlist = [(ldap.MOD_REPLACE, 'unicodePwd', [new_password])]
        try:
            adldap_obj.modify_s(self.user_dn, password_modlist)
        except ldap.CONSTRAINT_VIOLATION as e:
            raise ActiveDirectoryLDAPConnection.CONSTRAINT_VIOLATION(e)

    def get_user_password_policy(self, adldap_obj):
        '''
        Prefer msDS-ResultantPSO, fall back to domain policy.

        TODO: Make less fragile - expects adldap_obj to have policies loaded.
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
            if adldap_obj.check_domainlevel(level):
                available_attributes.append(attribute)
        return available_attributes
