from ..attribute import ActiveDirectoryAttribute

from datetime import datetime, timedelta
import pytz

import unittest2 as unittest

class TestActiveDirectoryAttribute(unittest.TestCase):

    def test_relativeinterval_never_zero(self):
        interval = '0'
        result = ActiveDirectoryAttribute.relative_adinterval_to_timedelta(interval)
        self.assertIsNone(result)
        
    def test_relativeinterval_never_inf(self):
        interval = '-9223372036854775808'
        result = ActiveDirectoryAttribute.relative_adinterval_to_timedelta(interval)
        self.assertIsNone(result)

    def test_relativeinterval_5mins(self):
        interval = '-3000000000'
        correct_timedelta = timedelta(minutes=5)
        result = ActiveDirectoryAttribute.relative_adinterval_to_timedelta(interval)
        self.assertEqual(result, correct_timedelta)

    def test_relativeinterval_180days(self):
        interval = '-155520000000000'
        correct_timedelta = timedelta(days=180)
        result = ActiveDirectoryAttribute.relative_adinterval_to_timedelta(interval)
        self.assertEqual(result, correct_timedelta)
    
    def test_absoluteinterval_never_zero(self):
        interval = '0'
        result = ActiveDirectoryAttribute.absolute_adinterval_to_datetime(interval)
        self.assertIsNone(result)

    def test_absoluteinterval_never_inf(self):
        interval = '9223372036854775807'
        result = ActiveDirectoryAttribute.absolute_adinterval_to_datetime(interval)
        self.assertIsNone(result)

    def test_absoluteinterval_20151116(self):
        interval = '130921524000000000'
        correct_datetime = datetime(2015, 11, 16, 13, 0, tzinfo=pytz.utc)
        result = ActiveDirectoryAttribute.absolute_adinterval_to_datetime(interval)
        self.assertEqual(result, correct_datetime)
    
    def test_absoluteinterval_20160629(self):
        interval = '130800589109016937'
        correct_datetime = datetime(2015, 6, 29, 13, 41, 50, tzinfo=pytz.utc)
        result = ActiveDirectoryAttribute.absolute_adinterval_to_datetime(interval)
        self.assertEqual(result, correct_datetime)

    def test_boolstr_true(self):
        boolstr = 'TrUe'
        result = ActiveDirectoryAttribute.string_to_boolean(boolstr)
        self.assertTrue(result)
    
    def test_boolstr_false(self):
        boolstr = 'FALSE'
        result = ActiveDirectoryAttribute.string_to_boolean(boolstr)
        self.assertFalse(result)
    
    def test_boolstr_bad_1(self):
        boolstr = 'True1'
        self.assertRaises(ValueError, ActiveDirectoryAttribute.string_to_boolean, boolstr)

    def test_utf16le_utf8(self):
        test_str = u'\xdfetablockers'
        correct_str = '"\x00\xdf\x00e\x00t\x00a\x00b\x00l\x00o\x00c\x00k\x00e\x00r\x00s\x00"\x00'
        result = ActiveDirectoryAttribute.string_to_utf16le(test_str)
        self.assertEqual(result, correct_str)

    def test_useraccountcontrol_combined(self):
        uaccomputed_str = '8388608'
        uac_str = '514'
        uac_str = str(int(uac_str) + int(uaccomputed_str))
        uac_dict = {
                'UF_ACCOUNTDISABLE': True,
                'UF_DONT_EXPIRE_PASSWD': False,
                'UF_DONT_REQUIRE_PREAUTH': False,
                'UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED': False,
                'UF_HOMEDIR_REQUIRED': False,
                'UF_INTERDOMAIN_TRUST_ACCOUNT': False,
                'UF_LOCKOUT': False,
                'UF_MNS_LOGON_ACCOUNT': False,
                'UF_NORMAL_ACCOUNT': True,
                'UF_NOT_DELEGATED': False,
                'UF_PARTIAL_SECRETS_ACCOUNT': False,
                'UF_PASSWD_CANT_CHANGE': False,
                'UF_PASSWD_NOTREQD': False,
                'UF_PASSWORD_EXPIRED': True,
                'UF_SCRIPT': False,
                'UF_SERVER_TRUST_ACCOUNT': False,
                'UF_SMARTCARD_REQUIRED': False,
                'UF_TEMP_DUPLICATE_ACCOUNT': False,
                'UF_TRUSTED_FOR_DELEGATION': False,
                'UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION': False,
                'UF_USE_AES_KEYS': False,
                'UF_USE_DES_KEY_ONLY': False,
                'UF_WORKSTATION_TRUST_ACCOUNT': False}
        result = ActiveDirectoryAttribute.parse_useraccountcontrol(uac_str)
        self.maxDiff = None
        self.assertEqual(result, uac_dict)
    
    def test_useraccountcontrol_simple(self):
        uac_str = '514'
        uac_dict = {
                'UF_ACCOUNTDISABLE': True,
                'UF_DONT_EXPIRE_PASSWD': False,
                'UF_DONT_REQUIRE_PREAUTH': False,
                'UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED': False,
                'UF_HOMEDIR_REQUIRED': False,
                'UF_INTERDOMAIN_TRUST_ACCOUNT': False,
                'UF_LOCKOUT': False,
                'UF_MNS_LOGON_ACCOUNT': False,
                'UF_NORMAL_ACCOUNT': True,
                'UF_NOT_DELEGATED': False,
                'UF_PARTIAL_SECRETS_ACCOUNT': False,
                'UF_PASSWD_CANT_CHANGE': False,
                'UF_PASSWD_NOTREQD': False,
                'UF_PASSWORD_EXPIRED': False,
                'UF_SCRIPT': False,
                'UF_SERVER_TRUST_ACCOUNT': False,
                'UF_SMARTCARD_REQUIRED': False,
                'UF_TEMP_DUPLICATE_ACCOUNT': False,
                'UF_TRUSTED_FOR_DELEGATION': False,
                'UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION': False,
                'UF_USE_AES_KEYS': False,
                'UF_USE_DES_KEY_ONLY': False,
                'UF_WORKSTATION_TRUST_ACCOUNT': False}
        result = ActiveDirectoryAttribute.parse_useraccountcontrol(uac_str)
        self.maxDiff = None
        self.assertEqual(result, uac_dict)

    def test_samaccounttype_user(self):
        samtype_str = '805306368'
        result = ActiveDirectoryAttribute.parse_samaccounttype(samtype_str)
        self.assertEqual(result, 'SAM_USER_OBJECT')

    def test_logonhours_allallowed(self):
        # TODO: Generate complex logonhours then create test for that.
        self.assertEqual(True, 'Fixme later')
        
