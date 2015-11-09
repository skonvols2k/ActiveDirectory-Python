from datetime import timedelta, datetime
from collections import OrderedDict
import struct
import itertools
import pytz

import logging
logger = logging.getLogger(__name__)

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
            raise ValueError('{0} not boolean string. (true/false, t/f, 0/1)'.format(bool_str))
        return bool_str in string_true

    @classmethod
    def string_to_utf16le(cls, password):
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
