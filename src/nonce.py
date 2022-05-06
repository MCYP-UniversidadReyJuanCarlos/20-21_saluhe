import itertools
import random
import string
from time import gmtime, strftime

#Constants
time_fmt = '%Y-%m-%dT%H:%M:%SZ'
time_str_len = len('0000-00-00T00:00:00Z')
NONCE_CHARS = string.ascii_letters + string.digits

#Generate and return a nonce salt.
#   @param length: Length of the generated string.
#   @type length: int
#   @rtype: six.text_type    
def make_nonce_salt(length=6):   
    sys_random = random.SystemRandom()
    random_chars = itertools.starmap(sys_random.choice, itertools.repeat((NONCE_CHARS, ), length))
    return ''.join(random_chars)

#Generate a nonce with the current timestamp
#   @param when: timestamp representing the issue time of the nonce. Defaults to the current time.
#   @type when: int
#   @returntype: six.text_type
#   @returns: A string that should be usable as a one-way nonce
#   @see: time
def mkNonce(when=None):   
    if when is None:
        t = gmtime()
    else:
        t = gmtime(when)

    #timestamp to string according to a format
    time_str = strftime(time_fmt, t)
    return time_str + make_nonce_salt()