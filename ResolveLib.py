import base64
import collections
import functools
import socket
import zlib

from heapq import nsmallest
from operator import itemgetter
from string import maketrans

try:
    from collections import Counter
except ImportError:
    from counter import Counter

def lru_cache (maxsize=128):
    '''Least-recently-used cache decorator.

    Arguments to the cached function must be hashable.
    Cache performance statistics stored in f.hits and f.misses.
    http://en.wikipedia.org/wiki/Cache_algorithms#Least_Recently_Used

    '''
    def decorating_function (user_function):
        cache = collections.OrderedDict()    # order: least recent to most recent

        @functools.wraps(user_function)
        def wrapper(*args, **kwds):
            key = args
            if kwds:
                key += tuple(sorted(kwds.items()))
            try:
                result = cache.pop(key)
                wrapper.hits += 1

            except KeyError:
                result = user_function(*args, **kwds)
                wrapper.misses += 1
                if len(cache) >= maxsize:
                    cache.popitem(0)    # purge least recently used cache entry

            cache[key] = result         # record recent use of this key
            return result

        wrapper.hits = wrapper.misses = 0
        return wrapper

    return decorating_function


def lfu_cache (maxsize=128):
    '''Least-frequenty-used cache decorator.

    Arguments to the cached function must be hashable.
    Cache performance statistics stored in f.hits and f.misses.
    Clear the cache with f.clear().
    http://en.wikipedia.org/wiki/Least_Frequently_Used

    '''
    def decorating_function (user_function):
        cache = {}                        # mapping of args to results
        use_count = Counter()             # times each key has been accessed
        kwarg_mark = object()             # separate positional and keyword args

        @functools.wraps(user_function)
        def wrapper (*args, **kwargs):
            key = args
            if kwargs:
                key += (kwarg_mark,) + tuple(sorted(kwargs.items()))

            # get cache entry or compute if not found
            try:
                result = cache[key]
                use_count[key] += 1
                wrapper.hits += 1

            except KeyError:
                # need to add something to the cache, make room if necessary
                if len(cache) == maxsize:
                    for k, _ in nsmallest(maxsize // 10 or 1,
                                            use_count.iteritems(),
                                            key=itemgetter(1)):
                        del cache[k], use_count[k]
                result = user_function(*args, **kwargs)
                cache[key] = result
                use_count[key] += 1
                wrapper.misses += 1

            return result

        def clear():
            cache.clear()
            use_count.clear()
            wrapper.hits = wrapper.misses = 0

        wrapper.hits = wrapper.misses = 0
        wrapper.clear = clear
        wrapper.cache = cache
        return wrapper

    return decorating_function


#@lfu_cache(maxsize=1024)
def get_hostname (ip):

    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip


#@lfu_cache(maxsize=1024)
def decode_frontier (query):

    char_translation = maketrans(".-_", "+/=")
    url_parts = query.split ("encoding=BLOB")

    if len(url_parts) > 1:

        url = url_parts[1].split("&p1=", 1)
        encparts = url[1].split("&", 1)
        if len(encparts) > 1:
            ttlpart = "&" + encparts[1]
        else:
            ttlpart = ""
        encoded_query = encparts[0].translate(char_translation)
        try:
            decoded_query = zlib.decompress (base64.binascii.a2b_base64 (encoded_query)).strip()
        except zlib.error:
            decoded_query = encoded_query
    else:
        decoded_query = query

    return decoded_query

