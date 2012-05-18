from __future__ import with_statement
import logging
from .constants import STRUCT_ALERTPKT


_logger = logging.getLogger(name=__file__)



class SocketHandler(object):
    defaults = {
        "logdir": "/var/log/snort/",
        "unixsock_filename": "snort_alert",
        "snort_conf": "/etc/snort/snort.conf",
    }

    def __init__(self, logdir=None, snort_conf=None):
        snort_conf = snort_conf or self.defaults['snort_conf']
        self.logdir = logdir or self.get_logdir(snort_conf)
    
    def get_logdir(self, snort_conf=None):
        snort_conf = snort_conf or self.defaults['snort_conf']
        return self.defaults['logdir']

    @staticmethod
    def _logdir_from_snort_conf(snort_conf):
        with  open(snort_conf) as snort_conf:
            for line in snort_conf:
                if line.startswith('#'):
                    continue
                else:
                    if line.startswith('config logdir:') and len(line.split()) > 2:
                        return ' '.join(line.split()[2:])


class DataHandler(object):

    _fmt = ''.join([f[1] for f in STRUCT_ALERTPKT])
    _names = [f[0] for f in STRUCT_ALERTPKT]
    _logger.debug("_fmt - %s", _fmt)
    _logger.debug("_names - %s", _names)

    def __init__(self):
        pass
