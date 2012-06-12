from __future__ import with_statement
import os
import socket
import struct
import logging
import inspect
import collections
from .constants import STRUCT_ALERTPKT


_logger = logging.getLogger(name=__file__)

_DEFAULTS = {
    "logdir": "/var/log/snort/",
    "unixsock_filename": "snort_alert",
    "snort_conf": "/etc/snort/snort.conf",
}


class SocketHandler(object):

    def __init__(self, logdir=None, snort_conf=None,
            data_handler=None, kwargs=None):
        self.defaults = _DEFAULTS.copy()
        snort_conf = snort_conf or self.defaults['snort_conf']
        self.logdir = logdir or self.get_logdir(snort_conf)
        self.unixsock_fullpath = os.path.join(
                self.logdir,
                self.defaults['unixsock_filename'])
        self.data_handler = data_handler or DataHandler
        if inspect.isclass(self.data_handler):
            try:
                self.data_handler = self.data_handler(
                        **(kwargs if kwargs else {}))
            except TypeError:
                _logger.exception(
                        ("Data handler class is probably "
                        "not accepting defined keyword arguments."
                        "kwargs=%s, class=%s") % (
                            str(kwargs if kwargs else {}),
                            str(self.data_handler)))
                raise

    def get_socket(self):
        return socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    def bind_socket(self, socket):
        try:
            os.remove(self.unixsock_fullpath)
        except OSError:
            pass
        socket.bind(self.unixsock_fullpath)

    def serve(self, forever=True):
        try:
            self._serve(forever=forever)
        except:
            self.socket.close()
            raise

    def _serve(self, forever):
        while True:
            try:
                (data, addr) = self.socket.recvfrom(
                        self.data_handler.msg_size)
                self.data_handler.handle(data, addr)
            except Exception as e:
                _logger.exception("Data struct unpacking error")
                if not forever:
                    raise e

    @property
    def socket(self):
        try:
            return self._socket
        except AttributeError:
            try:
                self._socket = self.get_socket()
                self.bind_socket(self._socket)
                return self._socket
            except OSError:
                _logger.exception(
                    "Can't bind snort socket [%s]",
                    self.unixsock_fullpath)
                raise Exception("... game over ...")

    def get_logdir(self, snort_conf=None):
        snort_conf = snort_conf or self.defaults['snort_conf']
        return self.logdir_from_snort_conf(
                snort_conf) or self.defaults['logdir']

    @staticmethod
    def logdir_from_snort_conf(snort_conf):
        with  open(snort_conf) as snort_conf:
            for line in snort_conf:
                if line.startswith('#'):
                    continue
                else:
                    if line.startswith(
                            'config logdir:') and len(line.split()) > 2:
                        return ' '.join(line.split()[2:])


class DataHandler(object):

    _fmt = ''.join([f[1] for f in STRUCT_ALERTPKT])
    _names = [f[0] for f in STRUCT_ALERTPKT]
    msg_size = struct.calcsize(_fmt)
    AlertMessage = collections.namedtuple('AlertMessage', _names)
    _logger.debug("_fmt - %s", _fmt)
    _logger.debug("_names - %s", _names)

    def handle(self, data, addr):
        msg = self.AlertMessage._make(
                struct.unpack(
                    self._fmt,
                    data[:self.msg_size]))
        _logger.debug("".join(
            ["\n%s: %s" % (
                name,
                getattr(msg, name)) for name in self._names if name != 'pkt']))
        return msg
