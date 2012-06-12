import json
import logging
import binascii
from ..core import DataHandler

_logger = logging.getLogger(name=__file__)

class HttpSendHandler(DataHandler):

    def __init__(self, url):
        self.url = url
        try:
            requests = __import__('requests')
        except ImportError:
            _logger.exception(
                "Can't import `requests` module !"
                " For installation instructions see:"
                " http://docs.python-requests.org/en/latest/index.html")
            raise
        else:
            self.post = requests.post

    def handle(self, data, addr):
        msg = super(HttpSendHandler, self).handle(data, addr)
        msg_dict = msg._asdict()
        msg_dict['pkt'] = binascii.b2a_base64(msg_dict['pkt'])
        self.send_event(self.url, alert=json.dumps(msg_dict))

    def send_event(self, url, **kwargs):
        r = self.post(url, data=kwargs)
        _logger.info(r.content)
