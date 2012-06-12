import os
import socket
import unittest
from pigear.core import SocketHandler 


class SocketHandlerTests(unittest.TestCase):

    def setUp(self):
        self.data = open(
            os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    'data',
                    'test_alert'
                )
            ),
            'rb',
        ).read()
        self.sh = SocketHandler(logdir=os.path.dirname(__file__))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    def test_data(self):
        self.assertTrue(self.data)
