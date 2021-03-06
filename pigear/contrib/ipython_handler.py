import sys
import logging
from ..core import DataHandler

_logger = logging.getLogger(name=__file__)

class IPythonDataHandler(DataHandler):

    def __init__(self):
        try:
            IPython = __import__('IPython')
        except ImportError:
            _logger.exception(
                "Can't import `IPython` module !"
                " For installation instructions see:"
                " http://ipython.org/index.html")
            raise
        else:
            self.embed = IPython.embed
        sys.stdout.write(
            "\n".join([
                82 * "#",
                "IPython data handler initialized.",
                "On Snort's alert, IPython shell is spawned"
                " for you.",
                "Alert is present as ``msg`` variable in current scope.",
                82 * "#",
                "\n"
            ])
        ) 


    def handle(self, data, addr):
        msg = super(IPythonDataHandler, self).handle(data, addr)
        self.embed()
