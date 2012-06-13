#############################################################
Pigear: Open socket for Snort(NIDS) and wait for some alerts.
#############################################################

**Pigear** is meant to provide interface for `Snort(NIDS)'s <http://www.snort.org/>`_ unix socket.
You can use **Pigear** to listen on snort's socket and then handle alert's appropriately. Default implementation
only turns binary data from socket into ``AlertMessage`` structure which refers to snort's C structure.

With `IPython <http://ipython.org/>`_ installed you can use **Pigear** for real-time examination of alerts.


Example::
    
    $ sudo python -m pigear --data-handler pigear.contrib.IPythonDataHandler
    ##################################################################################
    IPython data handler initialized.
    On Snort's alert, IPython shell is spawned for you.
    Alert is present as ``msg`` variable in current scope.
    ##################################################################################

    Python 2.7.3 (default, Apr 20 2012, 22:44:07) 
    Type "copyright", "credits" or "license" for more information.

    IPython 0.12.1 -- An enhanced Interactive Python.
    ?         -> Introduction and overview of IPython's features.
    %quickref -> Quick reference.
    help      -> Python's own help system.
    object?   -> Details about 'object', use 'object??' for extra details.

    In [1]: msg.
    msg.caplen           msg.count            msg.msg                        
    msg.classification   msg.data             msg.nethdr                     
    msg.dlthdr           msg.event_reference  msg.priority         
    msg.event_id         msg.index            msg.sig_generator    
    msg.pkt              msg.transhdr         msg.ts_usec
    msg.pktlen           msg.ts_sec           msg.tv_sec 
    msg.sig_id           msg.tv_usec                     
    msg.sig_rev          msg.val                         

    In [1]: msg.priority
    Out[1]: 2

    In [2]: print(msg.msg)
    VOIP-SIP-UDP From header unquoted tokens in field attempt


Or if you want to send alerts as json to remote http server there's `HttpSendHandler` class,
you'll nedd `requests <https://github.com/kennethreitz/requests/>`_ for this::

   $ sudo python -m pigear --debug --data-handler pigear.contrib.HttpSendHandler url=http://httpbin.org/post


************
Installation
************

Clone this repo and run::

    $ python setup.py install

Or use pip::

    $ pip install -e git://github.com/beezz/pigear.git#egg=pigear


*****
Usage
*****

Module script usage::

    $ python -m pigear --help
    usage: __main__.py [-h] [--logdir LOGDIR] [--data-handler DATA_HANDLER]
                    [--socket-handler SOCKET_HANDLER] [--serve-forever]
                    [--debug]
                    ...

    Open socket for Snort and wait for some alerts.

    positional arguments:
    kwargs                Keyword arguments for socket handler, which can pass
                            them to data handler. In form `key=value
                            another_key=next_value`

    optional arguments:
    -h, --help            show this help message and exit
    --logdir LOGDIR       Full path to Snort's logdir. Socket is created in this
                            directory as `snort_alert`, (Make sure that Snort will
                            have sufficient privileges to write to this location)
    --data-handler DATA_HANDLER
                            Python dotted path to data handler class.
                            `pigear.core.DataHandler` is used by default.
    --socket-handler SOCKET_HANDLER
                            Python dotted path to socket handler class.
                            `pigear.core.SocketHandler` is used by default.
    --serve-forever       With this option default implementation log exception
                            and goes for another alert.Without this option
                            exceptions are reraised
    --debug               set `logging.DEBUG` level, otherwise `logging.ERROR`
