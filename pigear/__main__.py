#!/usr/bin/env python
import sys
import logging
import argparse



def _import_dotted_path(path):
    if len(path.split('.')) == 1:
        return __import__(path)
    else:
        module = __import__('.'.join(path.split('.')[:-1]))
        for subm in path.split('.')[1:-1]:
            module = getattr(module, subm)
        return getattr(module, path.split('.')[-1])


def main():
    DESCRIPRTION = "Open socket for Snort and wait for some alerts."
    parser = argparse.ArgumentParser(description=DESCRIPRTION)
    parser.add_argument(
            '--logdir',
            type=str,
            default=None,
            help=(
                "Full path to Snort's logdir. Socket is created "
                "in this directory as `snort_alert`, "
                "(Make sure that Snort will have sufficient "
                "privileges to write to this location)"))
    parser.add_argument(
            '--data-handler',
            type=str,
            default='pigear.core.DataHandler',
            dest="data_handler",
            help=("Python dotted path to data handler class."
                " `pigear.core.DataHandler` is used by default."))
    parser.add_argument(
            '--socket-handler',
            dest="socket_handler",
            type=str,
            default='pigear.core.SocketHandler',
            help=("Python dotted path to socket handler class."
                " `pigear.core.SocketHandler` is used by default."))
    parser.add_argument(
            '--serve-forever',
            dest="forever",
            action='store_true',
            help=("With this option default implementation"
                " log exception and goes for another alert."
                "Without this option exceptions are reraised"))
    parser.add_argument(
            'kwargs',
            nargs=argparse.REMAINDER,
            help=(
                "Keyword arguments for socket handler, which can pass them to "
                "data handler. In form `key=value another_key=next_value`"))
    parser.add_argument(
            '--debug',
            dest="debug",
            action='store_true',
            help="set `logging.DEBUG` level, otherwise `logging.ERROR`")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.ERROR)
    _logger = logging.getLogger(name=__file__)
    _logger.addHandler(logging.StreamHandler())
    _logger.debug("Starting pigear ...")
    try:
        SocketHandler = _import_dotted_path(args.socket_handler)
    except ImportError:
        sys.exit("Can't import `%s`" % args.socket_handler)
    try:
        DataHandler = _import_dotted_path(args.data_handler)
    except ImportError:
        sys.exit("Can't import `%s`" % args.data_handler)
    try:
        kwargs = dict([arg.split('=') for arg in args.kwargs])
    except ValueError:
        sys.exit(parser.print_help())
    socket_handler = SocketHandler(
        logdir=args.logdir,
        data_handler=DataHandler,
        kwargs=kwargs,
    )
    socket_handler.serve(forever=args.forever)

main()
