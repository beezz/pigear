#!/usr/bin/env python
import os
import sys
import unittest

def main():
    sys.path.insert(0, os.path.dirname(__file__))
    from tests import (
        SocketHandlerTests,
    )
    suite = unittest.TestLoader().loadTestsFromTestCase(SocketHandlerTests)
    unittest.TextTestRunner(verbosity=2).run(suite)



if __name__ == '__main__':
    main()
