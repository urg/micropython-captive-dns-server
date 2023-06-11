import sys

sys.path.insert(0, 'src')
sys.path.insert(2, 'libs/micropython')

import unittest

if not unittest.main('test').wasSuccessful():
    sys.exit(1)
