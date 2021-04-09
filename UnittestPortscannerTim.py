import unittest
from unittest import mock
from PortscannerTim import ScannerInput
from PortscannerTim import MySQLtable

### Onjuiste input is al afgevangen in de code zelf. Unittesting heeft hier weinig toegevoegde waarde.
class ActivityTests(unittest.TestCase):
    def setup(self):
        self.IPadres = ScannerInput()
    
    def tearDown(self):
        self.IPadresempty()

    def fix_dbc(self):
        dbc = self.fix_dbc()
        rows = self.fix_rows()
        self.assertTrue(con.cursor.called)

if __name__ == "__main__":
    unittest.main()