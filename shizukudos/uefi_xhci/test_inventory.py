#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Regress the actual QMP primary/secondary bus distinction; no guest launch."""
import copy
import unittest
from test_qemu import verify_pci

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.endpoint={'bus':1,'slot':0,'function':0,
            'id':{'vendor':0x1b36,'device':0x000d},
            'regions':[{'bar':0,'type':'memory','mem_type_64':True,
                        'size':0x4000,'address':0x81000000}]}
        self.bridge={'bus':0,'slot':3,'function':0,
            'pci_bridge':{'bus':{'number':0,'secondary':1,'subordinate':1},
                          'devices':[self.endpoint]}}
        self.buses=[{'bus':0,'devices':[self.bridge]}]
        self.proof={'pci_bdf':0x100,'mmio':0x81000000}

    def test_actual_qmp_primary_and_secondary_bus_shape(self):
        verify_pci(self.buses,self.proof)

    def test_wrong_endpoint_bus(self):
        self.endpoint['bus']=0
        with self.assertRaises(RuntimeError):verify_pci(self.buses,self.proof)

    def test_wrong_bridge_primary(self):
        self.bridge['pci_bridge']['bus']['number']=1
        with self.assertRaises(RuntimeError):verify_pci(self.buses,self.proof)

    def test_each_resource_contract(self):
        for key,value in (('size',0x1000),('address',0x82000000),
                          ('type','io'),('mem_type_64',False),('bar',1)):
            with self.subTest(key=key):
                buses=copy.deepcopy(self.buses)
                buses[0]['devices'][0]['pci_bridge']['devices'][0]['regions'][0][key]=value
                with self.assertRaises(RuntimeError):verify_pci(buses,self.proof)

    def test_missing_or_duplicate_controller(self):
        for endpoints in ([],[self.endpoint,self.endpoint]):
            self.bridge['pci_bridge']['devices']=endpoints
            with self.assertRaises(RuntimeError):verify_pci(self.buses,self.proof)

    def test_guest_bdf_must_match(self):
        self.proof['pci_bdf']=0x108
        with self.assertRaises(RuntimeError):verify_pci(self.buses,self.proof)

if __name__=='__main__':unittest.main()
