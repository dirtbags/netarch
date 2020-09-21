#! /usr/bin/python3

import netarch

class DumbPacket(netarch.Packet):
	def parse(self, data):
		self.payload = data

class DumbSession(netarch.Session):
	Packet = DumbPacket

netarch.main(DumbSession)
