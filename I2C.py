#!/usr/bin/env python
# encoding: utf-8
"""
Created by Sean Nelson on 2009-10-14.
Copyright 2009 Sean Nelson <audiohacked@gmail.com>

This file is part of pyBusPirate.

pyBusPirate is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyBusPirate is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyBusPirate.  If not, see <http://www.gnu.org/licenses/>.
"""

from .BitBang import BBIO


class I2CSpeed:
    _400KHZ = 0x03
    _100KHZ = 0x02
    _50KHZ = 0x01
    _5KHZ = 0x00


class I2CPins:
    POWER = 0x8
    PULLUPS = 0x4
    AUX = 0x2
    CS = 0x1


class I2C(BBIO):
    bulk_read = None

    def __init__(self, port, speed, timeout=1):
        BBIO.__init__(self, port, speed, timeout)

    def send_start_bit(self):
        self.port.write("\x02")
        return self.response()

    def send_stop_bit(self):
        self.port.write("\x03")
        return self.response()

    def read_byte(self):
        self.port.write("\x04")
        return self.response(1, True)

    def send_ack(self):
        self.port.write("\x06")
        return self.response()

    def send_nack(self):
        self.port.write("\x07")
        return self.response()

    def bus_sniffer_start(self):
        """
        Sniff traffic on an I2C bus.

          [/] - Start/stop bit
          \ - escape character precedes a data byte value
          +/- - ACK/NACK

        Sniffed traffic is encoded according to the table above.
        Data bytes are escaped with the '\' character.

        Send a single byte to exit, Bus Pirate responds 0x01 on exit.
        """

        self.port.write(chr(0b00001111))

    def bus_sniffer_read(self):
        """return a single significant octet"""
        val = self.response(1, True)
        if val == '\\':
            val = self.response(1, True)
            val = '0x%02' % val
        return val

    def bus_sniffer_stop(self):
        """exit the sniffer mode"""
        self.port.write(chr(0x00))
        if self.response(1) == 0x01:
            return True
        else:
            return False
