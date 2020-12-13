import serial


class NV10USB(object):
    INIT_ERROR = False
    SEND_STATUS = False
    ERROR = None
    SERIAL_NUMBER = None
    CHANNEL_VALUE = None
    # Generic Response
    GENERIC_RESPONSE = {
        0xF0: 'OK',
        0xF2: 'COMMAND NOT KNOWN',
        0xF3: 'WRONG No PARAMETERS',
        0xF4: 'PARAMETERS',
        0xF5: 'COMMAND CANNOT BE PROCESSED',
        0xF6: 'SOFTWARE ERROR',
        0xF8: 'FAIL',
        0xFA: 'KEY NOT SET'
    }
    # Commands
    __Sync = '0x11'  # Generic Commands
    __Reset = '0x01'  # Generic Commands
    __Host_Protocol_Version = '0x06'  # Generic Commands
    __Poll = '0x07'
    __Get_Serial_Number = '0x0C'  # Generic Commands NEED TO FIX
    __Disable = '0x09'  # Generic Commands
    __Enable = '0x0A'  # Generic Commands
    __Get_Firmware_Version = '0x20'  # Generic Commands
    __Get_Dataset_Version = '0x21'  # Generic Commands
    __Set_Inhibits = '0x02'
    __Display_On = '0x03'
    __Display_Off = '0x04'
    __Reject = '0x08'
    __Unit_Data = '0x0D'
    __Channel_Value_Data = '0x0E'
    __Channel_Security_Data = '0x0F'
    __Last_Reject_Code = '0x17'
    __Configure_Bezel = '0x54'
    __Poll_With_Ack = '0x56'
    __Event_Ack = '0x57'
    __Get_Counters = '0x58'
    __Set_Generator = '0x4A'
    __Set_Modulus = '0x4B'
    __Request_Key_Exchange = '0x4C'
    __Ssp_Set_Encryption_Key = '0x60'
    __Ssp_Encryption_Reset_To_Default = '0x61'
    __Hold = '0x18'
    __Setup_Request = '0x05'
    __High_Protocol = '0x19'

    def __init__(self, serialport='COM15'):

        self.__eSSPId = 0
        self.__sequence = '0x80'
        try:
            self.ser = serial.Serial(serialport, 9600, timeout=0.1)
        except serial.SerialException as e:
            self.ERROR = str(e)
            self.INIT_ERROR = True

    #  Magic)
    def crc(self, command):
        """
        Low and high byte of a forward CRC-16 algorithm using the Polynomial (X16 + X15 + X2
        +1) calculated on all bytes, except STX. It is initialised using the seed 0xFFFF. The CRC is
        calculated before byte stuffing.
        """
        length = len(command)
        seed = int('0xFFFF', 16)
        poly = int('0x8005', 16)
        crc = seed
        for i in range(0, length):
            crc ^= (int(command[i], 16) << 8)
            for j in range(0, 8):
                if (crc & int('0x8000', 16)):
                    crc = ((crc << 1) & int('0xffff', 16)) ^ poly
                else:
                    crc <<= 1
        crc = [hex((crc & 0xFF)), hex(((crc >> 8) & 0xFF))]
        return crc

    def send(self, command):
        seq = self.getseq()
        if type(command) == list:
            crc = self.crc([seq] + command)
        else:
            crc = self.crc([seq, '0x01', command])
        packet = bytearray()
        packet.append(0x7F)
        # print(hex(0x7F))
        packet.append(int(seq, 16))
        # print(hex(int(seq,16)))
        if type(command) == list:
            packet.append(int(command[0], 16))
            for i in command[1:]:
                packet.append(int(i, 16))
        else:
            packet.append(0x01)
            # print(hex(0x01))
            packet.append(int(command, 16))
            # print(hex(int(command, 16)))
        packet.append(int(crc[0], 16))
        # print(hex(int(crc[0], 16)))
        packet.append(int(crc[1], 16))
        # print(hex(int(crc[1], 16)))
        ##print('sending ' + str(packet))
        self.ser.write(packet)
        """Read the requested data from the serial port."""
        bytes_read = []
        # initial response length is only the header.
        expected_bytes = 3
        while True:
            byte = self.ser.read()
            if byte:
                bytes_read.append(byte)
            else:
                self.ERROR = 'Unable to read the expected response'
                return None
            if expected_bytes == 3 and len(bytes_read) >= 3:
                # extract the actual message length
                expected_bytes += ord(bytes_read[2]) + 2
            if expected_bytes > 3 and len(bytes_read) == expected_bytes:
                # we've read the complete response
                break
        ##print(bytes_read)
        first_data_byte = bytes_read[3]
        length_data_byte = bytes_read[2]
        if self.GENERIC_RESPONSE[ord(first_data_byte)] == 'OK':
            self.SEND_STATUS = True
            data = []
            for i in bytes_read[4:3 + ord(length_data_byte)]:
                data.append(i)
            return data
        else:
            self.SEND_STATUS = False
            self.ERROR = self.GENERIC_RESPONSE[ord(first_data_byte)]
            return None

    def getseq(self):
        """
        The sequence flag is used to allow the slave to determine whether a packet is a re-transmission due to its last reply being
        lost. Each time the master sends a new packet to a slave it alternates the sequence flag. If a slave receives a packet with
        the same sequence flag as the last one, it does not execute the command but simply repeats it's last reply. In a reply
        packet the address and sequence flag match the command
        packet.
        """
        # toggle SEQ between 0x80 and 0x00
        if (self.__sequence == '0x80'):
            self.__sequence = '0x00'
        else:
            self.__sequence = '0x80'

        returnseq = hex(self.__eSSPId | int(self.__sequence, 16))
        return returnseq

    def sync(self):
        """
        A Sync command resets the seq bit of the packet so that the slave device expects the next seq bit to be 0.
        The host then sets its next seq bit to 0 and the seq sequence is synchronised.
        Reset Sequence to be 0x00.
        Set ssp_sequence to 0x00, so next will be 0x80 by default
        """
        self.__sequence = '0x00'
        result = self.send(self.__Sync)
        if self.SEND_STATUS:
            return 'OK'

    def get_serial_number(self):
        data = self.send(self.__Get_Serial_Number)
        if self.SEND_STATUS:
            serial = 0
            for i in range(len(data)):
                serial += ord(data[i]) << (8 * (7 - i))
                self.SERIAL_NUMBER = serial
            return serial

    def get_firmware_version(self):
        data = self.send(self.__Get_Firmware_Version)
        if self.SEND_STATUS:
            return ''.join(list(map(lambda x: x.decode('ascii'), data)))

    def get_dataset_version(self):
        data = self.send(self.__Get_Dataset_Version)
        if self.SEND_STATUS:
            return ''.join(list(map(lambda x: x.decode('ascii'), data)))

    def enable(self):
        """Resume from disable()'d state."""
        data = self.send(self.__Enable)
        if self.SEND_STATUS:
            return 'OK'

    def disable(self):
        """Resume from disable()'d state."""
        data = self.send(self.__Disable)
        if self.SEND_STATUS:
            return 'OK'

    def setup_request(self):
        result = self.send(self.__Setup_Request)
        # print(result)
        if not self.SEND_STATUS:
            return None
        unittype = int(result[0].hex())
        # print(unittype)
        fwversion = ''
        for i in range(1, 5):
            fwversion += result[i].decode('ascii')
        # print(fwversion)
        country = ''
        for i in range(5, 8):
            country += result[i].decode('ascii')
        # print(country)
        valuemulti = 0
        for i in range(8, 11):
            valuemulti += int(result[i].hex(), 16)
        # print(valuemulti)
        channels = int(result[11].hex())
        # print(channels)
        values = []
        for i in range(0, channels):
            values.append(int(result[i + 12].hex(), 16))
            # print(result[i+12])
        security = []
        for i in range(0, channels):
            security.append(int(result[i + 12 + channels].hex()))
        multiplier_raw = b''
        for i in range(12 + 2 * channels, 12 + 2 * channels + 3):
            multiplier_raw += result[i]
        multiplier = int(multiplier_raw.hex(), 16)
        protocol = int(result[15 + 2 * channels].hex())
        unit_data = {
            'Unit type': unittype,
            'Firmware version': fwversion,
            'Country code': country,
            'Value Multiplier': valuemulti,
            'Number of channels': channels,
            'Channel Values': values,
            'Channel Security': security,
            'Real value Multiplier': multiplier,
            'Protocol version': protocol
        }
        if protocol >= 6:
            Expanded_channel_country_code = ''
            for i in range(16 + 2 * channels, 16 + 2 * channels + channels * 3):
                Expanded_channel_country_code += result[i].decode('ascii')
            Expanded_channel_value_raw = []
            Expanded_channel_value = []
            print(result[16 + 5 * channels] + result[17 + 5 * channels] + result[18 + 5 * channels] + result[
                19 + 5 * channels])
            for i in range(16 + 5 * channels, 16 + 5 * channels + channels * 4):
                Expanded_channel_value_raw.append(result[i])
            a = 0
            b = 4
            for i in range(8):
                res = b''
                r = list(reversed(Expanded_channel_value_raw[a:b]))
                for y in r:
                    res = res + y
                Expanded_channel_value.append(int(res.hex(), 16))
                a = b
                b = b + 4

            unit_data['Expanded channel country code'] = Expanded_channel_country_code
            unit_data['Expanded_channel_value'] = Expanded_channel_value
            self.CHANNEL_VALUE = dict(zip([1, 2, 3, 4, 5, 6, 7, 8], Expanded_channel_value))

        return unit_data

    def display_on(self):
        """Illuminate bezel."""
        result = self.send(self.__Display_On)
        if self.SEND_STATUS:
            return 'OK'

    def unit_data(self):
        result = self.send(self.__Unit_Data)
        if not self.SEND_STATUS:
            return None
        unittype = int(result[0].hex(), 16)
        # print(unittype)
        fwversion = ''
        for i in range(1, 5):
            fwversion += result[i].decode('ascii')
        # print(fwversion)
        country = ''
        for i in range(5, 8):
            country += result[i].decode('ascii')
        # print(country)
        valuemulti = 0
        for i in range(8, 11):
            valuemulti += int(result[i].hex(), 16)
        # print(valuemulti)
        protocol = int(result[11].hex(), 16)
        # print(protocol)
        unit_data = [unittype, fwversion, country, valuemulti, protocol]
        return unit_data

    def display_off(self):
        """Nox bezel."""
        result = self.send(self.__Display_Off)
        if self.SEND_STATUS:
            return 'OK'

    def enable_higher_protocol(self):
        """
        NOT WORK
        Enable functions from implemented with version >= 3.
        """
        result = self.send(self.__High_Protocol)
        if self.SEND_STATUS:
            return 'OK'

    def host_protocol_version(self, protocol):

        result = self.send(['0x02', self.__Host_Protocol_Version, hex(protocol)])
        if self.SEND_STATUS:
            return 'OK'

    def poll(self):
        event_table = {
            0xF1: 'Slave Reset',
            0xEF: 'Read',
            0xEE: 'Note Credit',
            0xED: 'Rejecting',
            0xEC: 'Rejected',
            0xCC: 'Stacking',
            0xEB: 'Stacked',
            0xE9: 'Unsafe Jam',
            0xE8: 'Disabled',
            0xE6: 'Fraud Attempt',
            0xE7: 'Stacker Full',
            0xE2: 'Note Cleared Into Cashbox',
            0xB5: 'Channel Disable'
        }
        result = self.send(self.__Poll)
        if not self.SEND_STATUS:
            return None
        forreturn = []
        for i in result:
            try:
                forreturn.append(event_table[int(i.hex(), 16)])
            except:
                try:
                    forreturn.append(self.CHANNEL_VALUE[int(i.hex(), 16)])
                except:
                    forreturn.append(i)
        return forreturn

    def set_inhibits(self, command):
        result = self.send([self.__Set_Inhibits] + command)
        if self.SEND_STATUS:
            return 'OK'

    def inhibit_channel(self, channel1=1, channel2=1, channel3=1, channel4=1, channel5=1, channel6=1, channel7=1,
                        channel8=1, ):
        # {1: 10, 2: 50, 3: 100, 4: 200, 5: 500, 6: 1000, 7: 2000, 8: 5000}
        res = '0b{}{}{}{}{}{}{}{}'.format(channel8, channel7, channel6, channel5, channel4, channel3, channel2,
                                          channel1)
        result = self.send([self.__Set_Inhibits, '0x02', str(hex(int(res, 2)))])
        if self.SEND_STATUS:
            return 'OK'

    def __del__(self):
        try:
            if self.ser is not None:
                self.ser.close()
        except AttributeError as e:
            pass
