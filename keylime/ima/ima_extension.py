#!/usr/bin/python3
# -*- coding: utf-8 -*-
 
import codecs
import hashlib

 
START_HASH = (codecs.decode('0'*40, 'hex'))
FF_HASH = (codecs.decode('f'*40, 'hex'))
 
START_HASH_256 = (codecs.decode('0'*64, 'hex'))
FF_HASH_256 = (codecs.decode('f'*64, 'hex'))
 
START_HASH_384 = (codecs.decode('0'*96, 'hex'))
FF_HASH_384 = (codecs.decode('f'*96, 'hex'))
 
START_HASH_512 = (codecs.decode('0'*128, 'hex'))
FF_HASH_512 = (codecs.decode('f'*128, 'hex'))
 
class Hash:
    SHA1 = 'sha1'
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'
    supported_algorithms = (SHA1, SHA256, SHA384, SHA512)
 
    @staticmethod
    def is_recognized(algorithm):
        return algorithm in Hash.supported_algorithms
 
    @staticmethod
    def compute_hash(algorithm, tohash):
        return {
                Hash.SHA1: lambda h: hashlib.sha1(h).digest(),
                Hash.SHA256: lambda h: hashlib.sha256(h).digest(),
                Hash.SHA384: lambda h: hashlib.sha384(h).digest(),
                Hash.SHA512: lambda h: hashlib.sha512(h).digest(),
            }[algorithm](tohash)
 
start_hash = {
            Hash.SHA1: START_HASH,
            Hash.SHA256: START_HASH_256,
            Hash.SHA384: START_HASH_384,
            Hash.SHA512: START_HASH_512
        }
ff_hash = {
        Hash.SHA1: FF_HASH,
        Hash.SHA256: FF_HASH_256,
        Hash.SHA384: FF_HASH_384,
        Hash.SHA512: FF_HASH_512
    }

# in case of extension of the measure in a parent namespace is needed to reconstruct the 
# extensions done in the parents changing the counter
def extension_simulation(line, hash_alg):

    runninghash = start_hash[hash_alg]
    returning_list = []

    if line == '':
        return None
    tokens = line.split(" ")
    # check on the template
    if tokens[2] != "ima-nsid-cnt":
        return None
    
    number_of_extensions = int(tokens[-1])
    for x in range(1, number_of_extensions):
        value_4 = tokens[-4].split(':')
        byte_value = codecs.decode(value_4[1], 'hex')
        value_sha1 = value_4[0] + ':' +"\x00"
        value_to_hash = bytearray(value_sha1.encode('utf-8')) + byte_value

        value_3 = tokens[-3] + '\x00'
        value_to_hash = value_to_hash + bytearray(value_3.encode('utf-8'))

        value_to_hash = value_to_hash + bytearray((tokens[-2] + str(x)).encode('utf-8'))
        value_hashed = Hash.compute_hash(hash_alg, value_to_hash)
        runninghash = Hash.compute_hash(hash_alg, runninghash + value_hashed)
        final_string = tokens[0] + " " + codecs.encode(runninghash, 'hex').decode('utf-8').lower() + " " + tokens[2] + " " + tokens[3] + " " + tokens[4] + " " + tokens[5] + " " + str(x)
        returning_list.append(final_string)
    
    return returning_list

if __name__ == '__main__':
    print("MAIN")

    line = "10 3e0c6091849a5624e5448d41a3a2070341074603 ima-nsid-cnt sha1:6db4fcee136836a4a2579b6a0986898f58d85e67 /usr/lib/modules/5.19.0-46-generic/updates/dkms/vboxdrv.ko 15 5"

    result = extension_simulation(line, Hash.SHA1)
    

    print(result)