import argparse
import ctypes
import sys

from arc4 import ARC4


parser = argparse.ArgumentParser()
parser.add_argument("filename", help="File to decrypt")
parser.add_argument("-o", "--output", required=False, default="decrypted.dat", help="Output filename")
args = parser.parse_args()

def calc_hash(plaintext):
  h = 0x811c9dc5
  prime = 0x1000193
  for i in range(0, len(plaintext)):
    val = int(plaintext[i])
    h = ctypes.c_uint32(h ^ val).value
    h = ctypes.c_uint32(h * prime).value
  return h

if __name__ == "__main__":
  filename = args.filename
  try:
    with open(filename, 'rb') as f:
     contents = f.read()
  except Exception as e:
    print("Unable to open file: {e}")
    exit(1)
 
  if contents[0:4] != b'\x89PNG':
    print("Doesnt look like a png file to me...")
    exit(1)
 
  print(f"Processing png file {filename}")
  hdr_idx = 0
 
  #while True:
  for i in range(0,2): 
    try:
      hdr_idx = contents.index(b'IDAT', hdr_idx)
    except ValueError:
      # Get value error when cant find another header - so were finished
      print("Finished processing file.")
      break


  print("Found IDAT at " + str(hdr_idx))
  section_length = int.from_bytes(contents[hdr_idx-4:hdr_idx], byteorder='big')


  pt_hash = int.from_bytes(contents[hdr_idx+4:hdr_idx+8], byteorder='little')
  key_len = int(contents[hdr_idx+8])
  print(f"\tSection length: {section_length}")
  print(f"\tKey length: {key_len}")
  print(f"\tHash in image: {pt_hash}")
  key = contents[hdr_idx+9:hdr_idx+9+key_len]
  print(key)


  arc4 = ARC4(key)
  plaintext = arc4.decrypt(contents[hdr_idx+9+key_len:hdr_idx+9+section_length-5])

  h = calc_hash(plaintext)
  if h == pt_hash:
    print("Hash checks out")
    with open(args.output, 'wb') as output_file:
      output_file.write(plaintext)
