
# TEST program for rvcgeeks's native aes module for python

from aes import *

a = b'We are Anonymous.  We are Legion.  We do not Forgive.  We do not Forget.  Expect Us !'
k = b'this is key'

if check():
  print('This processor supports aes-ni')
  print(a)
  b = encrypt(k, a)
  print(b)
  c = decrypt(k, b)
  print(c)
else:
  print('This processor does not support aes-ni')
  quit(2)
