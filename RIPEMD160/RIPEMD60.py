import hashlib

# creating the hash object
hash = hashlib.new('ripemd160')
print(hash)

# putiing data to be hashed
hash.update(b'Hello World!')
x = hash.digest()
print(x)

# seeing the digest tin hexadecimal
size = hash.block_size
print(size)

# getting the digest size
digest_size = hash.digest_size
print(digest_size)

# notice that the igest size is smaller than the block size.