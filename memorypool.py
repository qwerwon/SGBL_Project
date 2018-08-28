import plyvel

class MemoryPool(plyvel.DB):
    # class variable
    _memoryPool = 0
    def initialize(self):
        MemoryPool._memoryPool = plyvel.DB('/tmp/testdb/', create_if_missing=True)

    # def append(self, arg...):

    # def search(self, arg...):
