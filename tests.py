from private_notes import PrivNotes

p = PrivNotes("correct")
p.set("First", "Hello")
p.set("Second", "World")

data, checksum = p.dump()

q = PrivNotes("correct", data, checksum)

assert q.get("First") == "Hello"
assert q.get("Second") == "World"

q.set("Third", "Another note")

assert q.get("Third") == "Another note"