import pickle
import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PrivNotes:
  MAX_NOTE_LEN = 2048;

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str) : password for accessing the notes
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """
    if data is None:
      self.kvs = {}
      self.salt = os.urandom(16)
      self.nonce_counter = 0
    else:
      try:
        raw_data = bytes.fromhex(data)

        if len(raw_data) < 48:
          raise ValueError("Invalid serialized data")

        if checksum is not None:
          digest = hashes.Hash(hashes.SHA256())
          digest.update(raw_data)
          expected = digest.finalize()

          if not bytes_eq(expected, bytes.fromhex(checksum)):
            raise ValueError()

        self.salt = raw_data[:16] # extract salt
        self.auth_tag = raw_data[16:48]
        serialized_state = raw_data[48:]

      except:
        raise ValueError("Invalid serialized data")
        
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, iterations = 2000000)
    self.big_key = kdf.derive(bytes(password, 'ascii'))

    h1 = hmac.HMAC(self.big_key, hashes.SHA256())
    h1.update(b'dictionary')
    self.dict_key = h1.finalize()

    h2 = hmac.HMAC(self.big_key, hashes.SHA256())
    h2.update(b'notes')
    self.notes_key = h2.finalize()

    h3 = hmac.HMAC(self.big_key, hashes.SHA256())
    h3.update(b'authentication')
    self.auth_key = h3.finalize()

    if data is not None:
      h = hmac.HMAC(self.auth_key, hashes.SHA256())
      h.update(self.salt + serialized_state)
      expected_tag = h.finalize()

      if not bytes_eq(expected_tag, self.auth_tag):
        raise ValueError("Incorrect password or modified data")

      try:
        state = pickle.loads(serialized_state)

        kvs = state["kvs"]
        counter = state["nonce_counter"]

        if not isinstance(kvs, dict):
          raise ValueError("Invalid dictionary")

        if type(counter) is not int:
          raise ValueError("Invalid nonce counter")

        self.kvs = kvs
        self.nonce_counter = counter
      except:
        raise ValueError("Malformed serialized state")

  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    serialized = {
      "kvs": self.kvs,
      "nonce_counter": self.nonce_counter
    }

    serialized_state = pickle.dumps(serialized)

    h = hmac.HMAC(self.auth_key, hashes.SHA256())
    h.update(self.salt + serialized_state)
    tag = h.finalize()

    raw_data = self.salt + tag + serialized_state
    ser_data = raw_data.hex()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw_data)
    checksum = digest.finalize().hex()

    return ser_data, checksum


  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    title_key = self._title_key(title)

    if title_key in self.kvs:
      record = self.kvs[title_key]

      nonce = record[:12]
      ciphertext = record[12:]

      aesgcm = AESGCM(self.notes_key)
      plaintext = aesgcm.decrypt(nonce, ciphertext, title_key)

      return self._decode_note(plaintext)
    
    return None

  def set(self, title, note):
    """Associates a note with a title and adds it to the database
       (or updates the associated note if the title is already
       present in the database).
       
       Args:
         title (str) : the title to set
         note (str) : the note associated with the title

       Returns:
         None

       Raises:
         ValueError : if note length exceeds the maximum
    """
    title_key = self._title_key(title)

    padded_note = self._encode_note(note)

    nonce = self.nonce_counter.to_bytes(12, 'little')
    aesgcm = AESGCM(self.notes_key)
    encrypted_notes = aesgcm.encrypt(nonce, padded_note, title_key)

    self.nonce_counter += 1

    self.kvs[title_key] = nonce + encrypted_notes


  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """
    title_key = self._title_key(title)

    if title_key in self.kvs:
      del self.kvs[title_key]
      return True

    return False

  def _title_key(self, title):
    h = hmac.HMAC(self.dict_key, hashes.SHA256())
    h.update(title.encode('ascii'))
    return h.finalize()

  def _encode_note(self, note):
    note_bytes = note.encode('ascii')

    if len(note_bytes) > self.MAX_NOTE_LEN:
      raise ValueError("Invalid note length")

    length_prefix = len(note_bytes).to_bytes(2, 'little')
    padding = bytes(self.MAX_NOTE_LEN - len(note_bytes))

    return length_prefix + note_bytes + padding

  def _decode_note(self, plaintext):
    if len(plaintext) != self.MAX_NOTE_LEN + 2:
      raise ValueError("Invalid encoded note length")

    note_length = int.from_bytes(plaintext[:2], 'little')

    if note_length > self.MAX_NOTE_LEN:
      raise ValueError("Invalid note length")

    note_bytes = plaintext[2:2 + note_length]

    return note_bytes.decode('ascii')