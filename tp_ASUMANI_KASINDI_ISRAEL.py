import struct

def rotr(x, n):
    """Rotation vers la droite de n bits sur un mot de 32 bits."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def rotl(x, n):
    """Rotation vers la gauche de n bits sur un mot de 32 bits."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

class AsumaniKasindiIsraelHash256:
    """
    Algorithme de hachage personnalisé pour le TP.
    Nom de l'étudiant : ASUMANI KASINDI ISRAEL
    """
    def __init__(self):
        # Valeurs initiales (H0-H7) - 8 premiers nombres premiers (racines carrées)
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        # Constantes de tour (32 constantes arbitraires basées sur des nombres irrationnels)
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
        ]

    def _pad(self, message):
        """Applique le padding au message (standard Merkle-Damgård)."""
        msg_len_bits = len(message) * 8
        message += b'\x80'
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'
        message += struct.pack('>Q', msg_len_bits)
        return message

    def _process_block(self, block):
        """Traite un bloc de 512 bits (64 octets)."""
        w = list(struct.unpack('>16I', block))
        # Expansion du message de 16 à 32 mots
        for i in range(16, 32):
            s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)

        a, b, c, d, e, f, g, h = self.h

        # 32 tours de mélange
        for i in range(32):
            # Fonctions de mélange non-linéaires simplifiées
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ch + self.k[i] + w[i]) & 0xFFFFFFFF
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Mise à jour de l'état
        self.h = [(x + y) & 0xFFFFFFFF for x, y in zip(self.h, [a, b, c, d, e, f, g, h])]

    def update(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        padded_msg = self._pad(message)
        for i in range(0, len(padded_msg), 64):
            self._process_block(padded_msg[i:i+64])
        
        return self.hexdigest()

    def hexdigest(self):
        return ''.join(f'{x:08x}' for x in self.h)

def asumani_kasindi_israel_hash(data):
    """Fonction utilitaire pour hacher une donnée."""
    hasher = AsumaniKasindiIsraelHash256()
    return hasher.update(data)

if __name__ == "__main__":
    msg = "Test de la fonction de hachage de ASUMANI KASINDI ISRAEL"
    print(f"Message: {msg}")
    print(f"Hash: {asumani_kasindi_israel_hash(msg)}")
