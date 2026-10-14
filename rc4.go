package rc4

/**
 * RC4 array length constant. The RC4 algorithm uses a state array of 256 bytes.
 */
const RC4_ARRAY_LEN = 256

/**
 * Swaps the values of two bytes.
 * @param a: Pointer to the first byte.
 * @param b: Pointer to the second byte.
 */
func swap(a, b *byte) {
	*a, *b = *b, *a
}

/*
 * Key Scheduling Algorithm (KSA) for RC4.
 * Initializes the state array S based on the provided key.
 * @param s: The key used for initialization.
 * @return: The initialized state array S.
 */
func ksa(s []byte) []byte {
	S := make([]byte, RC4_ARRAY_LEN)
	for i := range RC4_ARRAY_LEN {
		S[i] = byte(i)
	}
	j := byte(0)
	for i := range RC4_ARRAY_LEN {
		k := s[i%len(s)]
		j = byte((int(j) + int(S[i]) + int(k)) % RC4_ARRAY_LEN)
		swap(&S[i], &S[j])
	}
	return S
}

/**
 * Generates the next byte of the keystream.
 * @param S: The state array.
 * @param i: The index i (passed by reference).
 * @param j: The index j (passed by reference).
 * @return: The next byte of the keystream.
 */
func gen(S []byte, i, j *byte) byte {
	*i = byte((int(*i) + 1) % RC4_ARRAY_LEN)
	*j = byte((int(*j) + int(S[*i])) % RC4_ARRAY_LEN)
	swap(&S[*i], &S[*j])
	return S[(int(S[*i])+int(S[*j]))%RC4_ARRAY_LEN]
}

/**
 * Encrypts or decrypts the data using the RC4 algorithm.
 * The same function is used for both encryption and decryption since RC4 is a symmetric stream cipher.
 * @param s: The key used for encryption/decryption.
 * @param data: The data to be encrypted or decrypted.
 * @return: The encrypted or decrypted data.
 */
func RC4(s []byte, data []byte) []byte {
	S := ksa(s)
	var i, j byte
	for n := range data {
		nextByte := gen(S, &i, &j) // "nextByte" of the keystream
		data[n] ^= nextByte
	}
	return data
}
