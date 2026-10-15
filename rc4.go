package rc4

/**
 * RC4 array length constant.
 */
const RC4_ARRAY_LEN uint16 = 256

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
	/* State array */
	S := make([]byte, RC4_ARRAY_LEN)
	for i := range RC4_ARRAY_LEN {
		/* Initialize S with values from 0 to 255 */
		S[i] = byte(i)
	}
	/* Key scheduling */
	j := byte(0)
	for i := range RC4_ARRAY_LEN {
		/* Update j based on the current state and key */
		k := s[i%uint16(len(s))]
		j = byte((uint16(j) + uint16(S[i]) + uint16(k)) % RC4_ARRAY_LEN)
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
func gen(S []byte, i *byte, j *byte) byte {
	/* Update i */
	*i = byte((uint16(*i) + 1) % RC4_ARRAY_LEN)
	/* Update j based on the current state */
	*j = byte((uint16(*j) + uint16(S[*i])) % RC4_ARRAY_LEN)
	/* Swap the values at indices i and j in the state array */
	swap(&S[*i], &S[*j])
	return S[(uint16(S[*i])+uint16(S[*j]))%RC4_ARRAY_LEN]
}

/**
 * Encrypts or decrypts the data using the RC4 algorithm.
 * The same function is used for both encryption and decryption
 * since RC4 generates the same keystream for both operations
 * and the XOR operation is its own inverse.
 * @param s: The key used for encryption/decryption.
 * @param data: The data to be encrypted or decrypted.
 * @return: The encrypted or decrypted data.
 */
func RC4(s []byte, data []byte) []byte {
	/* State array */
	S := ksa(s)
	var i, j byte
	for n := range data {
		/* "nextByte" of the keystream */
		nextByte := gen(S, &i, &j)
		/* XOR the data with the keystream byte
		to encrypt/decrypt */
		data[n] ^= nextByte
	}
	return data
}
