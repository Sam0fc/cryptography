"""
Author: Sam Hutton
Project: Cryptography
Date: 2020-09-30
Description: This program implements 2 common ciphers and the Merkle-Hellman Knapsack Cryptosystem
(MKHC). It includes methods for each of these. The Caesar and Vignere Ciphers implemented only function
on uppercase ASCII alphabetical input, and the MKHC should work on all ascii, despite not being fully tested on
characters other than uppercase alphabetical input.
Each cipher or crytosystem has an encrypt and decrypt method, and since MKHC is a public key cryptosystem,
it has a method to generate a private key and create a public key from a private key.
Notes:
No known bugs. The main takes in an input and echoes it back, along with the MKHC encrypted representation.
"""

#import some stuff
import random
import math
import binascii

# Finals
ASCII_LETTER_START = 65 # Where letters start in ASCII (used for both Vignere and Caesar )
LENGTH_ALPHABET = 26 # Used for wrapping in Caesar and Vignere ciphers.
INITIAL_RANDOM_CEILING = 100 # When generating the superincreasing sequence for MKHC

# Caesar Cipher
# Will shift any text by some integer offset in the alphabet, and wrap around
# Takes in a string to encode, and an integer offset, returns the encrypted string
# Arguments: string, integer
# Returns: string
def encrypt_caesar(plaintext, offset):
	return aux_caesar(plaintext,offset,True)

# Decrypt Caesar Cipher
# Shifts by a negative offset, wrapping
# Takes in an encoded string and an integer offset
# Arguments: string, integer
# Returns: string
def decrypt_caesar(ciphertext, offset):
	return aux_caesar(ciphertext,offset,False)

# Since both are the same algorithms with only -offset,
# this function does the shift, but takes in a boolean,
# that determines whether it is encrypting or
# decoding
# Arguments: string, integer, boolean
# Returns: string
def aux_caesar(plaintext,offset,encrypt):
		#empty string to fill with encrypted text
		new_text = ""

		#for every letter in the input
		for letter in plaintext.upper():
			#if the letter is alphabetical, offset it, and then add to the output string
			if letter.isalpha():
				letter = doLetterOffset(letter,offset,encrypt)
			new_text += letter
		return new_text

# Vigenere Cipher
# Shifts by an offset of a looping key.
# Takes in a string to encode and a string to act as a key
# Arguments: string, string
# Returns: string
def encrypt_vigenere(plaintext, keyword):
	return aux_vigenere(plaintext, keyword, True)

# Decrypt function
# Arguments: string, string
# Returns: string
def decrypt_vigenere(ciphertext, keyword):
	return aux_vigenere(ciphertext, keyword, False)


# Since both are the same algorithms with only -offset,
# this function does the shift, but takes in a boolean,
# that determines whether it is encrypting or
# decoding
# Arguments: string, integer, boolean
# Returns: string
def aux_vigenere(ciphertext,keyword,encrypt):
	# make sure everything is uppercase
	new_text = ""
	keyword=keyword.upper()
	ciphertext=ciphertext.upper()

	#for all letters in the text, work out the offset from the keyword, and then perform the offset
	for index,letter in enumerate(ciphertext):
		#the offset is from the start of the alphabet as an int.
		offset = ord(keyword[index%len(keyword)]) - ASCII_LETTER_START
		if letter.isalpha():
			letter = doLetterOffset(letter,offset,encrypt)
		new_text += letter
	return new_text

# Helper function that offsets a letter.
# If the encrypt boolean is false, the offset will be put negative.
# Arguments: string, integer, boolean
# Returns: string
def doLetterOffset(letter,offset,encrypt):
	#if decoding, flip the offset
	if not (encrypt):
		offset = -1 * offset

	#work out how far from the start of the alphabet the number is,
	#add the offset, and then do the mod to work out which new letter is mapped on.
	num_letter = ord(letter) - ASCII_LETTER_START
	offset_num_letter = (num_letter + offset)%LENGTH_ALPHABET
	letter = chr(offset_num_letter + ASCII_LETTER_START)
	return letter

# Merkle-Hellman Knapsack Cryptosystem
# This generates a private key, by making a superincreasing sequence, and then a co-prime
# integer from the last number in the sequnce.
# Arguments: integer
# Returns: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
def generate_private_key(n=8):
	W,Q = genSincSequence(n)
	R = makeCoPrime(Q)
	return (W,Q,R)

# Generates a random superincreasing sequence, and an extra term at the end.
# Arguments: integer
# Returns: Array of integers, integer
def genSincSequence(n):
	sinc_sequence=[]

	#get a random number between 1 and 100
	inital_number = random.randint(1,INITIAL_RANDOM_CEILING)
	sinc_sequence.append(inital_number)
	running_total = 0

	#for every space in the list, generate a new number for a superincreasing sinc_sequence,
	#by keeping a running total.
	for (i) in range(n):
		running_total+=sinc_sequence[i]
		sinc_sequence.append(random.randint(running_total+1,running_total*2))

	#return this sequence and another extra term for the end.
	running_total+=sinc_sequence[-1]
	return sinc_sequence , random.randint(running_total+1,running_total*2)

# Brute forces the coprime to the integer
# Arguments: integer
# Returns: integer
def makeCoPrime(Q):
	done = False

	# generates a random number between 2 and Q-1, until they are
	# coprime
	while not done:
		R = random.randint(2,Q-1)
		done = (math.gcd(Q,R) == 1)
	return R

# Create a public key based on a private key.
# Arguments: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
# Returns: tuple B - a length-n tuple of integers
def create_public_key(private_key):
	B = []

	#for all the items in the W list, add R * Wi modulo Q
	for item in (private_key[0]):
		B.append((private_key[2] * item)%private_key[1])
	return tuple(B)

# Encryption in MKHC, using a public key.
# Arguments: string, tuple (W, Q, R)
# Returns: list of integers
def encrypt_mhkc(plaintext, public_key):
	encypted_text = []

	#for every letter in the input, turn it to binary
	for i in plaintext:
		letter_binary = (format(ord(i), 'b'))

		#add leading 0s
		length_short = len(public_key) - len(letter_binary)
		letter_binary = length_short * "0" + letter_binary

		#for all of the bits in the binary representation, sum the  public key at the index * the
		# bit.
		C = 0
		for index,bit in enumerate(letter_binary):
			C += (int(bit) * public_key[index])
		encypted_text.append(C)
	return encypted_text

# Decryption in MKHC, based on the private key.
# Arguments: list of integers, private key (W, Q, R) with W a tuple.
# Returns: bytearray or str of plaintext
def decrypt_mhkc(ciphertext, private_key):
	# find the modulo inverse of Q and R
	S = makeModInverse(private_key[2],private_key[1])
	letter_string=""

	#for all the letters in the text, multiply by S%Q
	for letter in ciphertext:
		letter = letter * S % private_key[1]
		message_letter_binary = ""

		#for the number from largest to smallest in W, smallest sum problem
		for number in (reversed(private_key[0])):
			if (number<=letter):
				message_letter_binary +="1"
				letter-=number
			else:
				message_letter_binary +="0"
		#flip, since I added at end not before
		message_letter_binary=(message_letter_binary[::-1])

		#switch to ASCII and add to string
		letter_string += (chr(int(message_letter_binary,2)))
	return letter_string

# Finds the modulo inverse using an extended Euclidean algorithm
# Arguments: integer, integer
# Return: integer
def makeModInverse(R,Q):
	_, x,_ = extendedEuclidean(R,Q)
	return x % Q #mod the coefficient by Q

# Extended euclidean algorithm, recursively defined.
# Arguments: integer, integer
# Return: integer
def extendedEuclidean(R,Q):
	#Base case
	if R == 0:
		return (Q,0,1)
	else: #find the coefficients and return them
		g,x,y = extendedEuclidean(Q%R,R)
		return(g, y - Q//R * x, x)

#Main for testing
def main():
	print(encrypt_caesar(input(),int(input)))
	print(decrypt_caesar(input(),int(input)))
	print(encrypt_vigenere(input(),input()))
	print(decrypt_vigenere(input(),input()))
	private_key=generate_private_key()
	encrypted = encrypt_mhkc(input(),create_public_key(private_key))
	print(encrypted)
	print(decrypt_mhkc(encrypted,private_key))
	pass



if __name__ == "__main__":
	main()
