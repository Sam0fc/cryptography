import random
import math
import binascii
ASCII_LETTER_START = 65
LENGTH_ALPHABET = 26
INITIAL_RANDOM_CEILING = 100

# Caesar Cipher
# Arguments: string, integer
# Returns: string
def encrypt_caesar(plaintext, offset):
	new_text = ""
	for letter in plaintext.upper():
		if letter.isalpha():
			letter = doLetterOffset(letter,offset)
		new_text += letter
	return new_text

# Arguments: string, integer
# Returns: string
def decrypt_caesar(ciphertext, offset):
	new_text = ""
	for letter in ciphertext.upper():
		if letter.isalpha():
			letter = doLetterOffset(letter,-1 * offset)
		new_text += letter
	return new_text

# Vigenere Cipher
# Arguments: string, string
# Returns: string
def encrypt_vigenere(plaintext, keyword):
	new_text = ""
	keyword=keyword.upper()
	plaintext=plaintext.upper()
	for index,letter in enumerate(plaintext):
		offset = ord(keyword[index%len(keyword)]) - ASCII_LETTER_START
		if letter.isalpha():
			letter = doLetterOffset(letter,offset)
		new_text += letter
	return new_text

# Arguments: string, string
# Returns: string
def decrypt_vigenere(ciphertext, keyword):
	new_text = ""
	keyword=keyword.upper()
	ciphertext=ciphertext.upper()
	for index,letter in enumerate(ciphertext):
		offset = ord(keyword[index%len(keyword)]) - ASCII_LETTER_START
		if letter.isalpha():
			letter = doLetterOffset(letter,-1 * offset)
		new_text += letter
	return new_text

def doLetterOffset(letter,offset):
	num_letter = ord(letter) - ASCII_LETTER_START
	offset_num_letter = (num_letter + offset)%LENGTH_ALPHABET
	letter = chr(offset_num_letter + ASCII_LETTER_START)
	return letter

# Merkle-Hellman Knapsack Cryptosystem
# Arguments: integer
# Returns: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
def generate_private_key(n=8):
	W,Q = genSincSequence(n)
	R = makeCoPrime(Q)
	return (W,Q,R)

# Arguments: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
# Returns: tuple B - a length-n tuple of integers
def create_public_key(private_key):
	B = []
	for item in (private_key[0]):
		B.append((private_key[2] * item)%private_key[1])
	return tuple(B)

# Arguments: string, tuple (W, Q, R)
# Returns: list of integers
def encrypt_mhkc(plaintext, public_key):
	encypted_text = []
	for i in plaintext:
		letter_binary = (format(ord(i), 'b'))
		length_short = len(public_key) - len(letter_binary)
		letter_binary = length_short * "0" + letter_binary
		C = 0
		for index,bit in enumerate(letter_binary):
			C += (int(bit) * public_key[index])
		encypted_text.append(C)
	return encypted_text

# Arguments: list of integers, tuple B - a length-n tuple of integers
# Returns: bytearray or str of plaintext
def decrypt_mhkc(ciphertext, private_key):
	S = makeModInverse(private_key[2],private_key[1])
	letter_string=""
	for letter in ciphertext:
		letter = letter * S % private_key[1]
		message_letter_binary = ""
		for number in (reversed(private_key[0])):
			if (number<=letter):
				message_letter_binary +="1"
				letter-=number
			else:
				message_letter_binary +="0"
		message_letter_binary=(message_letter_binary[::-1])
		letter_string += (chr(int(message_letter_binary,2)))
	return letter_string



def genSincSequence(n):
	sinc_sequence=[]
	inital_number = random.randint(1,INITIAL_RANDOM_CEILING)
	sinc_sequence.append(inital_number)
	running_total = 0
	for (i) in range(n):
		running_total+=sinc_sequence[i]
		sinc_sequence.append(random.randint(running_total+1,running_total*2))
	running_total+=sinc_sequence[-1]
	return sinc_sequence , random.randint(running_total+1,running_total*2)

def makeCoPrime(Q):
	done = False
	while not done:
		R = random.randint(2,Q-1)
		done = (math.gcd(Q,R) == 1)
	return R

def makeModInverse(R,Q):
	_, x,_ = extendedEuclidean(R,Q)
	return x % Q
	pass

def extendedEuclidean(R,Q):
	if R == 0:
		return (Q,0,1)
	else:
		g,x,y = extendedEuclidean(Q%R,R)
		return(g, y - Q//R * x, x)

def main():
	private_key=generate_private_key()
	encrypted = encrypt_mhkc(input(),create_public_key(private_key))
	print(encrypted)
	print(decrypt_mhkc(encrypted,private_key))
	pass



if __name__ == "__main__":
	main()
