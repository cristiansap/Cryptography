from pwn import remote
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import string



def main():

    conn = remote('130.192.5.212', 6544)

    print()
    print(conn.recvline().strip().decode())
    print(conn.recvline().strip().decode())
    print(conn.recvline().strip().decode())
    print(conn.recvline().strip().decode())
    print()


    # REASONING:
    # payload = padding1 + data + padding2 + flag
    # data = fill_padding_1 + pad(guess.encode() + flag.encode(), BLOCK_SIZE) + fill_padding_2 + b"A"*(i+1) + force_shift_pad

    # ---- 1st ITERATION (i=0) ----
    # 1st block: random_padding1 + fill_padding_1                  FULL OK
    # 2nd block: pad(guess + flag, BLOCK_SIZE)	                   FULL OK
    # 3rd block: fill_padding_2 + random_padding_2                 FULL OK
    # 4th block: b”A”*(i+1) + force_shift_pad (2B) + flag[0:13]    FULL OK
    # 5th block: flag[13:29]				                       FULL OK
    # 6th block: flag[29:45]    	          	                   FULL OK
    # 7th block: flag[45:46] (1B) + padding(15B)	   	           FULL OK

    # ---- 2nd ITERATION (i=1) ----
    # 1st block: random_padding1 + fill_padding_1                  FULL OK
    # 2nd block: pad(guess + flag, BLOCK_SIZE)	                   FULL OK
    # 3rd block: fill_padding_2 + random_padding_2                 FULL OK
    # 4th block: b”A”*(i+1) + force_shift_pad (2B) + flag[0:12]    FULL OK
    # 5th block: flag[12:28]			                           FULL OK
    # 6th block: flag[28:44]  	          	                       FULL OK
    # 7th block: flag[44:46] + padding(14B)	                       FULL OK

    # NOTE: The strategy is to retrieve the flag backwards: I start by adding some fill_padding to
    #       fill the random padding introduced by the server, then at each iteration I add one byte b"A"
    #       to force a right shift of the flag each time I guess one character. The first iteration
    #       is as follows: apart from the padding, I use pad(guess + flag) where 'flag' is empty at the 
    #       first iteration, so I'm padding a block of 1 byte (1 byte + 15B of padding), then by adding proper padding
    #       I force the last char (1B) of the flag (which is known to be 46B long) to go to the last block,
    #       which is automatically padded at the server side during the encryption process again using pad(),
    #       which behaves adding the same padding (since also here I need 15B of padding). This allows me to make
    #       a comparison between these two blocks: (guess + padding) == (flag's last char + padding), and discover
    #       the last character of the flag. The next iterations follow the same reasoning.

    flag = ""
    BLOCK_SIZE = AES.block_size
    FLAG_LENGTH = 36 + len("CRYPTO25{}")
    FORCE_SHIFT = FLAG_LENGTH % BLOCK_SIZE

    print("\nStart retrieving the flag from the last character to the first one...")
    
    for length in range(1,7):   # emulate the random extraction done at the server side in the range (1,6) (the for iterates within a range = (1,7) where 7 is excluded)

        fill_padding_1 = b"A" * (BLOCK_SIZE - length)    # generate padding of proper length so that the FIRST block of random padding that the server creates is completely filled
        fill_padding_2 = b"A" * (BLOCK_SIZE - (10 - length))   # generate padding of proper length so that the LAST block of random padding that the server creates is completely filled
        force_shift_pad = b"A" * (BLOCK_SIZE - FORCE_SHIFT)    # this is a 2 bytes long padding needed to force the right shift of the flag to align the flag's last character at the beginning of the last block in the first iteration (in the next iterations it will be right shifted by one position each time)

        for i in range(FLAG_LENGTH):
            found = False
            for guess in string.printable:
                conn.sendline(b"enc")
                conn.recvuntil(b"> ")

                if i < BLOCK_SIZE - 1:      # use pad() because guess.encode() + flag.encode() does not fill an entire block
                    data = fill_padding_1 + pad(guess.encode() + flag.encode(), BLOCK_SIZE) + fill_padding_2 + b"A"*(i+1) + force_shift_pad    # fill_padding_1 + [guess + flag (guessed so far)] => padded to 16B + fill_padding_2 + "A"*(i+1) (to right shift 1 byte of the flag at a time in the last block) + force_shift_pad
                else:       # stop using pad() because now you have guessed enough bytes to fill an entire block, so I must take only the first 15 guessed characters of the flag (to leave a free space for 1 byte of 'guess')
                    data = fill_padding_1 + guess.encode() + flag[:15].encode() + fill_padding_2 + b"A"*(i+1) + force_shift_pad

                conn.sendline(data.hex().encode())
                conn.recvuntil(b"> ")

                ciphertext = conn.recvline().strip().decode()
                ciphertext_bytes = bytes.fromhex(ciphertext)

                if ciphertext_bytes[16:32] == ciphertext_bytes[96:112]:
                    flag = guess + flag     # build the flag backwards (because the flag is retrieved starting from the last character to the first one, so I have to append the just guessed character at the beginning)
                    print(f"Char found: {guess} ==> {flag}")
                    found = True
                    break

                if len(flag) == FLAG_LENGTH:   # exit when all the characters of the flag have been guessed
                    break

            if not found:   # exit if no match has been found in the current iteration
                break

    print("\nThe flag is:", flag)

    conn.close()


if __name__ == '__main__':
    main()
