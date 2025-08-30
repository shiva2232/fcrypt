## fcrypt (smart security system using mfcc/checksum authentication)
 This project uses either **Mel Frequency Cepstral Coefficient (MFCC)** or **checksum** to **encrypt and decrypt files**.  
 It provides an extra layer of security by requiring a key file (audio or checksum) for both operations.

### ⚠️ Warning!!!
 If you lose the key file, the encrypted file **cannot be decrypted in any way**.  
 Be very careful not to lose your key file.

#### usage
 To encrypt using MFCC (use audio file next to -from file),

    ./fcrypt -file /path/to/file -from /path/to/keyfile.mp3

 To decrypt using MFCC (use same audio file that used to encypt -from file),

    ./fcrypt -file /path/to/file.enc -from /path/to/keyfile.mp3 -decrypt

 using checksum to encrypt files(add -c),

    ./fcrypt -file /path/to/file -from /path/to/keyfile.* -c

 using checksum to decrypt files,

    ./fcrypt -file /path/to/file.enc -from /path/to/keyfile.* -c -decrypt

#### params
 -file (required) - > file to be encrypted/decripted \
 -from (required) - > file as encryption key \
 -c (optional) - > use checksum as encryption key \
 -decrypt (optional) - > use -decrypt to decrypt otherwise it will be encrypted.
