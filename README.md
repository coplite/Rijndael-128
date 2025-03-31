# Rijndael-128
Implementation of an aes encryption 128 bits maybe used for sleep obfuscation in the future

## why did I make this???
# Well, I made this project because I am bored and I need something to make for CSP :/

## Is there anything you're going to add?
# Might add CTR mode with auto randomizable nonce via Mersenne 
# Might add ChaCha20Poly1305 for faster encryption
# Might remove MixColumns and ShiftRows because I need very low diffusion because encrypted memory pages are also suspicious
# Might rewrite some parts of this in assembly for smaller binaries, faster executions, and more ABI compatibility(I think thats how it works idk)

## Why for Sleep Obfuscation?????
# Uhhhh idk :p
# --> Maybe because receiving telemetry from SystemFunction032 every <insert-time-delay> seconds is kinda suspicious on the same memory region fluctuating from RW- to R-X and RC4 and SystemFunction032 is RC4 encryption which is kinda insecure and the function can be hooked (because its a winapi function and an edr can inline patch it if they wish) and it can fail (judging from its return value)?
