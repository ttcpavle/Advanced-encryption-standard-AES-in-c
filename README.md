# Advanced-encryption-standard-AES-in-c
This is a simple example of AES encryption (with 128, 192 and 256bit keys). It represents the core of aes, file and text encryption can be implemented on top of it. This is visualization of the AES round function:

<div align="center" size>
  <img src="https://github.com/user-attachments/assets/75b29cb3-e0e4-400f-8681-fcb598936850" alt="aes encryption visually" width="30%">
</div>

AES basically repeats these 4 operations for 10, 12 or 14 times depending on key size (128, 192 or 256bit) as defined in standard. This encryption algorithm utilizes confusion and diffusion making data difficult to decipher. More information about what each operation does is provided in materials below.

# How to use
Run AES.c in preferred compiler. Choose key size of aes - define AES128, AES192 or AES256. Key examples are from Appendix A in official documentation (link below). Test input in main function is from Appendix B.
# Useful materials:
### Official documentation (2001) on which this code was based on: 

https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf

### Useful videos on youtube:

*Short explaination:* https://youtu.be/gP4PqVGudtg?si=ItrO-kTEUj-2q5LL

*AES by Christof Paar (lecture):* https://youtu.be/NHuibtoL_qk?si=pFujBaE-zT04i2QF

*Key expansion:* https://youtu.be/0RxLUf4fxs8?si=qg9s-bPnxebhwX72

*Galois field:* https://www.youtube.com/watch?v=SKFjdAtl5Fc

