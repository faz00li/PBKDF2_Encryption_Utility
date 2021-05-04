# PBKDF2_Encryption_Utility
**Instructions:**  
This PBKDF2 encryption utility supports the following two symmetric encryption standards: 3DES and AES128/AES256. The utility also supports two hashing algorithms: SHA256 and SHA512. To configure the utility enter 1) prefered KDF 2) iteration count for the KDF 3) which encryption standard to use 4) and which hash digest. Currently only the parameters listed above are supported.

**Performance:**  
The use case for this utility is the encryption and decryption of personal files. RFC 2898, published in 2000, recommends 1000 iterations for the KDF. However, for increased security to match modern processing power I recommend using the utility with 1,250,000 iterations. This amount of iterations can be processed in a second for small files such as word, excel, text, and images. This time frame matches my security needs with practical usability.   

**State of Project:**  
The project has completed the initial development phase. It is currently in need of a review by the instructor and possible amendments. To this end debugging and logging has not been removed yet in anticipation of possible work ahead.

Eduard Raskin

