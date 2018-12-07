# ARIA_CIPHER
ARIA is standard block cipher of South Korea
this class support only cbc, ecb mode

1. create instance with pad mode
```java
ARIACipher cipher = new ARIACipher(CBC_NoPadding);
```

2. set key and iv (if seleted cbc mode)
```java
byte[] key = new byte[] { (byte) 0x43, (byte) 0xa2, (byte) 0xac, (byte) 0x7a, (byte) 0x87, (byte) 0xf8,
          (byte) 0x65, (byte) 0x90, (byte) 0x52, (byte) 0xf2, (byte) 0xf5, (byte) 0x19, (byte) 0xff, (byte) 0xad,
          (byte) 0x3d, (byte) 0xab };
          
byte[] iv = new byte[] { (byte) 0x79, (byte) 0x3e, (byte) 0x9a, (byte) 0x56, (byte) 0x31, (byte) 0x67,
          (byte) 0x83, (byte) 0xf5, (byte) 0x99, (byte) 0xb3, (byte) 0xb6, (byte) 0x24, (byte) 0xf6, (byte) 0x9f,
          (byte) 0x88, (byte) 0x73 };
          
byte[] plain = "aria test plain ".getBytes();

cipher.setKey(key);
cipher.setIV(iv);
```

3. encrypt (plain is byte[])
```java
byte[] encrypted = cipher.encrypt(plain);
```

4. decrypt
```java
byte[] decrypted = cipher.decrypt(encrypted);
```
