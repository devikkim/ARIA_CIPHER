/**
 * ARIA Block Cipher class
 *
 * <p> KISA에서 배포한 샘플 알고리즘을 Wrapping 한 클래스
 *
 * <p> 클래스 인스턴스 시 블록 모드를 세팅 이후 키를 세팅 (CBC일 경우, IV도 세팅) encrypt, decrypt 함수를 통하여 암,복호화 진행
 *
 * <p> 작성자 : 김인권 
 * 
 * <p> 작성일 : 2018.02.21
 */
package aria;

import aria.AbstractCustomCipher;

import java.security.InvalidKeyException;

public class ARIACipher extends AbstractCustomCipher {
  private ARIAAlgorithm cipher = null;
  private byte[] iv;

  public ARIACipher(String blockModeAndPadMode) {
    super(blockModeAndPadMode);
  }

  @Override
  public void setKey(byte[] key) {
    try {
      cipher = new ARIAAlgorithm(key.length * 8);
      cipher.setKey(key);
      cipher.setupRoundKeys();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }
  }

  @Override
  public void setIV(byte[] iv) {
    if (iv.length != 16) {
      try {
        throw new InvalidKeyException("iv size =" + iv.length);
      } catch (InvalidKeyException e) {
        e.printStackTrace();
      }
    }

    this.iv = iv;
  }

  @Override
  protected byte[] cbcEncrypt(byte[] plain) {
    try {
      byte[] XORBlock = new byte[plain.length];

      byte[] output = new byte[plain.length];
      int outputIdx = 0;

      for (int i = 0; i < plain.length; i += BLOCK_SIZE) {
        if (i == 0) { // 첫 평문 블록과 IV의 XOR
          for (int idx = 0; idx < 16; idx++) {
            XORBlock[idx] = (byte) (plain[idx] ^ this.iv[idx]);
          }
          cipher.encrypt(XORBlock, i, output, i);
        } else { // 이후, 앞의 암호화된 블록과 평문 블럭과의 XOR
          for (int currentIdx = i; currentIdx < i + BLOCK_SIZE; currentIdx++) {
            XORBlock[currentIdx] = (byte) (plain[currentIdx] ^ output[outputIdx]);
            outputIdx++;
          }
          cipher.encrypt(XORBlock, i, output, i);
        }
      }
      return output;
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }
    return null;
  }

  @Override
  protected byte[] cbcDecrypt(byte[] encryptedBytes) {
    try {
      byte[] output = new byte[encryptedBytes.length];
      int outputIdx = 0;

      byte[] decryptedBytes = new byte[encryptedBytes.length];

      for (int i = 0; i < encryptedBytes.length; i += BLOCK_SIZE) {
        cipher.decrypt(encryptedBytes, i, output, i);

        if (i == 0) { // 첫 암호화 블록을 복호화 한 후, 나온 결과를 IV와 XOR
          for (int idx = 0; idx < 16; idx++) {
            decryptedBytes[idx] = (byte) (this.iv[idx] ^ output[idx]);
          }
        } else { // 이후 암호화 블록은 복호화 한 후, 이전 암호화 블록과 XOR
          for (int currentIdx = i; currentIdx < i + 16; currentIdx++) {
            decryptedBytes[currentIdx] = (byte) (output[currentIdx] ^ encryptedBytes[outputIdx]);
            outputIdx++;
          }
        }
      }
      return decryptedBytes;
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }
    return null;
  }

  @Override
  protected byte[] ecbEncrypt(byte[] plain) {
    try {
      byte[] input = pad(plain, BLOCK_SIZE);
      byte[] encryptedBytes = new byte[input.length];

      for (int i = 0; i < input.length; i += BLOCK_SIZE) {
        cipher.encrypt(input, i, encryptedBytes, i);
      }
      return encryptedBytes;
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }
    return null;
  }

  @Override
  protected byte[] ecbDecrypt(byte[] encryptedBytes) {
    try {
      byte[] decryptedBytes = new byte[encryptedBytes.length];

      for (int i = 0; i < encryptedBytes.length; i += BLOCK_SIZE) {
        cipher.decrypt(encryptedBytes, i, decryptedBytes, i);
      }
      return decryptedBytes;
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }
    return null;
  }

  public static void main(String[] args) {
    try {
      ARIACipher cipher = new ARIACipher(CBC_NoPadding);

      byte[] key = new byte[] { (byte) 0x43, (byte) 0xa2, (byte) 0xac, (byte) 0x7a, (byte) 0x87, (byte) 0xf8,
          (byte) 0x65, (byte) 0x90, (byte) 0x52, (byte) 0xf2, (byte) 0xf5, (byte) 0x19, (byte) 0xff, (byte) 0xad,
          (byte) 0x3d, (byte) 0xab };

      byte[] iv = new byte[] { (byte) 0x79, (byte) 0x3e, (byte) 0x9a, (byte) 0x56, (byte) 0x31, (byte) 0x67,
          (byte) 0x83, (byte) 0xf5, (byte) 0x99, (byte) 0xb3, (byte) 0xb6, (byte) 0x24, (byte) 0xf6, (byte) 0x9f,
          (byte) 0x88, (byte) 0x73 };
      byte[] plain = "aria test plain ".getBytes();

      cipher.setKey(key);
      cipher.setIV(iv);

      byte[] encrypted = cipher.encrypt(plain);
      byte[] decrypted = cipher.decrypt(encrypted);

      System.out.println("decrypted = " + new String(decrypted));

    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
