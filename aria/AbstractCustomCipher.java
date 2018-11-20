/**
 * AbstractCustomCipher class
 *
 * <p> CustomCipher 클래스를 위한 추상클래
 *
 * <p> 작성자 : 김인권 
 * 
 * <p> 작성일 : 2018.02.21
 */
package aria;

import java.security.InvalidParameterException;

public abstract class AbstractCustomCipher {
  public static final String ECB_NoPadding = "ECB/NoPadding";
  public static final String ECB_PKCS5PADDING = "ECB/PKCS5Padding";
  public static final String CBC_NoPadding = "CBC/NoPadding";
  public static final String CBC_PKCS5PADDING = "CBC/PKCS5Padding";

  protected final int ECB_MODE = 0;
  protected final int CBC_MODE = 1;

  protected final int NO_PADDING = 0;
  protected final int PKCS5_PADDING = 1;

  protected final int BLOCK_SIZE = 16;

  protected int blockMode;
  protected int padMode;

  public AbstractCustomCipher(String blockModeAndPadMode) {
    try {
      String[] parseData = blockModeAndPadMode.split("/");

      String blockMode = parseData[0];
      String padMode = parseData[1];

      if (blockMode.toUpperCase().equals("CBC")) {
        this.blockMode = CBC_MODE;
      } else if (blockMode.toUpperCase().equals("ECB")) {
        this.blockMode = ECB_MODE;
      } else {
        throw new InvalidParameterException("invalid block mode : " + this.blockMode);
      }

      if (padMode.toUpperCase().equals("NOPADDING")) {
        this.padMode = NO_PADDING;
      } else if (padMode.toUpperCase().equals("PKCS5PADDING")) {
        this.padMode = PKCS5_PADDING;
      } else {
        throw new InvalidParameterException("invalid pad mode : " + this.padMode);
      }

    } catch (ArrayIndexOutOfBoundsException arrayException) {
      throw new ArrayIndexOutOfBoundsException("invalid mode : " + blockModeAndPadMode);
    }
  }

  public abstract void setKey(byte[] key);

  public abstract void setIV(byte[] iv);

  public byte[] encrypt(byte[] plain) {
    byte[] inputBytes;

    if (padMode == PKCS5_PADDING) {
      inputBytes = pad(plain, BLOCK_SIZE);
    } else {
      inputBytes = plain;
    }

    if (blockMode == CBC_MODE) {
      return cbcEncrypt(inputBytes);
    } else if (blockMode == ECB_MODE) {
      return ecbEncrypt(inputBytes);
    } else {
      return ecbEncrypt(inputBytes);
    }
  }

  public byte[] decrypt(byte[] encryptedData) {
    byte[] output;
    if (blockMode == CBC_MODE) {
      output = cbcDecrypt(encryptedData);
    } else if (blockMode == ECB_MODE) {
      output = ecbDecrypt(encryptedData);
    } else {
      output = ecbDecrypt(encryptedData);
    }

    if (this.padMode == PKCS5_PADDING) {
      return unpad(output, BLOCK_SIZE);
    } else {
      return output;
    }
  }

  protected abstract byte[] cbcEncrypt(byte[] plain);

  protected abstract byte[] cbcDecrypt(byte[] encryptedBytes);

  protected abstract byte[] ecbEncrypt(byte[] plain);

  protected abstract byte[] ecbDecrypt(byte[] encryptedBytes);

  protected byte[] pad(byte[] inputBytes, int blockSize) {
    if (inputBytes == null)
      return null;

    int offset = inputBytes.length;
    int len = blockSize - (offset % blockSize);

    byte paddingOctet = (byte) (len & 0xff);

    byte[] outputBytes = new byte[offset + len];

    System.arraycopy(inputBytes, 0, outputBytes, 0, inputBytes.length);
    for (int i = offset; i < outputBytes.length; i++) {
      outputBytes[i] = paddingOctet;
    }

    return outputBytes;
  }

  protected byte[] unpad(byte[] in, int blockSize) {
    if (in == null)
      return null;

    int len = in.length;
    byte lastByte = in[len - 1];
    int padValue = (int) (lastByte & 0xff);

    if ((padValue < 0x01) || (padValue > blockSize)) {
      return null;
    }

    int offset = len - padValue;

    for (int i = offset; i < len; i++) {
      if (in[i] != padValue)
        return null;
    }

    byte[] out = new byte[offset];

    System.arraycopy(in, 0, out, 0, offset);

    return out;
  }
}
