package com.oblador.keychain.cipherStorage;

import android.app.Activity;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.support.annotation.NonNull;

import com.oblador.keychain.exceptions.CryptoFailedException;
import com.oblador.keychain.exceptions.KeyStoreAccessException;

import java.util.Map;

public interface CipherStorage {
    abstract class CipherResult<T> {
        public final T username;
        public final T password;

        public CipherResult(T username, T password) {
            this.username = username;
            this.password = password;
        }
    }

    class EncryptionResult extends CipherResult<byte[]> {
        public CipherStorage cipherStorage;

        public EncryptionResult(byte[] username, byte[] password, CipherStorage cipherStorage) {
            super(username, password);
            this.cipherStorage = cipherStorage;
        }
    }

    abstract class EncryptionResultHandler {
        abstract public void onEncrypt(EncryptionResult encryptionResult, String errorMessage, String errorCode);

        public void onEncrypt(EncryptionResult encryptionResult, String errorMessage) {
            onEncrypt(encryptionResult, errorMessage, null);
        }
    }

    class DecryptionResult extends CipherResult<String> {
        public DecryptionResult(String username, String password) {
            super(username, password);
        }
    }

    abstract class DecryptionResultHandler {
        abstract public void onDecrypt(DecryptionResult decryptionResult, String errorMessage, String errorCode);

        public void onDecrypt(DecryptionResult decryptionResult, String errorMessage) {
            onDecrypt(decryptionResult, errorMessage, null);
        }
    }

    void encrypt(@NonNull EncryptionResultHandler encryptionResultHandler, @NonNull String service, @NonNull String username, @NonNull String password, Map<String, String> options) throws CryptoFailedException, KeyPermanentlyInvalidatedException;

    void decrypt(@NonNull DecryptionResultHandler decryptionResultHandler, @NonNull String service, @NonNull byte[] username, @NonNull byte[] password, Map<String, String> options) throws CryptoFailedException, KeyPermanentlyInvalidatedException;

    void removeKey(@NonNull String service) throws KeyStoreAccessException;

    String getCipherStorageName();

    boolean getCipherBiometrySupported();

    int getMinSupportedApiLevel();

    boolean getRequiresCurrentActivity();
    void setCurrentActivity(Activity activity);
}
