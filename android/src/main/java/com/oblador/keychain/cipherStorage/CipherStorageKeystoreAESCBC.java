package com.oblador.keychain.cipherStorage;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.annotation.NonNull;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.oblador.keychain.KeychainModule;
import com.oblador.keychain.R;
import com.oblador.keychain.exceptions.CryptoFailedException;
import com.oblador.keychain.exceptions.KeyStoreAccessException;
import com.oblador.keychain.supportBiometric.BiometricPrompt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import static com.oblador.keychain.supportBiometric.BiometricPrompt.*;

@TargetApi(Build.VERSION_CODES.M)
public class
CipherStorageKeystoreAESCBC implements CipherStorage {
    public static final String DELIMITER = "]";
    public static final String CIPHER_STORAGE_NAME = "KeystoreAESCBC";
    public static final String DEFAULT_SERVICE = "RN_KEYCHAIN_DEFAULT_ALIAS";
    public static final String KEYSTORE_TYPE = "AndroidKeyStore";
    public static final String ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES;
    public static final String ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC;
    public static final String ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7;
    public static final String ENCRYPTION_TRANSFORMATION =
            ENCRYPTION_ALGORITHM + "/" +
                    ENCRYPTION_BLOCK_MODE + "/" +
                    ENCRYPTION_PADDING;
    public static final int ENCRYPTION_KEY_SIZE = 256;

    private CancellationSignal mBiometricPromptCancellationSignal;
    private BiometricPrompt mBiometricPrompt;
    private KeyguardManager mKeyguardManager;
    private ReactContext mReactContext;
    private Activity mActivity;

    public CipherStorageKeystoreAESCBC(ReactApplicationContext reactContext) {
        mReactContext = reactContext;

        mKeyguardManager = (KeyguardManager) reactContext.getSystemService(Context.KEYGUARD_SERVICE);
    }

    private boolean canStartFingerprintAuthentication() {
        return (mKeyguardManager.isKeyguardSecure() &&
                (mReactContext.checkSelfPermission(Manifest.permission.USE_BIOMETRIC) == PackageManager.PERMISSION_GRANTED
                        || mReactContext.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED));
    }

    private void startFingerprintAuthentication(AuthenticationCallback callback, CryptoObject cryptoObject, Map<String, String> options) throws Exception {
        // If we have a previous cancellationSignal, cancel it.
        if (mBiometricPromptCancellationSignal != null) {
            mBiometricPromptCancellationSignal.cancel();
        }

        if (mActivity == null) {
            throw new Exception("mActivity is null (make sure to call setCurrentActivity)");
        }

        mBiometricPrompt = new BiometricPrompt(mActivity, Executors.newSingleThreadExecutor(), callback);
        mBiometricPromptCancellationSignal = new CancellationSignal();

        String title = options.get(KeychainModule.PROMPT_TITLE_KEY);
        if (title == null) title = mActivity.getString(R.string.fingerprint_prompt_title);

        String subtitle = options.get(KeychainModule.PROMPT_SUBTITLE_KEY);
        if (subtitle == null)  subtitle = mActivity.getString(R.string.fingerprint_prompt_subtitle);

        String cancel = options.get(KeychainModule.PROMPT_CANCEL_KEY);
        if (cancel == null) cancel = mActivity.getString(R.string.fingerprint_prompt_negative_button);


        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButtonText(cancel)
                .build();

        mBiometricPrompt.authenticate(promptInfo, cryptoObject);
        mReactContext.addLifecycleEventListener(mBiometricPrompt);
    }

    @Override
    public String getCipherStorageName() {
        return CIPHER_STORAGE_NAME;
    }

    @Override
    public boolean getCipherBiometrySupported() {
        return true;
    }

    @Override
    public int getMinSupportedApiLevel() {
        return Build.VERSION_CODES.M;
    }

    @Override
    public void encrypt(@NonNull final EncryptionResultHandler encryptionResultHandler, @NonNull final String service, @NonNull final String username, @NonNull final String password, Map<String, String> options) throws CryptoFailedException, KeyPermanentlyInvalidatedException {
        final String resolvedService = getDefaultServiceIfEmpty(service);
        final String resolvedServiceNoAuthRequired = getNoAuthRequiredService(service);

        final Key key;
        final Key keyNoAuthRequired;

        try {
            KeyStore keyStore = getKeyStoreAndLoad();

            if (!keyStore.containsAlias(resolvedService)) {
                generateKeyAndStoreUnderAlias(resolvedService, true);
            }
            if (!keyStore.containsAlias(resolvedServiceNoAuthRequired)) {
                generateKeyAndStoreUnderAlias(resolvedServiceNoAuthRequired, false);
            }

            key = keyStore.getKey(resolvedService, null);
            keyNoAuthRequired = keyStore.getKey(resolvedServiceNoAuthRequired, null);

            final Cipher cipher = getCipher(key, Cipher.ENCRYPT_MODE, null);
            final Cipher cipherNoAuthRequired = getCipher(keyNoAuthRequired, Cipher.ENCRYPT_MODE, null);

            if (!canStartFingerprintAuthentication()) {
                throw new CryptoFailedException("Could not start fingerprint Authentication");
            }
            try {
                AuthenticationCallback authenticationCallback = new AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                        super.onAuthenticationError(errorCode, errString);
                        encryptionResultHandler.onEncrypt(null, errString.toString(), Integer.toString(errorCode));
                        mBiometricPromptCancellationSignal.cancel();
                    }

                    // We don't really want to do anything here
                    // the error message is handled by the info view.
                    // And we don't want to throw an error, as the user can still retry.
                    @Override
                    public void onAuthenticationFailed() {
                        super.onAuthenticationFailed();
                    }

                    @Override
                    public void onAuthenticationSucceeded(@NonNull AuthenticationResult result) {
                        super.onAuthenticationSucceeded(result);
                        try {
                            byte[] encryptedUsername = encryptString(cipherNoAuthRequired, resolvedServiceNoAuthRequired, username);
                            byte[] encryptedPassword = encryptString(result.getCryptoObject().getCipher(), resolvedService, password);
                            encryptionResultHandler.onEncrypt(new EncryptionResult(encryptedUsername, encryptedPassword, CipherStorageKeystoreAESCBC.this), null);
                        } catch (InvalidKeyException e) {
                            // treat this the same as KeyPermanentlyInvalidatedException
                            try {
                                removeKey(resolvedService);
                                encryptionResultHandler.onEncrypt(null, e.getMessage());
                            } catch (Exception error) {
                                encryptionResultHandler.onEncrypt(null, error.getMessage());
                            }
                        } catch (Exception e) {
                            encryptionResultHandler.onEncrypt(null, e.getMessage());
                        }
                    }
                };

                startFingerprintAuthentication(authenticationCallback, new CryptoObject(cipher), options);
            } catch (Exception e1) {
                e1.printStackTrace();
                throw new CryptoFailedException("Could not start fingerprint Authentication", e1);
            }

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException | UnrecoverableKeyException e) {
            throw new CryptoFailedException("Could not encrypt data for service " + resolvedService, e);
        } catch (KeyStoreException | KeyStoreAccessException e) {
            throw new CryptoFailedException("Could not access Keystore for service " + resolvedService, e);
        } catch (Exception e) {
            throw new CryptoFailedException("Unknown error: " + e.getMessage(), e);
        }
    }

    private void generateKeyAndStoreUnderAlias(@NonNull String service, boolean userAuthenticationRequired) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // Set the alias of the entry in Android KeyStore where the key will appear
        // and the constrains (purposes) in the constructor of the Builder
        AlgorithmParameterSpec spec = new KeyGenParameterSpec.Builder(
                service,
                KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                .setBlockModes(ENCRYPTION_BLOCK_MODE)
                .setEncryptionPaddings(ENCRYPTION_PADDING)
                // .setRandomizedEncryptionRequired(true)
                // Require the user to authenticate with a fingerprint to authorize every use
                // of the key
                .setUserAuthenticationRequired(userAuthenticationRequired) // Will throw InvalidAlgorithmParameterException if there is no fingerprint enrolled on the device
                .setUserAuthenticationValidityDurationSeconds(-1)
                .setKeySize(ENCRYPTION_KEY_SIZE)
                .build();

        KeyGenerator generator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM, KEYSTORE_TYPE);
        generator.init(spec);

        generator.generateKey();
    }

    @Override
    public void decrypt(@NonNull final DecryptionResultHandler decryptionResultHandler, @NonNull String service, @NonNull final byte[] username, @NonNull final byte[] password, Map<String, String> options) throws CryptoFailedException, KeyPermanentlyInvalidatedException {
        final String resolvedService = getDefaultServiceIfEmpty(service);
        final String resolvedServiceNoAuthRequired = getNoAuthRequiredService(service);

        final Key key;
        final Key keyNoAuthRequired;

        try {
            KeyStore keyStore = getKeyStoreAndLoad();
            key = keyStore.getKey(resolvedService, null);
            keyNoAuthRequired = keyStore.getKey(resolvedServiceNoAuthRequired, null);

            final ByteArrayInputStream passwordInputStream = new ByteArrayInputStream(password);
            final Cipher cipher = getCipher(key, Cipher.DECRYPT_MODE, readIvFromStream(passwordInputStream));

            final ByteArrayInputStream usernameInputStream = new ByteArrayInputStream(username);
            final Cipher cipherNoAuthRequired = getCipher(keyNoAuthRequired, Cipher.DECRYPT_MODE, readIvFromStream(usernameInputStream));

            if (!canStartFingerprintAuthentication()) {
                throw new CryptoFailedException("Could not start fingerprint Authentication");
            }
            try {
                AuthenticationCallback authenticationCallback = new AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                        super.onAuthenticationError(errorCode, errString);
                        decryptionResultHandler.onDecrypt(null, errString.toString(), Integer.toString(errorCode));
                        mBiometricPromptCancellationSignal.cancel();
                    }

                    // We don't really want to do anything here
                    // the error message is handled by the info view.
                    // And we don't want to throw an error, as the user can still retry.
                    @Override
                    public void onAuthenticationFailed() {
                        super.onAuthenticationFailed();
                    }

                    @Override
                    public void onAuthenticationSucceeded(@NonNull AuthenticationResult result) {
                        super.onAuthenticationSucceeded(result);
                        try {
                            String decryptedUsername = decryptBytes(cipherNoAuthRequired, usernameInputStream);
                            String decryptedPassword = decryptBytes(cipher, passwordInputStream);
                            decryptionResultHandler.onDecrypt(new DecryptionResult(decryptedUsername, decryptedPassword), null);
                        } catch (InvalidKeyException e) {
                            // treat this the same as KeyPermanentlyInvalidatedException
                            try {
                                removeKey(resolvedService);
                                decryptionResultHandler.onDecrypt(null, e.getMessage());
                            } catch (Exception error) {
                                decryptionResultHandler.onDecrypt(null, error.getMessage());
                            }
                        } catch (Exception e) {
                            decryptionResultHandler.onDecrypt(null, e.getMessage());
                        }
                    }
                };

                startFingerprintAuthentication(authenticationCallback, new CryptoObject(cipher), options);
            } catch (Exception e1) {
                e1.printStackTrace();
                throw new CryptoFailedException("Could not start fingerprint Authentication", e1);
            }

        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new CryptoFailedException("Could not get key from Keystore", e);
        } catch (KeyStoreAccessException e) {
            throw new CryptoFailedException("Could not access Keystore", e);
        } catch (Exception e) {
            throw new CryptoFailedException("Unknown error: " + e.getMessage(), e);
        }
    }

    @Override
    public void removeKey(@NonNull String service) throws KeyStoreAccessException {
        service = getDefaultServiceIfEmpty(service);

        try {
            KeyStore keyStore = getKeyStoreAndLoad();

            if (keyStore.containsAlias(service)) {
                keyStore.deleteEntry(service);
            }
        } catch (KeyStoreException e) {
            throw new KeyStoreAccessException("Failed to access Keystore", e);
        } catch (Exception e) {
            throw new KeyStoreAccessException("Unknown error " + e.getMessage(), e);
        }
    }

    private Cipher getCipher(Key key, int opmode, IvParameterSpec ivParams) throws CryptoFailedException, UserNotAuthenticatedException, KeyPermanentlyInvalidatedException {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_TRANSFORMATION);
            cipher.init(opmode, key, ivParams);
            return cipher;
        } catch (UserNotAuthenticatedException | KeyPermanentlyInvalidatedException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoFailedException("Could not generate cipher", e);
        }
    }

    private byte[] encryptString(Cipher cipher, String service, String value) throws CryptoFailedException, UserNotAuthenticatedException, KeyPermanentlyInvalidatedException {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            // write initialization vector to the beginning of the stream
            byte[] iv = cipher.getIV();
            outputStream.write(iv, 0, iv.length);
            // encrypt the value using a CipherOutputStream
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
            cipherOutputStream.write(value.getBytes("UTF-8"));
            cipherOutputStream.close();
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new CryptoFailedException("Could not encrypt value for service " + service, e);
        }
    }

    private String decryptBytes(Cipher cipher, ByteArrayInputStream inputStream) throws CryptoFailedException, UserNotAuthenticatedException, KeyPermanentlyInvalidatedException {
        try {
            // decrypt the bytes using a CipherInputStream
            CipherInputStream cipherInputStream = new CipherInputStream(
                    inputStream, cipher);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            while (true) {
                int n = cipherInputStream.read(buffer, 0, buffer.length);
                if (n <= 0) {
                    break;
                }
                output.write(buffer, 0, n);
            }
            return new String(output.toByteArray(), Charset.forName("UTF-8"));
        } catch (IOException e) {
            throw new CryptoFailedException("Could not decrypt bytes", e);
        }
    }

    private IvParameterSpec readIvFromStream(ByteArrayInputStream inputStream) {
        byte[] iv = new byte[16];
        inputStream.read(iv, 0, iv.length);
        return new IvParameterSpec(iv);
    }

    private KeyStore getKeyStoreAndLoad() throws KeyStoreException, KeyStoreAccessException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(null);
            return keyStore;
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new KeyStoreAccessException("Could not access Keystore", e);
        }
    }

    @NonNull
    private String getDefaultServiceIfEmpty(@NonNull String service) {
        return service.isEmpty() ? DEFAULT_SERVICE : service;
    }

    @NonNull
    private String getNoAuthRequiredService(@NonNull String service) {
        return getDefaultServiceIfEmpty(service) + "_NO_AUTH_REQUIRED";
    }

    @Override
    public boolean getRequiresCurrentActivity() {
        return true;
    }

    @Override
    public void setCurrentActivity(Activity activity) {
        mActivity = activity;
    }
}
