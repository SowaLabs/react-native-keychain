package com.oblador.keychain;

import android.os.AsyncTask;
import android.os.Build;
import android.support.annotation.NonNull;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;

import com.oblador.keychain.PrefsStorage.ResultSet;
import com.oblador.keychain.cipherStorage.CipherStorage;
import com.oblador.keychain.cipherStorage.CipherStorage.DecryptionResult;
import com.oblador.keychain.cipherStorage.CipherStorage.EncryptionResult;
import com.oblador.keychain.cipherStorage.CipherStorage.DecryptionResultHandler;
import com.oblador.keychain.cipherStorage.CipherStorage.EncryptionResultHandler;
import com.oblador.keychain.cipherStorage.CipherStorageFacebookConceal;
import com.oblador.keychain.cipherStorage.CipherStorageKeystoreAESCBC;
import com.oblador.keychain.cipherStorage.CipherStorageKeystoreRSAECB;
import com.oblador.keychain.exceptions.CryptoFailedException;
import com.oblador.keychain.exceptions.EmptyParameterException;
import com.oblador.keychain.exceptions.KeyStoreAccessException;
import com.oblador.keychain.supportBiometric.BiometricPrompt;

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KeychainModule extends ReactContextBaseJavaModule {
    public static final String E_EMPTY_PARAMETERS = "E_EMPTY_PARAMETERS";
    public static final String E_CRYPTO_FAILED = "E_CRYPTO_FAILED";
    public static final String E_KEYSTORE_ACCESS_ERROR = "E_KEYSTORE_ACCESS_ERROR";
    public static final String E_SUPPORTED_BIOMETRY_ERROR = "E_SUPPORTED_BIOMETRY_ERROR";
    public static final String KEYCHAIN_MODULE = "RNKeychainManager";
    public static final String FINGERPRINT_SUPPORTED_NAME = "Fingerprint";
    public static final String EMPTY_STRING = "";


    public static final String AUTHENTICATION_TYPE_KEY = "authenticationType";
    public static final String AUTHENTICATION_TYPE_DEVICE_PASSCODE_OR_BIOMETRICS = "AuthenticationWithBiometricsDevicePasscode";
    public static final String AUTHENTICATION_TYPE_BIOMETRICS = "AuthenticationWithBiometrics";

    public static final String ACCESS_CONTROL_KEY = "accessControl";
    public static final String ACCESS_CONTROL_BIOMETRY_ANY = "BiometryAny";
    public static final String ACCESS_CONTROL_BIOMETRY_CURRENT_SET = "BiometryCurrentSet";

    public static final String PROMPT_TITLE_KEY = "authenticationPrompt";
    public static final String PROMPT_SUBTITLE_KEY = "authenticationSubtitlePrompt";
    public static final String PROMPT_CANCEL_KEY = "authenticationCancelPrompt";

    private final Map<String, CipherStorage> cipherStorageMap = new HashMap<>();
    private final PrefsStorage prefsStorage;
    final ReactApplicationContext mReactContext;

    @Override
    public String getName() {
        return KEYCHAIN_MODULE;
    }

    @Override
    public Map<String, Object> getConstants() {
        final Map<String, Object> constants = new HashMap<>();
        constants.put("E_EMPTY_PARAMETERS", E_EMPTY_PARAMETERS);
        constants.put("E_CRYPTO_FAILED", E_CRYPTO_FAILED);
        constants.put("E_KEYSTORE_ACCESS_ERROR", E_KEYSTORE_ACCESS_ERROR);
        constants.put("E_SUPPORTED_BIOMETRY_ERROR", E_SUPPORTED_BIOMETRY_ERROR);
        constants.put("BIOMETRIC_ERROR_HW_UNAVAILABLE", String.valueOf(BiometricPrompt.ERROR_HW_UNAVAILABLE));
        constants.put("BIOMETRIC_ERROR_UNABLE_TO_PROCESS", String.valueOf(BiometricPrompt.ERROR_UNABLE_TO_PROCESS));
        constants.put("BIOMETRIC_ERROR_TIMEOUT", String.valueOf(BiometricPrompt.ERROR_TIMEOUT));
        constants.put("BIOMETRIC_ERROR_NO_SPACE", String.valueOf(BiometricPrompt.ERROR_NO_SPACE));
        constants.put("BIOMETRIC_ERROR_CANCELED", String.valueOf(BiometricPrompt.ERROR_CANCELED));
        constants.put("BIOMETRIC_ERROR_LOCKOUT", String.valueOf(BiometricPrompt.ERROR_LOCKOUT));
        constants.put("BIOMETRIC_ERROR_VENDOR ",String.valueOf( BiometricPrompt.ERROR_VENDOR));
        constants.put("BIOMETRIC_ERROR_LOCKOUT_PERMANENT", String.valueOf(BiometricPrompt.ERROR_LOCKOUT_PERMANENT));
        constants.put("BIOMETRIC_ERROR_USER_CANCELED", String.valueOf(BiometricPrompt.ERROR_USER_CANCELED));
        constants.put("BIOMETRIC_ERROR_NO_BIOMETRICS", String.valueOf(BiometricPrompt.ERROR_NO_BIOMETRICS));
        constants.put("BIOMETRIC_ERROR_HW_NOT_PRESENT", String.valueOf(BiometricPrompt.ERROR_HW_NOT_PRESENT));
        constants.put("BIOMETRIC_ERROR_NEGATIVE_BUTTON", String.valueOf(BiometricPrompt.ERROR_NEGATIVE_BUTTON));
        return constants;
    }

    public KeychainModule(ReactApplicationContext reactContext) {
        super(reactContext);
        prefsStorage = new PrefsStorage(reactContext);
        mReactContext = reactContext;

        addCipherStorageToMap(new CipherStorageFacebookConceal(reactContext));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            addCipherStorageToMap(new CipherStorageKeystoreAESCBC(reactContext));
            addCipherStorageToMap(new CipherStorageKeystoreRSAECB(reactContext));
        }
    }

    private void addCipherStorageToMap(CipherStorage cipherStorage) {
        cipherStorageMap.put(cipherStorage.getCipherStorageName(), cipherStorage);
    }

    private HashMap<String, String> parseOptions(ReadableMap options, List<String> keys) {
        HashMap<String, String> parsedOptions = new HashMap<>();

        if (options == null || keys == null){
            return parsedOptions;
        }

        for (String key: keys) {
            if (options.hasKey(key) && !options.getString(key).isEmpty()) {
                parsedOptions.put(key, options.getString(key));
            }
        }
        return parsedOptions;
    }

    @ReactMethod
    public void setGenericPasswordForOptions(final String service, final String username, final String password, final ReadableMap options, final Promise promise) {
        // currentCipherStorage.encrypt() takes a couple of seconds to complete, run on a background thread so not to block the UI
        AsyncTask.execute(new Runnable() {
            @Override
            public void run() {
                final String resolvedService = getDefaultServiceIfNull(service);
                CipherStorage currentCipherStorage = null;
                try {
                    if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
                        throw new EmptyParameterException("you passed empty or null username/password");
                    }

                    Map<String, String> parsedOptions = parseOptions(options, Arrays.asList(
                            ACCESS_CONTROL_KEY, PROMPT_TITLE_KEY, PROMPT_SUBTITLE_KEY, PROMPT_CANCEL_KEY
                    ));
                    String accessControl = parsedOptions.get(ACCESS_CONTROL_KEY);

                    currentCipherStorage = getCipherStorageForCurrentAPILevel(getUseBiometry(accessControl));

                    EncryptionResultHandler encryptionHandler = new EncryptionResultHandler() {
                        @Override
                        public void onEncrypt(EncryptionResult encryptionResult, String errorMessage, String errorCode) {
                            if (encryptionResult != null) {
                                prefsStorage.storeEncryptedEntry(resolvedService, encryptionResult);
                                promise.resolve(true);
                            } else {
                                promise.reject(errorCode != null ? errorCode : E_CRYPTO_FAILED, errorMessage);
                            }
                        }
                    };
                    currentCipherStorage.encrypt(encryptionHandler, resolvedService, username, password, parsedOptions);
                } catch (EmptyParameterException e) {
                    Log.e(KEYCHAIN_MODULE, e.getMessage());
                    promise.reject(E_EMPTY_PARAMETERS, e);
                } catch (InvalidKeyException e) {
                    Log.e(KEYCHAIN_MODULE, String.format("Key for service %s permanently invalidated", resolvedService));
                    try {
                        currentCipherStorage.removeKey(resolvedService);
                    } catch (Exception error) {
                        Log.e(KEYCHAIN_MODULE, "Failed removing invalidated key: " + error.getMessage());
                    }
                    promise.resolve(false);
                } catch (CryptoFailedException e) {
                    Log.e(KEYCHAIN_MODULE, e.getMessage());
                    promise.reject(E_CRYPTO_FAILED, e);
                }
            }
        });
    }

    @ReactMethod
    public void getGenericPasswordForOptions(String service, final ReadableMap options, final Promise promise) {
        final String resolvedService = getDefaultServiceIfNull(service);
        CipherStorage cipherStorage = null;
        try {
            ResultSet resultSet = prefsStorage.getEncryptedEntry(resolvedService);
            if (resultSet == null) {
                Log.e(KEYCHAIN_MODULE, "No entry found for service: " + resolvedService);
                promise.resolve(false);
                return;
            }

            final Map<String, String> parsedOptions = parseOptions(options, Arrays.asList(
                    PROMPT_TITLE_KEY, PROMPT_SUBTITLE_KEY, PROMPT_CANCEL_KEY
            ));

            // Android < M will throw an exception as biometry is not supported.
            CipherStorage biometryCipherStorage = null;
            try {
                biometryCipherStorage = getCipherStorageForCurrentAPILevel(true);
            } catch(Exception e) { }
            final CipherStorage nonBiometryCipherStorage = getCipherStorageForCurrentAPILevel(false);
            if (biometryCipherStorage != null && resultSet.cipherStorageName.equals(biometryCipherStorage.getCipherStorageName())) {
                cipherStorage = biometryCipherStorage;
            } else if (nonBiometryCipherStorage != null && resultSet.cipherStorageName.equals(nonBiometryCipherStorage.getCipherStorageName())) {
                cipherStorage = nonBiometryCipherStorage;
            }

            final CipherStorage currentCipherStorage = cipherStorage;
            if (currentCipherStorage != null) {
                DecryptionResultHandler decryptionHandler = new DecryptionResultHandler() {
                    @Override
                    public void onDecrypt(DecryptionResult decryptionResult, String errorMessage, String errorCode) {
                        if (decryptionResult != null) {
                            WritableMap credentials = Arguments.createMap();

                            credentials.putString("service", resolvedService);
                            credentials.putString("username", decryptionResult.username);
                            credentials.putString("password", decryptionResult.password);

                            promise.resolve(credentials);
                        } else {
                            promise.reject(errorCode != null ? errorCode : E_CRYPTO_FAILED, errorMessage);
                        }
                    }
                };
                // The encrypted data is encrypted using the current CipherStorage, so we just decrypt and return
                currentCipherStorage.decrypt(decryptionHandler, resolvedService, resultSet.usernameBytes, resultSet.passwordBytes, parsedOptions);
            }
            else {
                // The encrypted data is encrypted using an older CipherStorage, so we need to decrypt the data first, then encrypt it using the current CipherStorage, then store it again and return
                final CipherStorage oldCipherStorage = getCipherStorageByName(resultSet.cipherStorageName);

                DecryptionResultHandler decryptionHandler = new DecryptionResultHandler() {
                    @Override
                    public void onDecrypt(DecryptionResult decryptionResult, String errorMessage, String errorCode) {
                        if (decryptionResult != null) {
                            final WritableMap credentials = Arguments.createMap();

                            credentials.putString("service", resolvedService);
                            credentials.putString("username", decryptionResult.username);
                            credentials.putString("password", decryptionResult.password);

                            try {
                                // clean up the old cipher storage
                                oldCipherStorage.removeKey(resolvedService);
                                // encrypt using the current cipher storage
                                EncryptionResultHandler encryptionHandler = new EncryptionResultHandler() {
                                    @Override
                                    public void onEncrypt(EncryptionResult encryptionResult, String errorMessage, String errorCode) {
                                        if (encryptionResult != null) {
                                            // store the encryption result
                                            prefsStorage.storeEncryptedEntry(resolvedService, encryptionResult);
                                            promise.resolve(credentials);
                                        } else {
                                            promise.reject(errorCode != null ? errorCode : E_CRYPTO_FAILED, errorMessage);
                                        }
                                    }
                                };
                                nonBiometryCipherStorage.encrypt(encryptionHandler, resolvedService, decryptionResult.username, decryptionResult.password, parsedOptions);
                            } catch (CryptoFailedException e) {
                                Log.e(KEYCHAIN_MODULE, e.getMessage());
                                promise.reject(E_CRYPTO_FAILED, e);
                            } catch (KeyStoreAccessException e) {
                                Log.e(KEYCHAIN_MODULE, e.getMessage());
                                promise.reject(E_KEYSTORE_ACCESS_ERROR, e);
                            } catch (InvalidKeyException e) {
                                Log.e(KEYCHAIN_MODULE, String.format("Key for service %s permanently invalidated", resolvedService));
                                try {
                                    oldCipherStorage.removeKey(resolvedService);
                                } catch (Exception error) {
                                    Log.e(KEYCHAIN_MODULE, "Failed removing invalidated key: " + error.getMessage());
                                }
                                promise.resolve(false);
                            }

                        } else {
                            promise.reject(errorCode != null ? errorCode : E_CRYPTO_FAILED, errorMessage);
                        }
                    }
                };
                // decrypt using the older cipher storage
                oldCipherStorage.decrypt(decryptionHandler, resolvedService, resultSet.usernameBytes, resultSet.passwordBytes, parsedOptions);
            }
        } catch (InvalidKeyException e) {
            Log.e(KEYCHAIN_MODULE, String.format("Key for service %s permanently invalidated", resolvedService));
            try {
                cipherStorage.removeKey(resolvedService);
            } catch (Exception error) {
                Log.e(KEYCHAIN_MODULE, "Failed removing invalidated key: " + error.getMessage());
            }
            promise.resolve(false);
        } catch (CryptoFailedException e) {
            Log.e(KEYCHAIN_MODULE, e.getMessage());
            promise.reject(E_CRYPTO_FAILED, e);
        }
    }

    @ReactMethod
    public void resetGenericPasswordForOptions(String service, Promise promise) {
        try {
            final String resolvedService = getDefaultServiceIfNull(service);

            // First we clean up the cipher storage (using the cipher storage that was used to store the entry)
            ResultSet resultSet = prefsStorage.getEncryptedEntry(resolvedService);
            if (resultSet != null) {
                CipherStorage cipherStorage = getCipherStorageByName(resultSet.cipherStorageName);
                if (cipherStorage != null) {
                    cipherStorage.removeKey(resolvedService);
                }
            }
            // And then we remove the entry in the shared preferences
            prefsStorage.removeEntry(resolvedService);

            promise.resolve(true);
        } catch (KeyStoreAccessException e) {
            Log.e(KEYCHAIN_MODULE, e.getMessage());
            promise.reject(E_KEYSTORE_ACCESS_ERROR, e);
        }
    }

    @ReactMethod
    public void setInternetCredentialsForServer(@NonNull String server, String username, String password, ReadableMap options, Promise promise) {
        setGenericPasswordForOptions(server, username, password, options, promise);
    }

    @ReactMethod
    public void getInternetCredentialsForServer(@NonNull String server, ReadableMap options, Promise promise) {
        getGenericPasswordForOptions(server, options, promise);
    }

    @ReactMethod
    public void resetInternetCredentialsForServer(@NonNull String server, ReadableMap unusedOptions, Promise promise) {
        resetGenericPasswordForOptions(server, promise);
    }

    @ReactMethod
    public void canCheckAuthentication(ReadableMap options, Promise promise) {
        String authenticationType = null;
        if (options != null && options.hasKey(AUTHENTICATION_TYPE_KEY)) {
            authenticationType = options.getString(AUTHENTICATION_TYPE_KEY);
        }

        if (authenticationType == null
                || (!authenticationType.equals(AUTHENTICATION_TYPE_DEVICE_PASSCODE_OR_BIOMETRICS)
                && !authenticationType.equals(AUTHENTICATION_TYPE_BIOMETRICS))) {
            promise.resolve(false);
            return;
        }

        try {
            boolean fingerprintAuthAvailable = isFingerprintAuthAvailable();
            promise.resolve(fingerprintAuthAvailable);
        } catch (Exception e) {
            promise.resolve(false);
        }
    }

    @ReactMethod
    public void getSupportedBiometryType(Promise promise) {
        try {
            boolean fingerprintAuthAvailable = isFingerprintAuthAvailable();
            if (fingerprintAuthAvailable) {
                promise.resolve(FINGERPRINT_SUPPORTED_NAME);
            } else {
                promise.resolve(null);
            }
        } catch (Exception e) {
            Log.e(KEYCHAIN_MODULE, e.getMessage());
            promise.reject(E_SUPPORTED_BIOMETRY_ERROR, e);
        }
    }

    private boolean getUseBiometry(String accessControl) {
        return accessControl != null
                && (accessControl.equals(ACCESS_CONTROL_BIOMETRY_ANY)
                || accessControl.equals(ACCESS_CONTROL_BIOMETRY_CURRENT_SET));
    }

    // The "Current" CipherStorage is the cipherStorage with the highest API level that is lower than or equal to the current API level
    private CipherStorage getCipherStorageForCurrentAPILevel(boolean useBiometry) throws CryptoFailedException {
        int currentAPILevel = Build.VERSION.SDK_INT;
        CipherStorage currentCipherStorage = null;
        for (CipherStorage cipherStorage : cipherStorageMap.values()) {
            int cipherStorageAPILevel = cipherStorage.getMinSupportedApiLevel();
            boolean biometrySupported = cipherStorage.getCipherBiometrySupported();
            // Is the cipherStorage supported on the current API level?
            boolean isSupported = (cipherStorageAPILevel <= currentAPILevel)
                    && (biometrySupported == useBiometry);
            // Is the API level better than the one we previously selected (if any)?
            if (isSupported && (currentCipherStorage == null ||
                    cipherStorageAPILevel > currentCipherStorage.getMinSupportedApiLevel() ||
                    // prefer AES, so don't add RSA (which is bugged on OnePlus - https://github.com/oblador/react-native-keychain/pull/195#issuecomment-492249974)
                    cipherStorage.getCipherStorageName().equals(CipherStorageKeystoreAESCBC.CIPHER_STORAGE_NAME))) {

                currentCipherStorage = cipherStorage;
            }
        }
        if (currentCipherStorage == null) {
            throw new CryptoFailedException("Unsupported Android SDK " + Build.VERSION.SDK_INT);
        }

        if (currentCipherStorage.getRequiresCurrentActivity()) {
            currentCipherStorage.setCurrentActivity(getCurrentActivity());
        }

        return currentCipherStorage;
    }

    private CipherStorage getCipherStorageByName(String cipherStorageName) {
        CipherStorage storage = cipherStorageMap.get(cipherStorageName);

        if (storage.getRequiresCurrentActivity()) {
            storage.setCurrentActivity(getCurrentActivity());
        }

        return storage;
    }

    private boolean isFingerprintAuthAvailable() {
        return DeviceAvailability.isFingerprintAuthAvailable(getReactApplicationContext());
    }

    @NonNull
    private String getDefaultServiceIfNull(String service) {
        return service == null ? EMPTY_STRING : service;
    }
}
