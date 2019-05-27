import { NativeModules, Platform } from 'react-native';
const { RNKeychainManager } = NativeModules;

// iOS
export const ERR_SEC_UNIMPLEMENTED = RNKeychainManager.errSecUnimplemented;
export const ERR_SEC_IO = RNKeychainManager.errSecIO;
export const ERR_SEC_OP_WR = RNKeychainManager.errSecOpWr;
export const ERR_SEC_PARAM = RNKeychainManager.errSecParam;
export const ERR_SEC_ALLOCATE = RNKeychainManager.errSecAllocate;
export const ERR_SEC_USER_CANCELED = RNKeychainManager.errSecUserCanceled;
export const ERR_SEC_BAD_REQ = RNKeychainManager.errSecBadReq;
export const ERR_SEC_NOT_AVAILABLE = RNKeychainManager.errSecNotAvailable;
export const ERR_SEC_DUPLICATE_ITEM = RNKeychainManager.errSecDuplicateItem;
export const ERR_SEC_ITEM_NOT_FOUND = RNKeychainManager.errSecItemNotFound;
export const ERR_SEC_INTERACTION_NOT_ALLOWED = RNKeychainManager.errSecInteractionNotAllowed;
export const ERR_SEC_DECODE = RNKeychainManager.errSecDecode;
export const ERR_SEC_AUTH_FAILED = RNKeychainManager.errSecAuthFailed;
export const ERR_SEC_MISSING_ENTITLEMEN = RNKeychainManager.errSecMissingEntitlemen;
// Android
export const BIOMETRIC_ERROR_HW_UNAVAILABLE = RNKeychainManager.BIOMETRIC_ERROR_HW_UNAVAILABLE;
export const BIOMETRIC_ERROR_UNABLE_TO_PROCESS = RNKeychainManager.BIOMETRIC_ERROR_UNABLE_TO_PROCESS;
export const BIOMETRIC_ERROR_TIMEOUT = RNKeychainManager.BIOMETRIC_ERROR_TIMEOUT;
export const BIOMETRIC_ERROR_NO_SPACE = RNKeychainManager.BIOMETRIC_ERROR_NO_SPACE;
export const BIOMETRIC_ERROR_CANCELED = RNKeychainManager.BIOMETRIC_ERROR_CANCELED;
export const BIOMETRIC_ERROR_LOCKOUT = RNKeychainManager.BIOMETRIC_ERROR_LOCKOUT;
export const BIOMETRIC_ERROR_VENDOR = RNKeychainManager.BIOMETRIC_ERROR_VENDOR;
export const BIOMETRIC_ERROR_LOCKOUT_PERMANENT = RNKeychainManager.BIOMETRIC_ERROR_LOCKOUT_PERMANENT;
export const BIOMETRIC_ERROR_USER_CANCELED = RNKeychainManager.BIOMETRIC_ERROR_USER_CANCELED;
export const BIOMETRIC_ERROR_NO_BIOMETRICS = RNKeychainManager.BIOMETRIC_ERROR_NO_BIOMETRICS;
export const BIOMETRIC_ERROR_HW_NOT_PRESENT = RNKeychainManager.BIOMETRIC_ERROR_HW_NOT_PRESENT;
export const BIOMETRIC_ERROR_NEGATIVE_BUTTON = RNKeychainManager.BIOMETRIC_ERROR_NEGATIVE_BUTTON;

export const ACCESSIBLE = {
  WHEN_UNLOCKED: 'AccessibleWhenUnlocked',
  AFTER_FIRST_UNLOCK: 'AccessibleAfterFirstUnlock',
  ALWAYS: 'AccessibleAlways',
  WHEN_PASSCODE_SET_THIS_DEVICE_ONLY: 'AccessibleWhenPasscodeSetThisDeviceOnly',
  WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'AccessibleWhenUnlockedThisDeviceOnly',
  AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY:
    'AccessibleAfterFirstUnlockThisDeviceOnly',
  ALWAYS_THIS_DEVICE_ONLY: 'AccessibleAlwaysThisDeviceOnly',
};

export const ACCESS_CONTROL = {
  USER_PRESENCE: 'UserPresence',
  BIOMETRY_ANY: 'BiometryAny',
  BIOMETRY_CURRENT_SET: 'BiometryCurrentSet',
  DEVICE_PASSCODE: 'DevicePasscode',
  APPLICATION_PASSWORD: 'ApplicationPassword',
  BIOMETRY_ANY_OR_DEVICE_PASSCODE: 'BiometryAnyOrDevicePasscode',
  BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE: 'BiometryCurrentSetOrDevicePasscode',
};

export const AUTHENTICATION_TYPE = {
  DEVICE_PASSCODE_OR_BIOMETRICS: 'AuthenticationWithBiometricsDevicePasscode',
  BIOMETRICS: 'AuthenticationWithBiometrics',
};

export const BIOMETRY_TYPE = {
  TOUCH_ID: 'TouchID',
  FACE_ID: 'FaceID',
  FINGERPRINT: 'Fingerprint',
};

type SecAccessible =
  | 'AccessibleWhenUnlocked'
  | 'AccessibleAfterFirstUnlock'
  | 'AccessibleAlways'
  | 'AccessibleWhenPasscodeSetThisDeviceOnly'
  | 'AccessibleWhenUnlockedThisDeviceOnly'
  | 'AccessibleAfterFirstUnlockThisDeviceOnly'
  | 'AccessibleAlwaysThisDeviceOnly';

type SecAccessControl =
  | 'UserPresence'
  | 'BiometryAny'
  | 'BiometryCurrentSet'
  | 'DevicePasscode'
  | 'ApplicationPassword'
  | 'BiometryAnyOrDevicePasscode'
  | 'BiometryCurrentSetOrDevicePasscode';

type LAPolicy = 'Authentication' | 'AuthenticationWithBiometrics';

type Options = {
  accessControl?: SecAccessControl,
  accessGroup?: string,
  accessible?: SecAccessible,
  authenticationPrompt?: string,
  authenticationType?: LAPolicy,
  service?: string,
};

/**
 * Inquire if the type of local authentication policy (LAPolicy) is supported
 * on this device with the device settings the user chose.
 * @param {object} options LAPolicy option, iOS only
 * @return {Promise} Resolves to `true` when supported, otherwise `false`
 */
export function canImplyAuthentication(options?: Options): Promise {
  if (!RNKeychainManager.canCheckAuthentication) {
    return Promise.resolve(false);
  }
  return RNKeychainManager.canCheckAuthentication(options);
}

/**
 * Get what type of hardware biometry support the device has.
 * @return {Promise} Resolves to a `BIOMETRY_TYPE` when supported, otherwise `null`
 */
export function getSupportedBiometryType(): Promise {
  if (!RNKeychainManager.getSupportedBiometryType) {
    return Promise.resolve(null);
  }
  return RNKeychainManager.getSupportedBiometryType();
}

/**
 * Saves the `username` and `password` combination for `server`.
 * @param {string} server URL to server.
 * @param {string} username Associated username or e-mail to be saved.
 * @param {string} password Associated password to be saved.
 * @param {object} options Keychain options, iOS only
 * @return {Promise} Resolves to `true` when successful
 */
export function setInternetCredentials(
  server: string,
  username: string,
  password: string,
  options?: Options
): Promise {
  return RNKeychainManager.setInternetCredentialsForServer(
    server,
    username,
    password,
    options
  );
}

/**
 * Fetches login combination for `server`.
 * @param {string} server URL to server.
 * @param {object} options Keychain options, iOS only
 * @return {Promise} Resolves to `{ server, username, password }` when successful
 */
export function getInternetCredentials(
  server: string,
  options?: Options
): Promise {
  return RNKeychainManager.getInternetCredentialsForServer(server, options);
}

/**
 * Deletes all internet password keychain entries for `server`.
 * @param {string} server URL to server.
 * @param {object} options Keychain options, iOS only
 * @return {Promise} Resolves to `true` when successful
 */
export function resetInternetCredentials(
  server: string,
  options?: Options
): Promise {
  return RNKeychainManager.resetInternetCredentialsForServer(server, options);
}

function getOptionsArgument(serviceOrOptions?: string | Options) {
  if (Platform.OS !== 'ios') {
    return typeof serviceOrOptions === 'object'
      ? serviceOrOptions.service
      : serviceOrOptions;
  }
  return typeof serviceOrOptions === 'string'
    ? { service: serviceOrOptions }
    : serviceOrOptions;
}

/**
 * Saves the `username` and `password` combination for `service`.
 * @param {string} username Associated username or e-mail to be saved.
 * @param {string} password Associated password to be saved.
 * @param {string|object} serviceOrOptions Reverse domain name qualifier for the service, defaults to `bundleId` or an options object.
 * @return {Promise} Resolves to `true` when successful
 */
export function setGenericPassword(
  username: string,
  password: string,
  serviceOrOptions?: string | Options
): Promise {
  return RNKeychainManager.setGenericPasswordForOptions(
    getOptionsArgument(serviceOrOptions),
    username,
    password,
    serviceOrOptions,
  );
}

/**
 * Fetches login combination for `service`.
 * @param {string|object} serviceOrOptions Reverse domain name qualifier for the service, defaults to `bundleId` or an options object.
 * @return {Promise} Resolves to `{ service, username, password }` when successful
 */
export function getGenericPassword(
  serviceOrOptions?: string | Options
): Promise {
  return RNKeychainManager.getGenericPasswordForOptions(
    getOptionsArgument(serviceOrOptions),
    serviceOrOptions,
  );
}

/**
 * Deletes all generic password keychain entries for `service`.
 * @param {string|object} serviceOrOptions Reverse domain name qualifier for the service, defaults to `bundleId` or an options object.
 * @return {Promise} Resolves to `true` when successful
 */
export function resetGenericPassword(
  serviceOrOptions?: string | Options
): Promise {
  return RNKeychainManager.resetGenericPasswordForOptions(
    getOptionsArgument(serviceOrOptions)
  );
}

/**
 * Asks the user for a shared web credential.
 * @return {Promise} Resolves to `{ server, username, password }` if approved and
 * `false` if denied and throws an error if not supported on platform or there's no shared credentials
 */
export function requestSharedWebCredentials(): Promise {
  if (Platform.OS !== 'ios') {
    return Promise.reject(
      new Error(
        `requestSharedWebCredentials() is not supported on ${Platform.OS} yet`
      )
    );
  }
  return RNKeychainManager.requestSharedWebCredentials();
}

/**
 * Sets a shared web credential.
 * @param {string} server URL to server.
 * @param {string} username Associated username or e-mail to be saved.
 * @param {string} password Associated password to be saved.
 * @return {Promise} Resolves to `true` when successful
 */
export function setSharedWebCredentials(
  server: string,
  username: string,
  password: string
): Promise {
  if (Platform.OS !== 'ios') {
    return Promise.reject(
      new Error(
        `setSharedWebCredentials() is not supported on ${Platform.OS} yet`
      )
    );
  }
  return RNKeychainManager.setSharedWebCredentialsForServer(
    server,
    username,
    password
  );
}
