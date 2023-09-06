part of '../flutter_secure_storage.dart';

enum IOSAccessControlCreateFlags {
  devicePasscode,
  biometryAny,
  biometryCurrentSet,
  userPresence,
  watch,
}

/// Specific options for iOS platform.
class IOSOptions extends AppleOptions {
  const IOSOptions({
    String? groupId,
    String? accountName = AppleOptions.defaultAccountName,
    KeychainAccessibility accessibility = KeychainAccessibility.unlocked,
    bool synchronizable = false,
    IOSAccessControlCreateFlags? accessControlCreateFlags,
  }) : super(
          groupId: groupId,
          accountName: accountName,
          accessibility: accessibility,
          synchronizable: synchronizable,
          accessControlCreateFlags: accessControlCreateFlags,
        );

  static const IOSOptions defaultOptions = IOSOptions();

  IOSOptions copyWith({
    String? groupId,
    String? accountName,
    KeychainAccessibility? accessibility,
    bool? synchronizable,
    IOSAccessControlCreateFlags? accessControlCreateFlags,
  }) =>
      IOSOptions(
        groupId: groupId ?? _groupId,
        accountName: accountName ?? _accountName,
        accessibility: accessibility ?? _accessibility,
        synchronizable: synchronizable ?? _synchronizable,
        accessControlCreateFlags: accessControlCreateFlags,
      );
}
