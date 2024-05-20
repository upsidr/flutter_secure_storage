part of '../flutter_secure_storage.dart';

/// KeyChain accessibility attributes as defined here:
/// https://developer.apple.com/documentation/security/ksecattraccessible?language=objc
enum KeychainAccessibility {
  /// The data in the keychain can only be accessed when the device is unlocked.
  /// Only available if a passcode is set on the device.
  /// Items with this attribute do not migrate to a new device.
  passcode,

  /// The data in the keychain item can be accessed only while the device is unlocked by the user.
  unlocked,

  /// The data in the keychain item can be accessed only while the device is unlocked by the user.
  /// Items with this attribute do not migrate to a new device.
  unlocked_this_device,

  /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
  first_unlock,

  /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
  /// Items with this attribute do not migrate to a new device.
  first_unlock_this_device,
}

abstract class AppleOptions extends Options {
  const AppleOptions({
    String? groupId,
    String? accountName = AppleOptions.defaultAccountName,
    KeychainAccessibility accessibility = KeychainAccessibility.unlocked,
    bool synchronizable = false,
    IOSAccessControlCreateFlags? accessControlCreateFlags,
  })  : _groupId = groupId,
        _accessibility = accessibility,
        _accountName = accountName,
        _synchronizable = synchronizable,
        _accessControlCreateFlags = accessControlCreateFlags;

  static const defaultAccountName = 'flutter_secure_storage_service';

  final String? _groupId;
  final String? _accountName;
  final KeychainAccessibility _accessibility;
  final bool _synchronizable;
  final IOSAccessControlCreateFlags? _accessControlCreateFlags;

  @override
  Map<String, String> toMap() => <String, String>{
        // TODO: Update min SDK from 2.12 to 2.15 in new major version to fix this deprecation warning
        // ignore: deprecated_member_use
        'accessibility': describeEnum(_accessibility),
        if (_accountName != null) 'accountName': _accountName!,
        if (_groupId != null) 'groupId': _groupId!,
        'synchronizable': '$_synchronizable',
        if (_accessControlCreateFlags != null)
          'accessControlCreateFlags': _accessControlCreateFlags!.name,
      };
}
