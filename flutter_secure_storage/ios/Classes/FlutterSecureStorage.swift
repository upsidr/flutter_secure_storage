//
//  FlutterSecureStorageManager.swift
//  flutter_secure_storage
//
//  Created by Julian Steenbakker on 22/08/2022.
//

import Foundation

class FlutterSecureStorage{
    
    private func baseQuery(key: String?, groupId: String?, accountName: String?, synchronizable: Bool?, returnData: Bool?, accessControl: SecAccessControl?) -> Dictionary<CFString, Any> {
        var keychainQuery: [CFString: Any] = [kSecClass : kSecClassGenericPassword]
        if (key != nil) {
            keychainQuery[kSecAttrAccount] = key
            
        }
        
        if (groupId != nil) {
            keychainQuery[kSecAttrAccessGroup] = groupId
        }
        
        if (accountName != nil) {
            keychainQuery[kSecAttrService] = accountName
        }
        
        if (synchronizable != nil) {
            keychainQuery[kSecAttrSynchronizable] = synchronizable
        }
        
        if (returnData != nil) {
            keychainQuery[kSecReturnData] = returnData
        }

        if (accessControl != nil) {
            keychainQuery[kSecAttrAccessControl] = accessControl
        }
        return keychainQuery
    }
    
    internal func containsKey(key: String, groupId: String?, accountName: String?, synchronizable: Bool?) -> Bool {
        if read(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable).value != nil {
            return true
        } else {
            return false
        }
    }
    
    internal func readAll(groupId: String?, accountName: String?, synchronizable: Bool?) -> FlutterSecureStorageResponse {
        var keychainQuery = baseQuery(key: nil, groupId: groupId, accountName: accountName, synchronizable: synchronizable, returnData: true)
        
        keychainQuery[kSecMatchLimit] = kSecMatchLimitAll
        keychainQuery[kSecReturnAttributes] = true
        
        var ref: AnyObject?
        let status = SecItemCopyMatching(
            keychainQuery as CFDictionary,
            &ref
        )
        
        var results: [String: String] = [:]
        
        if (status == noErr) {
            (ref as! NSArray).forEach { item in
                let key: String = (item as! NSDictionary)[kSecAttrAccount] as! String
                let value: String = String(data: (item as! NSDictionary)[kSecValueData] as! Data, encoding: .utf8) ?? ""
                results[key] = value
            }
        }
        
        return FlutterSecureStorageResponse(status: status, value: results)
    }
    
    internal func read(key: String, groupId: String?, accountName: String?, synchronizable: Bool?) -> FlutterSecureStorageResponse {
        let keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, returnData: true)
        
        var ref: AnyObject?
        let status = SecItemCopyMatching(
            keychainQuery as CFDictionary,
            &ref
        )
        
        var value: String? = nil
        
        if (status == noErr) {
            value = String(data: ref as! Data, encoding: .utf8)
        }
        return FlutterSecureStorageResponse(status: status, value: value)
    }
    
    internal func deleteAll(groupId: String?, accountName: String?, synchronizable: Bool?) -> OSStatus {
        let keychainQuery = baseQuery(key: nil, groupId: groupId, accountName: accountName, synchronizable: synchronizable, returnData: nil)
        
        return SecItemDelete(keychainQuery as CFDictionary)
    }
    
    internal func delete(key: String, groupId: String?, accountName: String?, synchronizable: Bool?) -> OSStatus {
        let keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, returnData: true)
        
        return SecItemDelete(keychainQuery as CFDictionary)
    }
    
    internal func write(key: String, value: String, groupId: String?, accountName: String?, synchronizable: Bool?, accessibility: String?, accessControl: String?) -> OSStatus {
        var attrAccessible: CFString = kSecAttrAccessibleWhenUnlocked
        if (accessibility != nil) {
            switch accessibility {
            case "passcode":
                attrAccessible = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
                break;
            case "unlocked":
                attrAccessible = kSecAttrAccessibleWhenUnlocked
                break
            case "unlocked_this_device":
                attrAccessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                break
            case "first_unlock":
                attrAccessible = kSecAttrAccessibleAfterFirstUnlock
                break
            case "first_unlock_this_device":
                attrAccessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                break
            default:
                attrAccessible = kSecAttrAccessibleWhenUnlocked
            }
        }

        let accessControlIsOn = accessControl != nil
        var accessControlCreateWithFlags: SecAccessControl?
        if let accessControl = accessControl {
            var secAccessControlCreateFlags: SecAccessControlCreateFlags
            if accessControl == "devicePasscode" {
                secAccessControlCreateFlags = SecAccessControlCreateFlags.devicePasscode
            } else if accessControl == "biometryAny" {
                secAccessControlCreateFlags = SecAccessControlCreateFlags.biometryAny
            }  else if accessControl == "biometryCurrentSet" {
                secAccessControlCreateFlags = SecAccessControlCreateFlags.biometryCurrentSet
            }  else if accessControl == "userPresence" {
                secAccessControlCreateFlags = SecAccessControlCreateFlags.userPresence
            }  else {
                abort()
            }

            var error: Unmanaged<CFError>?
            accessControlCreateWithFlags = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                           attrAccessible,
                                                                           secAccessControlCreateFlags,
                                                                           &error)
        }

        // When calling "read", authentication is always performed, so remove it and proceed with the writing.
        var keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, returnData: nil, accessControl: accessControlCreateWithFlags)

        let err = delete(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable)

        let errType = OSStatusType(rawValue: err)

        // The result of the deletion should be either "success" or "not found".
        guard [.noError, .couldNotFound ].contains( errType ) else { return err }

        keychainQuery[kSecValueData] = value.data(using: String.Encoding.utf8)

        if !accessControlIsOn {
            keychainQuery[kSecAttrAccessible] = attrAccessible
        }

        return SecItemAdd(keychainQuery as CFDictionary, nil)
    }
    
    struct FlutterSecureStorageResponse {
        var status: OSStatus?
        var value: Any?
    }
}

