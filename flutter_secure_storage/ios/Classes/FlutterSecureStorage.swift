//
//  FlutterSecureStorageManager.swift
//  flutter_secure_storage
//
//  Created by Julian Steenbakker on 22/08/2022.
//

import Foundation

class FlutterSecureStorage{
    private func parseAccessibleAttr(accessibility: String?) -> CFString {
        guard let accessibility = accessibility else {
            return kSecAttrAccessibleWhenUnlocked
        }
        
        switch accessibility {
        case "passcode":
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case "unlocked":
            return kSecAttrAccessibleWhenUnlocked
        case "unlocked_this_device":
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case "first_unlock":
            return kSecAttrAccessibleAfterFirstUnlock
        case "first_unlock_this_device":
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        default:
            return kSecAttrAccessibleWhenUnlocked
        }
    }
    
    private func baseQuery(key: String?, groupId: String?, accountName: String?, synchronizable: Bool?, accessibility: String?, returnData: Bool?, accessControl: SecAccessControl?) -> Dictionary<CFString, Any> {
        var keychainQuery: [CFString: Any] = [
            kSecClass : kSecClassGenericPassword,
        ]
        
        // Enable only when accessControl is not set because accessControl and kSecAttrAccessible cannot be used at the same time
        if(accessControl == nil) {
            keychainQuery[kSecAttrAccessible] = parseAccessibleAttr(accessibility: accessibility)
        }
        
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
    
    internal func containsKey(key: String, groupId: String?, accountName: String?, synchronizable: Bool?, accessibility: String?) -> Result<Bool, OSSecError> {
        let keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, returnData: false, accessControl: nil)
        
        let status = SecItemCopyMatching(keychainQuery as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return .success(true)
        case errSecItemNotFound:
            return .success(false)
        default:
            return .failure(OSSecError(status: status))
        }
    }
    
    internal func readAll(groupId: String?, accountName: String?, synchronizable: Bool?) -> FlutterSecureStorageResponse {
        var keychainQuery = baseQuery(key: nil, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: nil, returnData: true, accessControl: nil)
        
        keychainQuery[kSecMatchLimit] = kSecMatchLimitAll
        keychainQuery[kSecReturnAttributes] = true
        
        var ref: AnyObject?
        let status = SecItemCopyMatching(
            keychainQuery as CFDictionary,
            &ref
        )
        
        if (status == errSecItemNotFound) {
            // readAll() returns all elements, so return nil if the items does not exist
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        
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
    
    internal func read(key: String, groupId: String?, accountName: String?, synchronizable: Bool?, accessibility: String?) -> FlutterSecureStorageResponse {
        let keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, returnData: true, accessControl: nil)
        
        var ref: AnyObject?
        let status = SecItemCopyMatching(
            keychainQuery as CFDictionary,
            &ref
        )
        
        // Return nil if the key is not found
        if (status == errSecItemNotFound) {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        
        var value: String? = nil
        
        if (status == noErr) {
            value = String(data: ref as! Data, encoding: .utf8)
        }
        
        return FlutterSecureStorageResponse(status: status, value: value)
    }
    
    internal func deleteAll(groupId: String?, accountName: String?, synchronizable: Bool?) -> FlutterSecureStorageResponse {
        let keychainQuery = baseQuery(key: nil, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: nil, returnData: nil, accessControl: nil)
        let status = SecItemDelete(keychainQuery as CFDictionary)
        
        if (status == errSecItemNotFound) {
            // deleteAll() deletes all items, so return nil if the items does not exist
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        
        return FlutterSecureStorageResponse(status: status, value: nil)
    }
    
    internal func delete(key: String, groupId: String?, accountName: String?, synchronizable: Bool?, accessibility: String?) -> FlutterSecureStorageResponse {
        let keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, returnData: true, accessControl: nil)
        let status = SecItemDelete(keychainQuery as CFDictionary)
        
        // Return nil if the key is not found
        if (status == errSecItemNotFound) {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        
        return FlutterSecureStorageResponse(status: status, value: nil)
    }
    
    internal func write(key: String, value: String, groupId: String?, accountName: String?, synchronizable: Bool?, accessibility: String?, accessControl: String?) -> FlutterSecureStorageResponse {
 
        
        let attrAccessible = parseAccessibleAttr(accessibility: accessibility)
        
        // アクセスコントロールが設定されているかどうか
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
        var keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, returnData: nil, accessControl: accessControlCreateWithFlags)
        
        let resp = delete(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility)
        
        
         let errType = OSStatusType(rawValue: resp.status!)

        
        // The result of the deletion should be either "success" or "not found".
        guard [.noError, .couldNotFound ].contains( errType ) else { return resp }
        
        keychainQuery[kSecValueData] = value.data(using: String.Encoding.utf8)
        
        if !accessControlIsOn {
            keychainQuery[kSecAttrAccessible] = attrAccessible
        }
        
        let status = SecItemAdd(keychainQuery as CFDictionary, nil)
        
        return FlutterSecureStorageResponse(status: status, value: nil)
    }
}

struct FlutterSecureStorageResponse {
    var status: OSStatus?
    var value: Any?
}

struct OSSecError: Error {
    var status: OSStatus
}
