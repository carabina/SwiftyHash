//
//  FileHash.swift
//  SwiftyHash
//
//  Created by 栋刘 on 16/7/28.
//  Copyright © 2016年 anotheren.com. All rights reserved.
//

import Foundation
import CommonCrypto

public struct FileHash {
    
    private static let sizeForReadingData: Int = 4096
    
    public static func hashString(_ type: Hash, filePath: String) -> String? {
        guard let array: Array<UInt8> = hashArray(type, filePath: filePath) else { return nil }
        return type.string(array)
    }
 
    public static func hashArray(_ type: Hash, filePath: String) -> Array<UInt8>? {
        guard FileManager.default.fileExists(atPath: filePath) else { return nil}
        let fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, filePath as CFString!, .cfurlposixPathStyle, false)
        let readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault, fileURL)
        let didSucceed = readStream != nil ? CFReadStreamOpen(readStream) : false
        guard didSucceed else { return nil }
        
        var digest = Array<UInt8>(repeating: 0, count: type.length)
        switch type {
        case .md5:
            if !hashOfFileMD5(&digest, readStream: readStream!) { return nil }
        case .sha1:
            if !hashOfFileSHA1(&digest, readStream: readStream!) { return nil }
        case .sha224:
            if !hashOfFileSHA224(&digest, readStream: readStream!) { return nil }
        case .sha256:
            if !hashOfFileSHA256(&digest, readStream: readStream!) { return nil }
        case .sha384:
            if !hashOfFileSHA384(&digest, readStream: readStream!) { return nil }
        case .sha512:
            if !hashOfFileSHA512(&digest, readStream: readStream!) { return nil }
        }
        CFReadStreamClose(readStream)
        return digest
    }
    
    private static func hashOfFileMD5(_ digestPointer: UnsafeMutablePointer<UInt8>, readStream: CFReadStream) -> Bool {
        var hashObject = CC_MD5_CTX()
        CC_MD5_Init(&hashObject)
        var hasMoreData = true
        while hasMoreData {
            var buffer = Array<UInt8>(repeating: 0, count: sizeForReadingData)
            let readBytesCount = CFReadStreamRead(readStream, &buffer, sizeForReadingData)
            if readBytesCount == -1 {
                break
            } else if readBytesCount == 0 {
                hasMoreData = false
            } else {
                CC_MD5_Update(&hashObject, &buffer, CC_LONG(readBytesCount))
            }
        }
        if hasMoreData { return false }
        CC_MD5_Final(digestPointer, &hashObject)
        return true
    }
    
    private static func hashOfFileSHA1(_ digestPointer: UnsafeMutablePointer<UInt8>, readStream: CFReadStream) -> Bool {
        var hashObject = CC_SHA1_CTX()
        CC_SHA1_Init(&hashObject)
        var hasMoreData = true
        while hasMoreData {
            var buffer = Array<UInt8>(repeating: 0, count: sizeForReadingData)
            let readBytesCount = CFReadStreamRead(readStream, &buffer, sizeForReadingData)
            if readBytesCount == -1 {
                break
            } else if readBytesCount == 0 {
                hasMoreData = false
            } else {
                CC_SHA1_Update(&hashObject, &buffer, CC_LONG(readBytesCount))
            }
        }
        if hasMoreData { return false }
        CC_SHA1_Final(digestPointer, &hashObject)
        return true
    }
    
    private static func hashOfFileSHA224(_ digestPointer: UnsafeMutablePointer<UInt8>, readStream: CFReadStream) -> Bool {
        var hashObject = CC_SHA256_CTX() // same context struct is used for SHA224 and SHA256
        CC_SHA224_Init(&hashObject)
        var hasMoreData = true
        while hasMoreData {
            var buffer = Array<UInt8>(repeating: 0, count: sizeForReadingData)
            let readBytesCount = CFReadStreamRead(readStream, &buffer, sizeForReadingData)
            if readBytesCount == -1 {
                break
            } else if readBytesCount == 0 {
                hasMoreData = false
            } else {
                CC_SHA224_Update(&hashObject, &buffer, CC_LONG(readBytesCount))
            }
        }
        if hasMoreData { return false }
        CC_SHA224_Final(digestPointer, &hashObject)
        return true
    }
    
    private static func hashOfFileSHA256(_ digestPointer: UnsafeMutablePointer<UInt8>, readStream: CFReadStream) -> Bool {
        var hashObject = CC_SHA256_CTX()
        CC_SHA256_Init(&hashObject)
        var hasMoreData = true
        while hasMoreData {
            var buffer = Array<UInt8>(repeating: 0, count: sizeForReadingData)
            let readBytesCount = CFReadStreamRead(readStream, &buffer, sizeForReadingData)
            if readBytesCount == -1 {
                break
            } else if readBytesCount == 0 {
                hasMoreData = false
            } else {
                CC_SHA256_Update(&hashObject, &buffer, CC_LONG(readBytesCount))
            }
        }
        if hasMoreData { return false }
        CC_SHA256_Final(digestPointer, &hashObject)
        return true
    }
    
    private static func hashOfFileSHA384(_ digestPointer: UnsafeMutablePointer<UInt8>, readStream: CFReadStream) -> Bool {
        var hashObject = CC_SHA512_CTX() // same context struct is used for SHA384 and SHA512
        CC_SHA384_Init(&hashObject)
        var hasMoreData = true
        while hasMoreData {
            var buffer = Array<UInt8>(repeating: 0, count: sizeForReadingData)
            let readBytesCount = CFReadStreamRead(readStream, &buffer, sizeForReadingData)
            if readBytesCount == -1 {
                break
            } else if readBytesCount == 0 {
                hasMoreData = false
            } else {
                CC_SHA384_Update(&hashObject, &buffer, CC_LONG(readBytesCount))
            }
        }
        if hasMoreData { return false }
        CC_SHA384_Final(digestPointer, &hashObject)
        return true
    }
    
    private static func hashOfFileSHA512(_ digestPointer: UnsafeMutablePointer<UInt8>, readStream: CFReadStream) -> Bool {
        var hashObject = CC_SHA512_CTX()
        CC_SHA512_Init(&hashObject)
        var hasMoreData = true
        while hasMoreData {
            var buffer = Array<UInt8>(repeating: 0, count: sizeForReadingData)
            let readBytesCount = CFReadStreamRead(readStream, &buffer, sizeForReadingData)
            if readBytesCount == -1 {
                break
            } else if readBytesCount == 0 {
                hasMoreData = false
            } else {
                CC_SHA512_Update(&hashObject, &buffer, CC_LONG(readBytesCount))
            }
        }
        if hasMoreData { return false }
        CC_SHA512_Final(digestPointer, &hashObject)
        return true
    }
}
