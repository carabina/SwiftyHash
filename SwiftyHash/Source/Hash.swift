//
//  Hash.swift
//  SwiftyHash
//
//  Created by 栋刘 on 16/7/11.
//  Copyright © 2016年 anotheren.com. All rights reserved.
//

import Foundation
import CommonCrypto

/// Hash 算法
public enum Hash {
    case MD5
    case SHA1
    case SHA224
    case SHA256
    case SHA384
    case SHA512
    
    public var length: Int {
        switch self {
        case .MD5:      return Int(CC_MD5_DIGEST_LENGTH)
        case .SHA1:     return Int(CC_SHA1_DIGEST_LENGTH)
        case .SHA224:   return Int(CC_SHA224_DIGEST_LENGTH)
        case .SHA256:   return Int(CC_SHA256_DIGEST_LENGTH)
        case .SHA384:   return Int(CC_SHA384_DIGEST_LENGTH)
        case .SHA512:   return Int(CC_SHA512_DIGEST_LENGTH)
        }
    }
}

extension Hash {
    
    /**
     计算 hash
     
     - Note:    hash 码的实质即为 Array< UInt8 >
     
     - parameter data: 需要求 hash 的文件
     
     - returns: hash 结果
     */
    public func array(data: NSData) -> [UInt8] {
        var hash = [UInt8](count: length, repeatedValue: 0)
        switch self {
        case .MD5:
            CC_MD5(data.bytes, UInt32(data.length), &hash)
        case .SHA1:
            CC_SHA1(data.bytes, UInt32(data.length), &hash)
        case .SHA224:
            CC_SHA224(data.bytes, UInt32(data.length), &hash)
        case .SHA256:
            CC_SHA256(data.bytes, UInt32(data.length), &hash)
        case .SHA384:
            CC_SHA384(data.bytes, UInt32(data.length), &hash)
        case .SHA512:
            CC_SHA512(data.bytes, UInt32(data.length), &hash)
        }
        return hash
    }
    
    /**
     生成 hash 字符串
     
     - Note:    常见的 hash 十六进制字符串表示, 与 Array< UInt8 > 的对象可相互转化
     
     - parameter hashArray: 待编码的 hashArray
     
     - returns: hash 字符串
     */
    public func string(hashArray: [UInt8]) -> String {
        var string = ""
        for i in 0..<length {
            string += String(format: "%02x", hashArray[Int(i)])
        }
        return string
    }
    
    /**
     生成 hash 字符串
     
     - Note:    常见的 hash 十六进制字符串表示, 与 Array< UInt8 > 的对象可相互转化

     - parameter hashData: 待编码的 hashData
     
     - returns: hash 字符串
     */
    public func string(hashData: NSData) -> String {
        return string(array(hashData))
    }
}

public extension NSData {
    
    /**
     计算 NSData 的 hash
     */
    public func hashString(type: Hash) -> String {
        return type.string(self)
    }
}

public extension String {
    
    /**
     计算 String 的 hash
     */
    public func hashString(type: Hash) -> String {
        if let data = dataUsingEncoding(NSASCIIStringEncoding) {
            return type.string(data)
        }
        return ""
    }
}