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
    case md5
    case sha1
    case sha224
    case sha256
    case sha384
    case sha512
    
    public var length: Int {
        switch self {
        case .md5:      return Int(CC_MD5_DIGEST_LENGTH)
        case .sha1:     return Int(CC_SHA1_DIGEST_LENGTH)
        case .sha224:   return Int(CC_SHA224_DIGEST_LENGTH)
        case .sha256:   return Int(CC_SHA256_DIGEST_LENGTH)
        case .sha384:   return Int(CC_SHA384_DIGEST_LENGTH)
        case .sha512:   return Int(CC_SHA512_DIGEST_LENGTH)
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
    public func array(_ data: Data) -> [UInt8] {
        var hash = [UInt8](repeating: 0, count: length)
        switch self {
        case .md5:
            CC_MD5((data as NSData).bytes, UInt32(data.count), &hash)
        case .sha1:
            CC_SHA1((data as NSData).bytes, UInt32(data.count), &hash)
        case .sha224:
            CC_SHA224((data as NSData).bytes, UInt32(data.count), &hash)
        case .sha256:
            CC_SHA256((data as NSData).bytes, UInt32(data.count), &hash)
        case .sha384:
            CC_SHA384((data as NSData).bytes, UInt32(data.count), &hash)
        case .sha512:
            CC_SHA512((data as NSData).bytes, UInt32(data.count), &hash)
        }
        return hash
    }
    
    /**
     生成 hash 字符串
     
     - Note:    常见的 hash 十六进制字符串表示, 与 Array< UInt8 > 的对象可相互转化
     
     - parameter hashArray: 待编码的 hashArray
     
     - returns: hash 字符串
     */
    public func string(_ hashArray: [UInt8]) -> String {
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
    public func string(_ hashData: Data) -> String {
        return string(array(hashData))
    }
}

public extension Data {
    
    /**
     计算 NSData 的 hash
     */
    public func hashString(_ type: Hash) -> String {
        return type.string(self)
    }
}

public extension String {
    
    /**
     计算 String 的 hash
     */
    public func hashString(_ type: Hash) -> String {
        if let data = data(using: String.Encoding.ascii) {
            return type.string(data)
        }
        return ""
    }
}
