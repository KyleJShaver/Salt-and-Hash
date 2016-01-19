//
//  SaltHash.swift
//  Salt and Hash
//
//  Created by Kyle Shaver on 1/13/16.
//  Copyright © 2016 Kyle Shaver. All rights reserved.
//

/* IMPORTANT: Make sure you put
        #import <CommonCrypto/CommonHMAC.h>
   into your Objective-C Bridging header, or use the included bridging header and set it to be your project's Objective-C Bridging header under Build Settings > Objective-C Bridging Header
*/

import UIKit
import Foundation

class SaltHash: NSObject {
    
    let SHA512_DIGEST_LENGTH: Int = 64
    
    // This can be changed to allow any characters you like in your salt string. Uses NSString for simplicity
    let APPROVED_SALT_CHARACTERS: NSString = "1234567890!@#$%^&()qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM,.?" as NSString
    
    var plaintextPassword : String = ""
    var saltLength : Int = 8
    var salt : String = ""
    var hashedPasword : String = ""
    var numberOfCycles : Int = 1
    
    
    // The standard init will try to automaticallt generate a Salt and hash the password. It will return nil if either the salt or the password is not generated.
    init?(plaintextPassword plainInput : String, saltLength lengthInput : Int) {
        super.init()
        plaintextPassword = plainInput
        saltLength = lengthInput
        (salt, hashedPasword) = saltAndHash(plaintextPassword: plaintextPassword, saltLength: saltLength)
        if (hashedPasword == "" || salt == "") {
            return nil
        }
    }
    
    // Convenience initializer that will also allow you to configure the number of hashing cycles
    convenience init?(plaintextPassword plainInput : String, saltLength lengthInput : Int, numberOfHashCycles cycleInput: Int) {
        self.init(plaintextPassword: plainInput, saltLength: lengthInput)
        numberOfCycles = cycleInput
    }
    
    // The method that can be used to generate a salt and hash, in case you want to use them independent of creating a SaltHash object. Returns a tuple of the generated salt, then the hashed text
    func saltAndHash(plaintextPassword plainInput : String, saltLength lengthInput: Int) -> (String, String) {
        let generatedSalt = generateSalt(saltLength: lengthInput)
        let generatedHash = hashString(plainInput+generatedSalt, numberOfCycles: numberOfCycles);
        return (generatedSalt, generatedHash)
    }
    
    // Uses a string of approved characters to generate a salt of whatever length passed in. Approved characters can be customized by changing APPROVED_SALT_CHARACTERS string. Returns the generated salt as a swift String type
    func generateSalt(saltLength lengthInput: Int) -> String {
        var generatedSalt: String = ""
        for _ in 0..<lengthInput {
            let randomCharPosition = Int(arc4random_uniform(UInt32(APPROVED_SALT_CHARACTERS.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))))
            generatedSalt += APPROVED_SALT_CHARACTERS.substringWithRange(NSRange(location: randomCharPosition, length: 1))
        }
        return generatedSalt
    }
    
    // Will hash whatever string you give it however many times you like. Returns the hashed value as a Base64 swift String
    func hashString(plaintextString: String, numberOfCycles: Int) -> String {
        var tempString = plaintextString as NSString
        for _ in 0..<numberOfCycles {
            var hash = [UInt8](count: SHA512_DIGEST_LENGTH, repeatedValue: 0)
            var stringData = tempString.dataUsingEncoding(NSUTF8StringEncoding)!
            CC_SHA512(stringData.bytes, CC_LONG(stringData.length), &hash)
            stringData = NSData(bytes: hash, length: SHA512_DIGEST_LENGTH)
            tempString = stringData.base64EncodedStringWithOptions([])
        }
        return tempString as String
    }
}
