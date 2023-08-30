var crypto = require('crypto')
var fs = require('fs')
var jwt = require('jsonwebtoken')
var base64url = require('base64-url')
const jose = require('jose')

async function refreshToken(auth)
{
    const pkcs8 = fs.readFileSync("privateKey.pem").toString() //Gets EdDSA key
    var token = fs.readFileSync("jwt.txt") //Gets last stored Jwt
    var tokenPayload = token.subarray(21, 256).toString() //Gets the payload of the Jwt
    let text = base64url.decode(tokenPayload).toString() //Decodes the payload
    var ts = Buffer.from(text) //Creates buffer of decoded payload
    var tsSlice = ts.subarray(98, 108).toString() //Gets expiration timestamp from the payload
    var newts = Math.round(Date.now() / 1000) //Gets current timestamp
    if (parseInt(tsSlice) < newts) //Checks if expiration time is over
    {
        var payload = {
            "sub": auth["Username"],
            "iss": "enigma",
            "jit": auth["authSecret"],
            "aud": [
                "client",
                "web"
            ],
            "nbf": Math.round(Date.now() / 1000),
            "exp": Math.round(Date.now() / 1000) + 17280000,
            "iat": Math.round(Date.now() / 1000),
            "sid": auth["DeviceId"]
        } //Makes payload
        var alg = "EdDSA"; //Algorithm used for the Jwt
        const privateKey = await jose.importPKCS8(pkcs8, alg) //Turns key in pkcs8 format
        var rToken = await new jose.SignJWT(payload).setProtectedHeader({ alg }).sign(privateKey).then() //Creates Jwt token with EdDSA algorithm
        fs.writeFileSync("jwt.txt",rToken) //Stores the Jwt
        return rToken.toString()
    }
    else
    return token.toString()
}
function createToken(auth,encryptionKey)
{
    var tokenOld = fs.readFileSync("oldToken.txt").toString() //Stores latest token
    var tsOpen = fs.readFileSync("TimeStamp.txt").toString() //Stores timestamp when token made
    var ts = Number(tsOpen)
    var combine = encryptionKey + auth['DeviceId'] + auth['authSecret'] + auth['Version'] + ts //Recreates token
    var tokenNew = crypto.createHash('sha1').update(combine).digest('base64url') //New token made
    var newts = Date.now()
    var diff = newts - ts
    if (diff > 600000) //If the token is 30 min old, it will refresh
    {
        var newToken = encryptionKey + auth['DeviceId'] + auth['authSecret'] + auth['Version'] + newts
        var finalToken = crypto.createHash('sha1').update(newToken).digest('base64url')
        fs.writeFileSync('TimeStamp.txt',newts.toString())
        fs.writeFileSync('oldToken.txt',finalToken)
        return finalToken
    }
    if (tokenOld == tokenNew) //If the token is the same as the last one saved, it returns the last saved one
    {
        return tokenOld
    }
    else
    {
        var newToken = encryptionKey + auth['DeviceId'] + auth['authSecret'] + auth['Version'] + newts //Creates new token if version changed with new version and timestamp
        var finalToken = crypto.createHash('sha1').update(newToken).digest('base64url')
        fs.writeFileSync('TimeStamp.txt',newts.toString()) //Stores last timestamp the token was made
        fs.writeFileSync('oldToken.txt',finalToken) //Stores the token for new logins
        return finalToken
    }
}
function parseToken(auth,encryptionKey)
{
    var token = fs.readFileSync("oldToken.txt").toString()
    var tsOpen = fs.readFileSync("TimeStamp.txt").toString()
    var ts = Number(tsOpen)
    var combine = encryptionKey + auth['DeviceId'] + auth['authSecret'] + auth['Version'] + ts //Recreates token
    var tokenNew = crypto.createHash('sha1').update(combine).digest('base64url')
    var newts = Date.now()
    var diff = newts - ts
    if (diff > 600000) //Checks if token is expired; 10 minutes
    {
        return "Expired!"
    }
    if (token == tokenNew)
    {
        return "Authorizated!"
    }
    else
    {
        return "Wrong!"
    }
}
function jwtEnigma(auth,token)
{
    var payload = {
        "nbf": Math.round(Date.now() / 1000) - 100,
        "exp": Math.round(Date.now() / 1000) + 7200,
        "iat": Math.round(Date.now() / 1000),
        "sub": auth["Username"],
        "sid": token,
    } //Payload used for the JWT, this includes the temporary token and username
    var jwtKey = fs.readFileSync('jwtKey.txt').toString()
    var jwtE = jwt.sign(payload,jwtKey,{ algorithm: 'HS256' })
    return jwtE
}
async function onLogin(auth,refreshToken)
{
    if (refreshToken == '')   
    {
        var key = fs.readFileSync("key.txt").toString() //Key For Tokens
        var urlToken = createToken(auth,key) //Makes token with key
        let ParseToken = parseToken(auth,key) //Checks if token is right
        if (ParseToken == "Expired!") //Returns wrong if token is wrongly generated
        {
            return "Unauthorizated Token!"
        }
        if (ParseToken == "Wrong!")
        {
            return "Unauthorizated Token!"
        }
        else
        {
            var jwtToken = jwtEnigma(auth,urlToken) //Creates JWT if the token is right
        }
        var ts = Date.now()
        var Auth = {
            "DeviceId": auth["DeviceId"],
            "Version": auth["Version"],
            "Username": "enigma",
            "Token": urlToken.toString(),
            "JWT": jwtToken,
            "Timestamp": ts.toString(),
            "authSecret": "y0HizT08IAAA"
        } //Returns new auth for requests
        return Auth
    }
    else
    {
        var alg = "EdDSA" //Algorithm used for refreshToken
        var spki = fs.readFileSync("publicKey.pem").toString() //Gets publickey
        var publicKey = await jose.importSPKI(spki, alg) //Formats key in spki
        var verifyJwt = await jose.jwtVerify(refreshToken,publicKey) //Verifies jwt
        var countJwt = verifyJwt.toString().length //Gets length of Jwt
        var bufferJwt = Buffer.from(refreshToken) //Buffers jwt
        var slicePayload = bufferJwt.subarray(21, 255) //Gets payload of Jwt
        var decodedPayload = base64url.decode(slicePayload) //Base64url decodes payload
        if (countJwt > 10) //checks if Jwt was made correctly
        {
            var payloadBuffer = Buffer.from(decodedPayload) //Buffers payload
            var expirationSlice = payloadBuffer.subarray(98, 108).toString() //Gets expiration
            var newts = Math.round(Date.now() / 1000) //Gets timestamp right now
            if (parseInt(expirationSlice) > newts) //Checks if Jwt expired
            { //ALL SLICES ARE PAYLOAD SPECIFIC, SO YOU NEED TO CONFIGURE THIS
                var deviceId = payloadBuffer.subarray(133, 173).toString() //DeviceId
                var authSecret = payloadBuffer.subarray(38, 50).toString() //authSecret
                var version = "0.55" //Uses current version
                var username = payloadBuffer.subarray(8, 14) //Username
                var authToken = {
                    "DeviceId": deviceId,
                    "authSecret": authSecret,
                    "Version": version,
                    "Username": username
                }
                var urlToken = createToken(authToken,key) //Makes token
                let parsed = parseToken(authToken,key) //Parses token
                if (parsed == "Expired!") //Returns wrong if token is wrongly generated
                {
                    return "Unauthorizated Token!"
                }
                if (parsed == "Wrong!")
                {
                    return "Unauthorizated Token!"
                }
                else
                {
                    var jwtToken = jwtEnigma(auth,urlToken) //Creates JWT if the token is right
                }
                var ts = Date.now()
                var Auth = {
                    "DeviceId": deviceId,
                    "Version": version,
                    "Username": username,
                    "Token": urlToken.toString(),
                    "JWT": jwtToken,
                    "Timestamp": ts.toString(),
                    "authSecret": authSecret
                }
                return Auth
            }
            else
            {
                "Refresh Token Expired!"
            }
        }
        else
        {
            return "Refresh token wrong"
        }
    }
}
function getAuthTicket(auth)
{
    var key = fs.readFileSync("key.txt").toString() //Key for token verification
    var ticketKey = "67WrW8hzXatB9WsJYJnnezaPMbyGBGYE" //Key used for encrypting the ticket
    var saltKey = "h8TIiA65DCO4KUXDSXyFYfbDXvIk0joE" //Key used for the signature/salt hashed part
    var ts = Date.now().toString() //Gets timestamp for when the ticket was made
    var urlToken = auth['Token'].toString() //Makes token to string
    var hash = saltKey + urlToken + ts.toString() + auth["authSecret"] + auth["DeviceId"] //Creates hash for verification
    var saltHash = crypto.createHash('sha256').update(hash).digest('hex') //Hash made for signature
    var bufferPart1 = Buffer.alloc(auth["DeviceId"].length, auth["DeviceId"]) //Makes buffer for DeviceId
    var bufferPart2 = Buffer.alloc(urlToken.length, urlToken) //Makes buffer for token
    var bufferPart3 = Buffer.alloc(ts.length, ts.toString()) //Makes buffer for timestamp
    var bufferPart4 = Buffer.alloc(saltHash.length, saltHash) //Makes buffer for signature/salt hash
    var bufferList = [bufferPart1, bufferPart2, bufferPart3, bufferPart4] //Makes list of buffers
    var hexRequestTicket = Buffer.concat(bufferList) //Combines all buffers and converts it to a hex string (uppercase)
    const encryptTicket = encrypt(hexRequestTicket,ticketKey)
    var tokenState = parseToken(auth,key)
    if (tokenState == "Expired!")
    {
        return "Token Expired"
    }
    if (tokenState == "Wrong!")
    {
        return "Token Wrong"
    }
    else
    return encryptTicket.toString('hex').toUpperCase()
}
function parseTicket(ticketEncrypted,auth)
{
    var saltKey = "h8TIiA65DCO4KUXDSXyFYfbDXvIk0joE" //Key for signature
    var ticketKey = "67WrW8hzXatB9WsJYJnnezaPMbyGBGYE" //Key for ticket decryption
    var ticketBuffer = Buffer.from(ticketEncrypted, 'hex') //Buffers ticket to hex
    var ticket = decrypt(ticketBuffer,ticketKey) //Decrypts encrypted ticket
    var newts = Date.now() //Gets current timestamp
    var deviceIdTicket = ticket.slice(0, 40).toString() //DeviceId
    var tokenTicket = ticket.slice(40, 67).toString() //Token
    var timestampTicket = ticket.slice(67, 80).toString() //Timestamp
    var saltHash = ticket.slice(80).toString() //Signature
    var recreateHash = saltKey + tokenTicket + timestampTicket + auth["authSecret"] + deviceIdTicket //Recreates signature
    var saltHashR = crypto.createHash('sha256').update(recreateHash).digest('hex') //Hash recreated
    var difference = newts - timestampTicket //Checks time difference from now and when the ticket was made
    if (difference > 36000) //Checks if ticket expired
    {
        return "Ticket Wrong Or Expired!"
    }
    if (saltHash == saltHashR) //If the ticket is rightly made, it will return correct!
    {
        var Ticket = {
            "DeviceId": deviceIdTicket,
            "Token": tokenTicket,
            "Timestamp": timestampTicket,
            "Signature": saltHash
        }
        return Ticket
    }
    else
    {
        return "Ticket Wrong Or Expired!" //If the ticket is wrong, wrong key, it will return this
    }
}
function encrypt(chunk,key) {
	iv = crypto.randomBytes(16);
	cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
	result = Buffer.concat([iv, cipher.update(chunk), cipher.final()]);
	return result;
}
function decrypt(chunk,key) {
	iv = chunk.slice(0, 16);
	chunk = chunk.slice(16);
	decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
	result = Buffer.concat([decipher.update(chunk), decipher.final()]);
	return result;
}
module.exports = { createToken, parseToken, jwtEnigma, onLogin, getAuthTicket, parseTicket, encrypt, decrypt, refreshToken};
