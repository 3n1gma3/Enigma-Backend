var crypto = require('crypto')
var fs = require('fs')
var jwt = require('jsonwebtoken')
var base64url = require('base64-url')
const jose = require('jose')

async function refreshToken(auth)
{
    const pkcs8 = fs.readFileSync("privateKey.pem").toString()
    var token = fs.readFileSync("jwt.txt")
    var tokenPayload = token.subarray(37, 205).toString()
    let text = base64url.decode(tokenPayload).toString()
    var ts = Buffer.from(text)
    var tsSlice = ts.subarray(86, 96).toString()
    var newts = Math.round(Date.now() / 1000)
    if (parseInt(tsSlice) < newts)
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
            "iat": Math.round(Date.now() / 1000)
        }
        var alg = "EdDSA";
        const privateKey = await jose.importPKCS8(pkcs8, alg)
        var rToken = await new jose.SignJWT(payload).setProtectedHeader({ alg }).sign(privateKey).then()
        fs.writeFileSync("jwt.txt",rToken)
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
    if (diff > 600000)
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
function onLogin(auth)
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
function Request(auth)
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

    var saltKey = "h8TIiA65DCO4KUXDSXyFYfbDXvIk0joE"
    var ticketKey = "67WrW8hzXatB9WsJYJnnezaPMbyGBGYE"
    var ticketBuffer = Buffer.from(ticketEncrypted, 'hex')
    var ticket = decrypt(ticketBuffer,ticketKey)
    var newts = Date.now()
    var deviceIdTicket = ticket.slice(0, 40).toString()
    var tokenTicket = ticket.slice(40, 67).toString()
    var timestampTicket = ticket.slice(67, 80).toString()
    var saltHash = ticket.slice(80).toString()
    var recreateHash = saltKey + tokenTicket + timestampTicket + auth["authSecret"] + deviceIdTicket
    var saltHashR = crypto.createHash('sha256').update(recreateHash).digest('hex')
    var difference = newts - timestampTicket
    if (difference > 36000)
    {
        return "Ticket Wrong Or Expired!"
    }
    if (saltHash == saltHashR)
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
        return "Ticket Wrong Or Expired!"
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
module.exports = { createToken, parseToken, jwtEnigma, onLogin, Request, parseTicket, encrypt, decrypt, refreshToken};
