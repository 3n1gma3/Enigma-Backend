# Enigma-Backend
Test for my backend, isn't hosted, works on files.

Example for the auth:
{
    "DeviceId": '78cda3f0cf08fbae94dd431bf9413f22ec179a0c',
    "Version": '0.55',
    "Username": 'enigma',
    "authSecret": 'y0HizT08IAAA'
}
DeviceId is a 20 byte hash/uuid, version is the version of your game, username is the users name and the authSecret is the userId encoded in msgpack b64, but you can change this to anything you like.

```
var auth = {
    "DeviceId": '78cda3f0cf08fbae94dd431bf9413f22ec179a0c',
    "Version": '0.55',
    "Username": 'enigma',
    "authSecret": 'y0HizT08IAAA'
}
var login = onLogin(auth) //Result = Jwt, Token and Timestamp
```
```
var refreshToken = refreshToken(auth) //Result = Jwt useable for 200 days (Uses ecdsa keys in PEM format)
```
```
var getTicket = Request(login) //Result = Encrypted hex cipher
```
```
let parsed = parseTicket(getTicket,login) //Result = contents of ticket (used for validating requests)
```
