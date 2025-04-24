const crypto = require('crypto');

exports.signJWT = (payload, secret, expiresInSeconds) => {
    jwtHeader= {"alg":"HS256","typ":"JWT"}
    const base64Header = toBase64url(jwtHeader)
    const newPayload= payloadWExp(payload, expiresInSeconds)
    const base64Payload = toBase64url(newPayload)
    const signature = crypto.createHmac('sha256', secret).update(`${base64Header}.${base64Payload}`).digest('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    return `${base64Header}.${base64Payload}.${signature}`
}

exports.verifyJWT = (token, secret) => {
    const [header, payload, signature] = token.split('.')
    const calculatedSignature = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    if (calculatedSignature !== signature) {
        return null
    }
    const decodedPayload = Buffer.from(payload, 'base64').toString('utf-8')
    const parsedPayload = JSON.parse(decodedPayload)
    if (parsedPayload.exp && parsedPayload.exp < Math.floor(Date.now() / 1000)) {
        return null
    }
    return parsedPayload
}

const toBase64url = (obj) => {
    const json = typeof obj === 'string' ? obj : JSON.stringify(obj)
    return Buffer.from(json).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

const payloadWExp = (payload, expiresInSeconds) => {
    const exp = Math.floor(Date.now() / 1000) + expiresInSeconds
    return { ...payload, exp }
}

