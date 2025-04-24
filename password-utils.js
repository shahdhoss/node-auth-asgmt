const crypto = require('crypto');

exports.hashPassword = (password) => {
    const salt = crypto.randomBytes(16).toString('hex')
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex')
    return `${salt}:${hash}`
}

exports.verifyPassword = (password, hashedPassword) => {
    const [salt, hash] = hashedPassword.split(':')
    const hashVerify = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex')
    return hash === hashVerify
}